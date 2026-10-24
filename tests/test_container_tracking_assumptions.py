from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from salty_actions.container_findings import (
    APPLICATION_DISTRO,
    finding,
    package_purl,
)
from salty_actions.container_tracking import evolve, read_state, state_comment

from .test_container_security import scout_findings, scout_report
from .test_container_tracking import package_inventory


def observation(
    platform="linux/amd64", *, source="scout", kev=False, version="3.14.7-r1"
):
    item = scout_findings(scout_report())[0]
    return {
        **item,
        "source": source,
        "kev": kev,
        "version": version,
        "name": "base",
        "platform": platform,
    }


def finding_group(*observations):
    first = {
        key: value
        for key, value in observations[0].items()
        if key not in {"name", "platform"}
    }
    return {
        **first,
        "kev": any(row["kev"] for row in observations),
        "observations": list(observations),
        "images": sorted({f"example/image:{row['platform']}" for row in observations}),
        "run_url": "",
    }


def assessment(coverage):
    return {
        "targets": [
            {
                "name": "base",
                "platform": platform,
                "scanners": scanners,
                "inventory": package_inventory(),
            }
            for platform, scanners in coverage.items()
        ],
        "run_id": "100",
        "at": "",
    }


COMPLETE = {"trivy": "complete", "scout": "complete", "kev": "complete"}


class TrackingIdentityTests(unittest.TestCase):
    def test_scoped_and_encoded_package_identities_round_trip(self):
        for package_type, namespace, package in (
            ("npm", "@babel", "core"),
            ("generic", "vendor%name/path", "a?b#c%@d"),
        ):
            with self.subTest(package_type=package_type, package=package):
                item = finding(
                    "CVE-2026-12345",
                    package_purl(package_type, namespace, package),
                    "1.0.0",
                    "HIGH",
                    APPLICATION_DISTRO,
                    "scout",
                )
                row = {**item, "name": "base", "platform": "linux/amd64"}
                state = evolve(None, finding_group(row), None, complete=False)
                self.assertEqual(read_state(state_comment(state)), state)
                self.assertEqual(item["namespace"], namespace)
                self.assertEqual(item["package"], package)


class PartialAssessmentTests(unittest.TestCase):
    def initial(self, *rows):
        group = finding_group(*rows)
        coverage = {row["platform"]: dict(COMPLETE) for row in rows}
        return evolve(None, group, assessment(coverage), complete=True)

    def test_missing_target_retains_last_known_observation_and_images(self):
        previous = self.initial(observation(), observation("linux/arm64"))
        original = copy.deepcopy(previous)
        group = finding_group(observation())
        current = assessment({"linux/amd64": dict(COMPLETE)})

        state = evolve(previous, group, current, complete=False)

        self.assertEqual(previous, original)
        rows = state["group"]["observations"]
        self.assertEqual(
            [row["platform"] for row in rows], ["linux/amd64", "linux/arm64"]
        )
        self.assertNotIn("evidence_status", rows[0])
        self.assertEqual(rows[1]["evidence_status"], "last known")
        self.assertEqual(state["group"]["images"], previous["group"]["images"])
        self.assertEqual(state["status"], "incomplete")
        self.assertIsNone(state["pending"])
        self.assertEqual(read_state(state_comment(state)), state)

    def test_missing_scanner_metadata_conservatively_retains_evidence(self):
        previous = self.initial(observation(), observation("linux/arm64"))
        current = assessment({"linux/amd64": dict(COMPLETE), "linux/arm64": {}})
        del current["targets"][1]["scanners"]

        state = evolve(previous, finding_group(observation()), current, complete=False)

        historical = [
            row for row in state["group"]["observations"] if "evidence_status" in row
        ]
        self.assertEqual([row["platform"] for row in historical], ["linux/arm64"])

    def test_failed_scout_retains_its_evidence_while_trivy_refreshes(self):
        previous = self.initial(observation(), observation(source="trivy"))
        current = assessment({"linux/amd64": {**COMPLETE, "scout": "error"}})
        fresh = observation(source="trivy", version="3.14.8-r0")

        state = evolve(previous, finding_group(fresh), current, complete=False)

        rows = {row["source"]: row for row in state["group"]["observations"]}
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows["scout"]["evidence_status"], "last known")
        self.assertEqual(rows["scout"]["version"], "3.14.7-r1")
        self.assertEqual(rows["trivy"]["version"], "3.14.8-r0")
        self.assertNotIn("evidence_status", rows["trivy"])

    def test_kev_and_ordinary_scout_have_independent_coverage(self):
        previous = self.initial(observation(), observation(kev=True))
        for failed, fresh_kev in (("kev", False), ("scout", True)):
            with self.subTest(failed=failed):
                current = assessment({"linux/amd64": {**COMPLETE, failed: "error"}})
                group = finding_group(observation(kev=fresh_kev))

                state = evolve(previous, group, current, complete=False)

                rows = {row["kev"]: row for row in state["group"]["observations"]}
                self.assertEqual(len(rows), 2)
                self.assertNotIn("evidence_status", rows[fresh_kev])
                self.assertEqual(rows[not fresh_kev]["evidence_status"], "last known")
                self.assertTrue(state["group"]["kev"])

    def test_complete_negative_supersedes_a_scope_despite_other_errors(self):
        previous = self.initial(observation(), observation("linux/arm64"))
        current = assessment(
            {
                "linux/amd64": dict(COMPLETE),
                "linux/arm64": {**COMPLETE, "trivy": "error"},
            }
        )
        group = finding_group(observation("linux/arm64"))

        state = evolve(previous, group, current, complete=False)

        self.assertEqual(state["group"]["observations"], group["observations"])
        self.assertEqual(state["group"]["images"], group["images"])

    def test_no_positive_group_retains_only_unavailable_scopes(self):
        previous = self.initial(observation(), observation("linux/arm64"))
        current = assessment(
            {
                "linux/amd64": dict(COMPLETE),
                "linux/arm64": {**COMPLETE, "scout": "error"},
            }
        )

        state = evolve(previous, None, current, complete=False)

        rows = state["group"]["observations"]
        self.assertEqual([row["platform"] for row in rows], ["linux/arm64"])
        self.assertEqual(rows[0]["evidence_status"], "last known")
        self.assertEqual(state["affected"], previous["affected"])
        self.assertEqual(state["group"]["key"], previous["group"]["key"])

    def test_repeated_partial_assessment_deduplicates_without_metadata_churn(self):
        previous = self.initial(observation(), observation("linux/arm64"))
        group = finding_group(observation())
        current = assessment({"linux/amd64": dict(COMPLETE)})
        first = evolve(previous, group, current, complete=False)

        second = evolve(first, group, current, complete=False)

        self.assertEqual(second, first)
        self.assertEqual(len(second["group"]["observations"]), 2)

    def test_complete_refresh_replaces_historical_observations(self):
        previous = self.initial(observation(), observation("linux/arm64"))
        partial = evolve(
            previous,
            finding_group(observation()),
            assessment({"linux/amd64": dict(COMPLETE)}),
            complete=False,
        )
        group = finding_group(
            observation(), observation("linux/arm64", version="3.14.8-r0")
        )

        state = evolve(
            partial,
            group,
            assessment({"linux/amd64": dict(COMPLETE), "linux/arm64": dict(COMPLETE)}),
            complete=True,
        )

        self.assertEqual(state["group"]["observations"], group["observations"])
        self.assertFalse(
            any("evidence_status" in row for row in state["group"]["observations"])
        )
        self.assertEqual(state["status"], "detected")


class TrackingSizeTests(unittest.TestCase):
    def state_with_url(self, repetitions):
        row = observation()
        row["url"] = "https://example.test/" + "--" * repetitions
        return evolve(None, finding_group(row), None, complete=False)

    def test_escaped_state_under_the_limit_round_trips(self):
        state = self.state_with_url(1500)

        serialized = state_comment(state)

        self.assertLessEqual(
            len(serialized.split(":", 1)[1].removesuffix(" -->")), 40000
        )
        self.assertEqual(read_state(serialized), state)

    def test_escaping_cannot_exceed_the_reader_limit(self):
        state = self.state_with_url(2000)
        self.assertLess(
            len(json.dumps(state, sort_keys=True, separators=(",", ":"))), 40000
        )

        with self.assertRaisesRegex(ValueError, "exceeds supported size"):
            state_comment(state)
