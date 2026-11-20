"""Automatic resolution of application (language package) findings."""

from __future__ import annotations

import copy
import json
import sys
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from salty_actions.container_findings import finding, trivy_findings
from salty_actions.container_issues import (
    BOT,
    issue_marker,
    managed_body,
    plan_issues,
)
from salty_actions.container_packages import application_fixed, digest, inventory
from salty_actions.container_report import validate_inventory
from salty_actions.container_tracking import (
    application_remediation,
    evolve,
    read_state,
    state_comment,
)

from .test_container_security import REPOSITORY, FakeIssueClient, scan_report
from .test_container_tracking import AppliedIssues, apply, apply_images

CVE = "CVE-2026-111943"
FIX = "1.26.10, 1.27.3"
BINARY = "app/autoscan/autoscan"
COMPLETE = {"trivy": "complete", "scout": "complete", "kev": "complete"}


def go_package(name, version):
    return {
        "ID": f"{name}@{version}",
        "Name": name,
        "Identifier": {
            "PURL": f"pkg:golang/{name}@{version}",
            "UID": "fac97335882c9ae4",
        },
        "Version": version,
        "Relationship": "direct",
        "Layer": {"Digest": "sha256:" + "4" * 64, "DiffID": "sha256:" + "f" * 64},
        "AnalyzedBy": "gobinary",
    }


def go_payload(version="v1.27.2", *, vulnerable=True, stdlib=True, fix=FIX):
    """A Trivy report shaped like a published Autoscan image scan."""
    packages = [
        {
            **go_package("github.com/saltydk/autoscan", "v1.4.7"),
            "Relationship": "root",
            "DependsOn": ["github.com/alecthomas/kong@v1.17.0"],
        },
        go_package("github.com/alecthomas/kong", "v1.17.0"),
    ]
    if stdlib:
        packages.append(go_package("stdlib", version))
    application = {
        "Target": BINARY,
        "Class": "lang-pkgs",
        "Type": "gobinary",
        "Packages": packages,
    }
    if vulnerable:
        application["Vulnerabilities"] = [
            {
                "VulnerabilityID": CVE,
                "PkgID": f"stdlib@{version}",
                "PkgName": "stdlib",
                "PkgIdentifier": {"PURL": f"pkg:golang/stdlib@{version}"},
                "InstalledVersion": version,
                "FixedVersion": fix,
                "Status": "fixed",
                "Severity": "HIGH",
                "PrimaryURL": f"https://avd.aquasec.com/nvd/{CVE.lower()}",
            }
        ]
    return {
        "SchemaVersion": 2,
        "ArtifactType": "container_image",
        "Metadata": {"OS": {"Family": "alpine", "Name": "3.24.4"}},
        "Results": [
            {
                "Target": "image.tar (alpine 3.24.4)",
                "Class": "os-pkgs",
                "Type": "alpine",
                "Packages": [
                    {
                        "ID": "musl@1.2.6-r3",
                        "Name": "musl",
                        "Version": "1.2.6-r3",
                        "SrcName": "musl",
                        "SrcVersion": "1.2.6-r3",
                    }
                ],
            },
            application,
        ],
    }


def go_report(run="100", *, hours_ago=18, payload=None, name="base", **options):
    payload = payload or go_payload(**options)
    report = scan_report(clean=True)
    report["target"]["name"] = name
    report.update(
        schema=2,
        run_id=run,
        scanned_at=(datetime.now(UTC) - timedelta(hours=hours_ago)).isoformat(),
        findings=trivy_findings(payload, all_severities=True),
        inventory=inventory(payload),
        provenance={"trivy_version": "v0.74.0"},
        availability={
            "status": "unsupported",
            "errors": [],
            "fixes": {},
            "remediated": [],
        },
    )
    return report


def rehash(report):
    data = report["inventory"]
    data["sha256"] = digest({k: v for k, v in data.items() if k != "sha256"})
    return report


class GoVersionTests(unittest.TestCase):
    def assertFixed(self, version, *advisories, fixed=True):
        self.assertIs(
            application_fixed("golang", version, list(advisories)),
            fixed,
            (version, advisories),
        )

    def test_version_on_a_listed_line_must_reach_that_fix(self):
        self.assertFixed("v1.27.3", FIX)
        self.assertFixed("1.27.3", FIX)
        self.assertFixed("v1.27.10", FIX)
        self.assertFixed("v1.26.10", FIX)
        self.assertFixed("v1.27.2", FIX, fixed=False)
        self.assertFixed("1.26.9", FIX, fixed=False)
        self.assertFixed("v1.27.0", FIX, fixed=False)

    def test_newer_line_than_every_fix_is_fixed_and_older_lines_are_not(self):
        self.assertFixed("v1.28.0", FIX)
        self.assertFixed("v2.0.0", FIX)
        self.assertFixed("v1.25.99", FIX, fixed=False)
        self.assertFixed("v0.30.0", FIX, fixed=False)
        # A line between the listed lines has no listed fix.
        self.assertFixed("1.26.20", "1.25.9, 1.27.4", fixed=False)

    def test_scanner_lists_combine_with_the_highest_fix_per_line(self):
        self.assertFixed("1.26.11", "1.26.11, 1.27.4", "1.27.4")
        self.assertFixed("1.27.3", "1.26.11, 1.27.4", "1.27.4", fixed=False)
        self.assertFixed("1.27.3", "1.27.3", "1.27.4", fixed=False)
        self.assertFixed("1.27.4", "1.27.3", "v1.27.4")
        self.assertFixed("1.28.0", "1.27.4", "1.28.1", fixed=False)

    def test_release_without_patch_is_its_first_patch(self):
        self.assertFixed("1.27", "1.27.0")
        self.assertFixed("v1.21", "1.21.1", fixed=False)
        self.assertFixed("1.21.1", "1.21")

    def test_module_versions_with_a_leading_v(self):
        self.assertFixed("v0.17.0", "v0.17.0")
        self.assertFixed("v0.38.0", "0.36.0")
        self.assertFixed("v0.16.9", "0.17.0", fixed=False)

    def test_unparsable_versions_or_fixes_give_no_proof(self):
        for version in (
            "v1.28.0-rc.1",
            "1.28rc1",
            "go1.27.3",
            "devel",
            "",
            "1.27.3+incompatible",
            "v0.0.0-20261001000000-abcdefabcdef",
            "01.27.3",
            "1.027.3",
            "1.27.x",
            " 1.27.3",
            "1",
            "1.27.3.1",
        ):
            self.assertFixed(version, FIX, fixed=False)
        for advisory in ("", "1.27.3,", ">=1.27.3", "1.27.3 1.28.0", "1.28.0-rc.2"):
            self.assertFixed("1.28.5", advisory, fixed=False)
        self.assertFixed("1.28.5", FIX, "", fixed=False)
        self.assertFixed("1.28.5", fixed=False)

    def test_other_ecosystems_get_no_version_proof(self):
        for package_type in ("npm", "pypi", "cargo", "maven", "apk", "gem"):
            self.assertFalse(application_fixed(package_type, "2.0.0", ["1.0.0"]))


class ApplicationInventoryTests(unittest.TestCase):
    def test_real_shaped_trivy_payload_records_every_language_result(self):
        payload = go_payload("v1.27.3", vulnerable=False)
        payload["Results"].append(
            {
                "Target": "usr/local/bin/helper",
                "Class": "lang-pkgs",
                "Type": "gobinary",
                "Packages": [
                    {**go_package("helper", ""), "Relationship": "root"},
                    go_package("stdlib", "v1.27.4"),
                ],
            }
        )
        payload["Results"].append({"Target": "secrets", "Class": "secret"})
        data = inventory(payload)
        self.assertEqual(data["status"], "complete")
        self.assertEqual([p["name"] for p in data["packages"]], ["musl"])
        self.assertEqual(
            data["applications"],
            {
                "status": "complete",
                "results": [
                    {
                        "type": "gobinary",
                        "target": BINARY,
                        "packages": [
                            {
                                "name": "github.com/alecthomas/kong",
                                "version": "v1.17.0",
                            },
                            {
                                "name": "github.com/saltydk/autoscan",
                                "version": "v1.4.7",
                            },
                            {"name": "stdlib", "version": "v1.27.3"},
                        ],
                    },
                    {
                        "type": "gobinary",
                        "target": "usr/local/bin/helper",
                        "packages": [
                            {"name": "helper", "version": ""},
                            {"name": "stdlib", "version": "v1.27.4"},
                        ],
                    },
                ],
            },
        )
        self.assertEqual(
            data["sha256"], digest({k: v for k, v in data.items() if k != "sha256"})
        )
        self.assertEqual(validate_inventory(data), data)

    def test_the_real_autoscan_sample_records_stdlib(self):
        sample = (
            Path(__file__).parent
            / "fixtures/container-security/trivy-v0.74.0-gobinary.json"
        )
        data = inventory(json.loads(sample.read_text()))
        (result,) = data["applications"]["results"]
        self.assertEqual(data["applications"]["status"], "complete")
        self.assertEqual((result["type"], result["target"]), ("gobinary", BINARY))
        self.assertEqual(len(result["packages"]), 26)
        self.assertIn({"name": "stdlib", "version": "v1.27.3"}, result["packages"])

    def test_unlisted_or_malformed_language_results_are_unknown(self):
        for change in (
            lambda r: r.pop("Packages"),
            lambda r: r.update(Packages=None),
            lambda r: r.update(Type=""),
            lambda r: r["Packages"].append({"Name": "", "Version": "v1.0.0"}),
            lambda r: r["Packages"].append({"Name": "x", "Version": "bad\nline"}),
            lambda r: r["Packages"].append("stdlib"),
        ):
            payload = go_payload(vulnerable=False)
            change(payload["Results"][1])
            data = inventory(payload)
            self.assertEqual(data["applications"]["status"], "unknown")
            # OS evidence is independent of the language inventory.
            self.assertEqual(data["status"], "complete")

    def test_osless_images_keep_their_language_inventory(self):
        payload = go_payload("v1.27.3", vulnerable=False)
        del payload["Metadata"]["OS"]
        payload["Results"].pop(0)
        data = validate_inventory(inventory(payload))
        self.assertEqual(data["status"], "unsupported")
        self.assertEqual(data["applications"]["status"], "complete")

    def test_reports_without_a_language_inventory_still_validate(self):
        data = inventory(go_payload())
        del data["applications"]
        data["sha256"] = digest({k: v for k, v in data.items() if k != "sha256"})
        self.assertNotIn("applications", validate_inventory(data))
        self.assertEqual(
            validate_inventory({"status": "unsupported"}), {"status": "unsupported"}
        )

    def test_hash_covers_the_language_inventory(self):
        for status in ("complete", "unsupported"):
            payload = go_payload()
            if status == "unsupported":
                del payload["Metadata"]["OS"]
            data = inventory(payload)
            data["applications"]["results"][0]["packages"][-1]["version"] = "v1.27.9"
            with self.assertRaisesRegex(ValueError, "inventory hash"):
                validate_inventory(data)
        data = inventory(go_payload())
        data["applications"]["results"][0]["packages"][0]["extra"] = "x"
        with self.assertRaisesRegex(ValueError, "application package fields"):
            validate_inventory(data)
        data = inventory(go_payload())
        data["applications"]["status"] = "partial"
        with self.assertRaisesRegex(ValueError, "application inventory"):
            validate_inventory(data)


class ApplicationLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.client = AppliedIssues()
        apply(self.client, go_report())

    def state(self):
        return read_state(self.client.issues[0]["body"])

    def test_fixed_toolchain_is_pending_then_resolved_after_six_hours(self):
        self.assertEqual(self.state()["status"], "detected")
        self.assertEqual(
            self.state()["affected"][0]["packages"],
            [{"name": "stdlib", "version": "v1.27.2"}],
        )
        self.assertEqual(
            self.state()["affected"][0]["sources"],
            [{"type": "gobinary", "target": BINARY}],
        )
        self.assertIn("(application)", self.client.issues[0]["title"])
        fixed = {"version": "v1.27.3", "vulnerable": False}
        apply(self.client, go_report("101", hours_ago=12, **fixed))
        self.assertEqual(self.state()["status"], "pending")
        (proof,) = self.state()["verification"]
        self.assertEqual(proof["reason"], "fixed application version installed")
        self.assertEqual(proof["packages"], [{"name": "stdlib", "version": "v1.27.3"}])
        self.assertEqual(self.client.issues[0]["state"], "open")
        apply(self.client, go_report("102", hours_ago=7, **fixed))
        self.assertEqual(self.state()["status"], "pending")
        apply(self.client, go_report("103", hours_ago=5, **fixed))
        self.assertEqual(self.client.issues[0]["state"], "closed")
        self.assertTrue((issue_marker(self.client.issues[0]) or {})["resolved"])
        body = self.client.issues[0]["body"]
        self.assertIn("fixed application version installed", body)
        self.assertIn("Package `stdlib=v1.27.3`", body)

    def test_newer_release_line_resolves(self):
        for run, hours in (("101", 12), ("102", 5)):
            apply(
                self.client,
                go_report(run, hours_ago=hours, version="v1.28.0", vulnerable=False),
            )
        self.assertEqual(self.state()["status"], "resolved")

    def test_removal_is_proven_when_the_same_binary_no_longer_lists_it(self):
        for run, hours in (("101", 12), ("102", 5)):
            apply(
                self.client,
                go_report(run, hours_ago=hours, stdlib=False, vulnerable=False),
            )
        self.assertEqual(self.client.issues[0]["state"], "closed")
        (proof,) = self.state()["verification"]
        self.assertEqual(proof["reason"], "application package removed")
        self.assertNotIn("packages", proof)

    def test_no_removal_proof_when_the_binary_path_disappeared(self):
        payload = go_payload(stdlib=False, vulnerable=False)
        payload["Results"][1]["Target"] = "usr/local/bin/autoscan"
        self.assertStaysInReview(go_report("101", hours_ago=12, payload=payload))

    def test_no_removal_proof_when_trivy_stops_listing_the_binary(self):
        payload = go_payload(vulnerable=False)
        payload["Results"].pop(1)
        self.assertStaysInReview(go_report("101", hours_ago=12, payload=payload))

    def test_no_removal_proof_when_the_result_type_changed(self):
        payload = go_payload(stdlib=False, vulnerable=False)
        payload["Results"][1]["Type"] = "gomod"
        self.assertStaysInReview(go_report("101", hours_ago=12, payload=payload))

    def assertStaysInReview(self, *reports):
        for report in reports:
            apply(self.client, report)
            self.assertEqual(self.state()["status"], "review")
            self.assertIsNone(self.state()["pending"])
            self.assertNotIn("verification", self.state())
        self.assertEqual(self.client.issues[0]["state"], "open")

    def test_missing_language_inventory_cannot_prove_a_fix(self):
        reports = []
        for run, hours in (("101", 12), ("102", 5)):
            report = go_report(
                run, hours_ago=hours, version="v1.27.3", vulnerable=False
            )
            del report["inventory"]["applications"]
            reports.append(rehash(report))
        self.assertStaysInReview(*reports)

    def test_incomplete_language_inventory_cannot_prove_a_fix_or_removal(self):
        reports = []
        for run, hours, stdlib in (("101", 12, True), ("102", 5, False)):
            payload = go_payload("v1.27.3", vulnerable=False, stdlib=stdlib)
            payload["Results"].append(
                {"Target": "usr/bin/other", "Class": "lang-pkgs", "Type": "gobinary"}
            )
            reports.append(go_report(run, hours_ago=hours, payload=payload))
        self.assertStaysInReview(*reports)

    def test_unfixed_or_older_line_version_stays_open(self):
        self.assertStaysInReview(
            go_report("101", hours_ago=12, vulnerable=False),
            go_report("102", hours_ago=5, version="v1.26.9", vulnerable=False),
            go_report("103", hours_ago=4, version="v1.25.30", vulnerable=False),
        )

    def test_unparsable_version_stays_open(self):
        self.assertStaysInReview(
            *(
                go_report(run, hours_ago=hours, version=version, vulnerable=False)
                for run, hours, version in (
                    ("101", 12, "v1.28.0-rc.1"),
                    ("102", 5, "devel"),
                )
            )
        )

    def test_one_remaining_vulnerable_binary_blocks_resolution(self):
        payload = go_payload("v1.27.3", vulnerable=False)
        payload["Results"].append(
            {
                **payload["Results"][1],
                "Target": "usr/bin/old",
                "Packages": [go_package("stdlib", "v1.27.2")],
            }
        )
        self.assertStaysInReview(go_report("101", hours_ago=12, payload=payload))

    def test_same_name_in_another_ecosystem_is_not_guessed(self):
        payload = go_payload(stdlib=False, vulnerable=False)
        payload["Results"].append(
            {
                "Target": "app/package-lock.json",
                "Class": "lang-pkgs",
                "Type": "npm",
                "Packages": [{"Name": "stdlib", "Version": "9.9.9"}],
            }
        )
        self.assertStaysInReview(go_report("101", hours_ago=12, payload=payload))

    def test_manual_reopening_does_not_reuse_old_resolution(self):
        fixed = {"version": "v1.27.3", "vulnerable": False}
        for run, hours in (("101", 12), ("102", 5)):
            apply(self.client, go_report(run, hours_ago=hours, **fixed))
        self.assertEqual(self.client.issues[0]["state"], "closed")
        self.client.issues[0]["state"] = "open"
        apply(self.client, go_report("103", hours_ago=1, **fixed))
        self.assertEqual(self.client.issues[0]["state"], "open")
        self.assertEqual(self.state()["status"], "review")


class ApplicationPartialImageSetTests(unittest.TestCase):
    def setUp(self):
        self.client = AppliedIssues()
        apply_images(self.client, go_report(name="latest", hours_ago=20))
        apply_images(self.client, go_report("101", name="nonroot", hours_ago=19))

    def state(self):
        return read_state(self.client.issues[0]["body"])

    def fixed(self, name, run, hours):
        return go_report(
            run, name=name, hours_ago=hours, version="v1.27.3", vulnerable=False
        )

    def test_only_an_assessment_of_every_tracked_image_can_close(self):
        self.assertEqual(len(self.client.issues), 1)
        for run, hours in (("102", 16), ("103", 8)):
            apply_images(self.client, self.fixed("latest", run, hours))
            self.assertEqual(self.state()["status"], "detected")
            self.assertIsNone(self.state()["pending"])
        self.assertEqual(self.client.issues[0]["state"], "open")
        apply_images(
            self.client, *(self.fixed(n, "104", 7) for n in ("latest", "nonroot"))
        )
        self.assertEqual(self.state()["status"], "pending")
        apply_images(self.client, self.fixed("latest", "105", 2))
        self.assertEqual(self.state()["status"], "pending")
        apply_images(
            self.client, *(self.fixed(n, "106", 1) for n in ("latest", "nonroot"))
        )
        self.assertEqual(self.client.issues[0]["state"], "closed")
        self.assertEqual(
            {row["name"] for row in self.state()["verification"]},
            {"latest", "nonroot"},
        )


def tracked(body):
    state = read_state(body)
    if state is None:
        raise AssertionError("expected persisted tracking state")
    return state


def legacy_state(at):
    """Tracking state written before application proof, shaped like Autoscan #28."""
    item = finding(
        CVE,
        "pkg:golang/stdlib@v1.27.2",
        "v1.27.2",
        "HIGH",
        "debian/13.7",
        "trivy",
        url=f"https://avd.aquasec.com/nvd/{CVE.lower()}",
        fix=FIX,
    )
    observations = [
        {**item, "name": "latest-nonroot", "platform": platform}
        for platform in ("linux/amd64", "linux/arm/v7", "linux/arm64")
    ]
    return {
        "schema": 1,
        "group": {
            **item,
            "observations": observations,
            "images": ["saltydk/autoscan@sha256:" + "1" * 64],
        },
        "affected": [
            {"name": name, "platform": platform, "packages": []}
            for name in ("latest-nonroot", "master-nonroot")
            for platform in ("linux/amd64", "linux/arm/v7", "linux/arm64")
        ],
        "scope": [],
        "status": "review",
        "pending": None,
        "history": [{"at": at, "run_id": "40086429924", "status": "review"}],
        "evidence": {"at": at, "run_id": "40086429924"},
    }


def published_assessment(run, hours_ago, versions):
    targets = []
    for (name, platform), version in sorted(versions.items()):
        data = inventory(go_payload(version, vulnerable=False))
        targets.append(
            {
                "name": name,
                "platform": platform,
                "image": f"saltydk/autoscan@sha256:{digest([name, platform])}",
                "image_id": "sha256:" + digest([name, platform, "id"]),
                "inventory": validate_inventory(data),
                "availability": {"status": "unsupported"},
                "provenance": {"trivy_version": "v0.74.0"},
                "scanners": dict(COMPLETE),
            }
        )
    return {
        "targets": targets,
        "run_id": run,
        "at": (datetime.now(UTC) - timedelta(hours=hours_ago)).isoformat(),
    }


class LegacyApplicationStateTests(unittest.TestCase):
    """Issues written by the old tracker have no affected application packages."""

    def setUp(self):
        state = legacy_state("2026-10-24T10:38:50.388793+00:00")
        group = state["group"]
        body = managed_body(
            "published-images", group, tracking=state, repository=REPOSITORY
        )
        body = "Human note.\n" + body
        self.assertEqual(read_state(body), state)
        self.issue = {
            "number": 28,
            "state": "open",
            "user": {"login": BOT},
            "title": f"{CVE}: stdlib (debian/13.7)",
            "body": body,
        }
        self.versions = {
            (name, platform): version
            for name, version in (
                ("latest", "v1.27.3"),
                ("latest-nonroot", "v1.27.3"),
                ("master", "v1.27.4"),
                ("master-nonroot", "v1.27.4"),
            )
            for platform in ("linux/amd64", "linux/arm/v7", "linux/arm64")
        }

    def plan(self, assessment):
        client = FakeIssueClient([self.issue])
        return plan_issues(
            "published-images",
            {},
            [self.issue],
            complete=True,
            client=client,
            assessment=assessment,
        )

    def test_old_state_derives_its_package_and_resolves_after_confirmation(self):
        (action,) = self.plan(published_assessment("44683470043", 12, self.versions))
        self.assertEqual((action["operation"], action["number"]), ("update", 28))
        state = tracked(action["payload"]["body"])
        self.assertEqual(state["status"], "pending")
        self.assertEqual(
            {(row["name"], row["reason"]) for row in state["verification"]},
            {
                ("latest-nonroot", "fixed application version installed"),
                ("master-nonroot", "fixed application version installed"),
            },
        )
        self.assertEqual(len(state["verification"]), 6)
        self.assertTrue(action["payload"]["body"].startswith("Human note.\n"))
        self.issue = {**self.issue, **action["payload"]}
        (action,) = self.plan(published_assessment("44700000000", 5, self.versions))
        self.assertEqual(action["operation"], "close")
        self.assertTrue(
            (issue_marker({**self.issue, **action["payload"]}) or {})["resolved"]
        )

    def test_old_state_stays_open_while_a_tracked_image_is_unfixed(self):
        self.versions["master-nonroot", "linux/arm64"] = "v1.27.2"
        # The state is unchanged: still in review, with no pending confirmation.
        self.assertEqual(
            self.plan(published_assessment("44683470043", 12, self.versions)), []
        )

    def test_old_state_stays_open_without_every_tracked_image(self):
        del self.versions["master-nonroot", "linux/arm64"]
        self.assertEqual(
            self.plan(published_assessment("44683470043", 12, self.versions)), []
        )


class ApplicationProofTests(unittest.TestCase):
    def setUp(self):
        self.state = legacy_state(datetime.now(UTC).isoformat())
        self.group = self.state["group"]
        self.affected = self.state["affected"][0]
        self.target = published_assessment(
            "1", 1, {("latest-nonroot", "linux/amd64"): "v1.27.3"}
        )["targets"][0]

    def proof(self, group=None, target=None):
        return application_remediation(
            group or self.group, self.affected, target or self.target
        )

    def test_scanner_coverage_must_be_complete_on_the_target(self):
        self.assertIsNotNone(self.proof())
        for scanner in COMPLETE:
            target = copy.deepcopy(self.target)
            target["scanners"][scanner] = "error"
            self.assertIsNone(self.proof(target=target))
        target = copy.deepcopy(self.target)
        del target["scanners"]["kev"]
        self.assertIsNone(self.proof(target=target))

    def test_missing_or_empty_fix_advice_gives_no_proof(self):
        for fix in ("", "unknown"):
            group = copy.deepcopy(self.group)
            group["observations"][1]["fix"] = fix
            self.assertIsNone(self.proof(group))

    def test_detected_version_that_advice_calls_fixed_is_inconsistent(self):
        group = copy.deepcopy(self.group)
        group["observations"][0]["version"] = "v1.27.3"
        self.assertIsNone(self.proof(group))
        group["observations"][0]["version"] = "devel"
        self.assertIsNone(self.proof(group))

    def test_legacy_state_without_recorded_results_has_no_removal_proof(self):
        target = published_assessment(
            "1", 1, {("latest-nonroot", "linux/amd64"): "v1.27.3"}
        )["targets"][0]
        stdlib_free = validate_inventory(
            inventory(go_payload(stdlib=False, vulnerable=False))
        )
        target["inventory"] = stdlib_free
        self.assertNotIn("sources", self.affected)
        self.assertIsNone(self.proof(target=target))
        recorded = {
            **self.affected,
            "sources": [{"type": "gobinary", "target": BINARY}],
        }
        proof = application_remediation(self.group, recorded, target)
        if proof is None:
            self.fail("expected removal proof for a still analysed binary")
        self.assertEqual(proof["reason"], "application package removed")
        recorded["sources"].append({"type": "gobinary", "target": "usr/bin/gone"})
        self.assertIsNone(application_remediation(self.group, recorded, target))

    def test_recorded_sources_are_validated(self):
        state = copy.deepcopy(self.state)
        self.assertEqual(read_state(state_comment(state)), state)
        state["affected"][0]["sources"] = [{"type": "gobinary", "target": BINARY}]
        self.assertEqual(read_state(state_comment(state)), state)
        for sources in (
            {"type": "gobinary"},
            [{"type": "gobinary"}],
            [{"type": "gobinary", "target": 1}],
            [{"type": "gobinary", "target": BINARY, "extra": ""}],
        ):
            broken = copy.deepcopy(state)
            broken["affected"][0]["sources"] = sources
            with self.assertRaisesRegex(ValueError, "package baseline"):
                read_state(state_comment(broken))

    def test_unsupported_ecosystems_get_no_proof(self):
        group = copy.deepcopy(self.group)
        group["package_type"] = "npm"
        self.assertIsNone(self.proof(group))

    def test_module_paths_match_case_insensitively(self):
        group = copy.deepcopy(self.group)
        group.update(
            namespace="github.com/Alecthomas", package="kong", version="v1.16.0"
        )
        group["fix"] = "1.17.0"
        for row in group["observations"]:
            row.update(version="v1.16.0", fix="1.17.0")
        proof = self.proof(group)
        self.assertEqual(
            proof["packages"],
            [{"name": "github.com/alecthomas/kong", "version": "v1.17.0"}],
        )

    def test_stored_application_evidence_is_validated(self):
        state = evolve(
            self.state, None, published_assessment("2", 1, {}), complete=True
        )
        state["verification"] = [
            {**self.proof(), "inventory_sha256": "x", "image": "i"}
        ]
        self.assertEqual(read_state(state_comment(state)), state)
        for change in (
            {"reason": "vendor fixed version installed"},
            {"reason": "fixed application version installed", "packages": []},
            {"reason": "application package removed"},
        ):
            broken = copy.deepcopy(state)
            broken["verification"][0].update(change)
            with self.assertRaisesRegex(ValueError, "remediation evidence"):
                read_state(state_comment(broken))
        os_state = copy.deepcopy(state)
        os_state["group"] = {
            **os_state["group"],
            **finding(
                CVE, "pkg:apk/alpine/go", "1.27.2-r0", "HIGH", "alpine/3.24", "trivy"
            ),
        }
        for row in os_state["group"]["observations"]:
            row.update(
                finding(
                    CVE,
                    "pkg:apk/alpine/go",
                    "1.27.2-r0",
                    "HIGH",
                    "alpine/3.24",
                    "trivy",
                )
            )
        with self.assertRaisesRegex(ValueError, "remediation evidence"):
            read_state(state_comment(os_state))


if __name__ == "__main__":
    unittest.main()
