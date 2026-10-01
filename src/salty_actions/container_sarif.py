"""Prepare native Scout results for GitHub's Code Scanning location limits."""
from __future__ import annotations

from copy import deepcopy

from .container_findings import obj, rows


def code_scanning_report(payload: dict) -> dict:
    """Keep every finding and its primary location; retain raw evidence separately.

    GitHub annotates only the primary location. Scout can enumerate every file
    belonging to a package, which can exceed ingestion limits even for one CVE.
    """
    report = deepcopy(payload)
    for run in rows(report.get("runs"), "SARIF runs"):
        for result in rows(obj(run, "SARIF run").get("results"), "SARIF results"):
            result = obj(result, "SARIF result")
            if "locations" in result:
                result["locations"] = rows(result["locations"], "SARIF locations")[:1]
            if "relatedLocations" in result:
                result["relatedLocations"] = rows(result["relatedLocations"], "SARIF related locations")[:999]
    return report
