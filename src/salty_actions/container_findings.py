"""Normalize documented Trivy JSON and Scout SARIF reports."""
from __future__ import annotations

import hashlib
import json
import re
from urllib.parse import parse_qs, unquote, urlsplit


def text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 4096 or any(
        ord(character) < 32 for character in value
    ):
        raise ValueError(f"{field} must be a nonempty single-line string")
    return value


def obj(value: object, field: str) -> dict:
    if not isinstance(value, dict):
        raise ValueError(f"{field} must be an object")
    return value


def rows(value: object, field: str) -> list:
    if not isinstance(value, list):
        raise ValueError(f"{field} must be an array")
    return value


def distro_name(family: str, version: str) -> str:
    # Alpine patch releases share one package repository branch.
    if family == "alpine":
        match = re.fullmatch(r"(\d+\.\d+)(?:\.\d+)?", version)
        if not match:
            raise ValueError("invalid Alpine release in scanner report")
        version = match[1]
    return f"{family}/{version}"


def package_identity(purl: object) -> tuple[str, str, str, dict]:
    purl = text(purl, "package PURL")
    if not purl.startswith("pkg:"):
        raise ValueError("package identity must be a PURL")
    path, _, query = purl[4:].partition("?")
    path = path.split("#", 1)[0].rsplit("@", 1)[0]
    parts = path.split("/")
    if len(parts) < 2:
        raise ValueError("package PURL has no type/name")
    return (text(parts[0], "package type"), unquote("/".join(parts[1:-1])),
            text(unquote(parts[-1]), "package name"), parse_qs(query))


def finding(identifier: object, purl: object, version: object, severity: object,
            distro: str, source: str, *, url: object = "", fix: object = "",
            kev: bool = False) -> dict:
    package_type, namespace, package, _ = package_identity(purl)
    identifier = text(identifier, "vulnerability identifier")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:+-]*", identifier):
        raise ValueError("invalid vulnerability identifier")
    severity = text(severity, "severity").upper()
    if severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN", "INFO", "NEGLIGIBLE"}:
        raise ValueError("unsupported vulnerability severity")
    if url and (not isinstance(url, str) or not url.startswith("https://")):
        raise ValueError("advisory URL must use HTTPS")
    if url:
        text(url, "advisory URL")
    if fix:
        text(fix, "advertised fix")
    identity = [identifier, package_type, namespace, package, distro]
    key = hashlib.sha256(json.dumps(identity, separators=(",", ":")).encode()).hexdigest()
    return {"key": key, "id": identifier, "package_type": package_type,
            "namespace": namespace, "package": package, "distro": distro,
            "version": text(version, "installed version"), "severity": severity,
            "source": source, "url": url, "fix": fix or "", "kev": kev}


def trivy_findings(payload: object) -> list[dict]:
    report = obj(payload, "Trivy report")
    if report.get("SchemaVersion") != 2:
        raise ValueError("unsupported Trivy report schema")
    metadata = obj(report.get("Metadata"), "Trivy metadata")
    os_data = obj(metadata.get("OS"), "Trivy operating system")
    distro = distro_name(text(os_data.get("Family"), "OS family"),
                         text(os_data.get("Name"), "OS release"))
    results = rows(report.get("Results", []), "Trivy results")
    findings = []
    for result in results:
        result = obj(result, "Trivy result")
        for vulnerability in rows(result.get("Vulnerabilities") or [], "Trivy vulnerabilities"):
            vulnerability = obj(vulnerability, "Trivy vulnerability")
            identity = obj(vulnerability.get("PkgIdentifier"), "Trivy package identifier")
            item = finding(vulnerability.get("VulnerabilityID"), identity.get("PURL"),
                           vulnerability.get("InstalledVersion"), vulnerability.get("Severity"),
                           distro, "trivy", url=vulnerability.get("PrimaryURL", ""),
                           fix=vulnerability.get("FixedVersion", ""))
            if item["severity"] in {"CRITICAL", "HIGH"}:
                findings.append(item)
    return findings


def scout_findings(payload: object, *, kev: bool = False) -> list[dict]:
    report = obj(payload, "Scout report")
    if report.get("version") != "2.1.0":
        raise ValueError("unsupported Scout SARIF report schema")
    findings = []
    runs = rows(report.get("runs"), "Scout runs")
    if len(runs) != 1:
        raise ValueError("Scout report must contain one scan run")
    run = obj(runs[0], "Scout run")
    driver = obj(obj(run.get("tool"), "Scout tool").get("driver"), "Scout driver")
    if driver.get("name") != "docker scout":
        raise ValueError("SARIF report is not from Docker Scout")
    rules = [obj(rule, "Scout rule") for rule in rows(driver.get("rules"), "Scout rules")]
    results = rows(run.get("results"), "Scout results")
    used = set()
    for result in results:
        result = obj(result, "Scout result")
        rule_id = text(result.get("ruleId"), "Scout rule ID")
        index = result.get("ruleIndex")
        if index is not None:
            if type(index) is not int or not 0 <= index < len(rules) or rules[index].get("id") != rule_id:
                raise ValueError("Scout result has an invalid rule index")
            matched = [rules[index]]
        else:
            matched = [rule for rule in rules if rule.get("id") == rule_id]
        if not matched:
            raise ValueError("Scout result references an unknown rule")
        for rule in matched:
            properties = obj(rule.get("properties"), "Scout rule properties")
            purls = rows(properties.get("purls"), "Scout package PURLs")
            if not purls:
                raise ValueError("Scout finding has no package identity")
            severity = properties.get("cvssV3_severity", "UNKNOWN")
            rank = {"UNKNOWN": 0, "UNSPECIFIED": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
            v4 = properties.get("cvssV4_severity", "UNKNOWN")
            if rank.get(v4, 0) > rank.get(severity, 0):
                severity = v4
            if severity == "UNSPECIFIED":
                severity = "UNKNOWN"
            for purl in purls:
                purl = text(purl, "Scout package PURL")
                if (rule_id, purl) in used:
                    continue
                used.add((rule_id, purl))
                _, _, _, qualifiers = package_identity(purl)
                version_path = purl.split("?", 1)[0].split("#", 1)[0]
                if "@" not in version_path:
                    raise ValueError("Scout PURL has no installed package version")
                version = unquote(version_path.rsplit("@", 1)[1])
                distro = qualifiers.get("distro", [""])[0]
                if distro:
                    os_name, separator, os_version = distro.rpartition("-")
                else:
                    os_name = qualifiers.get("os_name", [""])[0]
                    os_version = qualifiers.get("os_version", [""])[0]
                    separator = bool(os_name and os_version)
                if not separator:
                    # Scout advisory links also carry structured OS parameters.
                    query = parse_qs(urlsplit(rule.get("helpUri", "")).query)
                    os_name, os_version = query.get("osn", [""])[0], query.get("osv", [""])[0]
                if not os_name or not os_version:
                    raise ValueError("Scout finding has no distro identity")
                fix = properties.get("fixed_version", "")
                if fix == "not fixed":
                    fix = ""
                item = finding(rule_id, purl, version, severity, distro_name(os_name, os_version),
                               "scout", url=rule.get("helpUri", ""), fix=fix, kev=kev)
                if kev or item["severity"] in {"CRITICAL", "HIGH"}:
                    findings.append(item)
    return findings
