"""Emit a bounded, location-safe SARIF view of VibeScan's normalized findings.

The JSON report remains authoritative. This file is an untrusted scan artifact,
not an upload or an acceptance verdict.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import PurePosixPath
import re
from pathlib import Path
from urllib.parse import quote


SCHEMA_URI = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
SCANNERS = {"gitleaks", "opengrep", "ai_patterns", "osv", "dast", "review"}
CATEGORIES = {"secret_exposure", "injection", "auth_issue", "dependency_risk",
              "ai_specific", "config_issue", "data_exposure", "insecure_pattern"}
LEVELS = {"critical": "error", "high": "error", "medium": "warning",
          "low": "note", "info": "note"}


def _known(value, allowed, fallback):
    return value if isinstance(value, str) and value in allowed else fallback


def _safe_label(value):
    if not isinstance(value, str):
        return "unknown"
    if value in {"verified", "hash-mismatch", "pinned-but-missing", "present-unpinned",
                 "absent", "substituted-unpinned", "invalid-pinned-commit",
                 "commit-mismatch", "working-tree-unverifiable", "working-tree-modified",
                 "origin-mismatch", "content-verified-origin-unknown", "mirror-absent",
                 "unpinned", "unknown"}:
        return value
    if re.fullmatch(r"[0-9a-fA-F]{12,40}", value):
        return "digest-" + hashlib.sha256(("vibescan-label-v1\0" + value).encode("utf-8")).hexdigest()[:16]
    if re.fullmatch(r"v?[0-9]{1,4}(?:\.[0-9]{1,4}){1,3}(?:[-+][0-9A-Za-z.-]{1,16})?", value):
        return value
    return "unknown"


def _safe_path(value):
    """Keep only repository-relative file paths; never serialize host paths/URLs."""
    if not isinstance(value, str) or not value or any(ord(c) < 32 for c in value):
        return None
    path = value.replace("\\", "/")
    if path.startswith("/") or path.startswith("//") or re.match(r"^[A-Za-z]:", path):
        return None
    if "://" in path or any(part in ("", ".", "..") for part in path.split("/")):
        return None
    normalized = PurePosixPath(path).as_posix()
    return quote(normalized, safe="/-._~") if normalized == path else None


def _fingerprint(value, rule_id):
    if isinstance(value, str) and re.fullmatch(r"[0-9a-fA-F]{16,64}", value):
        return value.lower()
    return hashlib.sha256((rule_id + ":" + str(value)).encode("utf-8")).hexdigest()[:16]


def _rule_suffix(value, category):
    # Rule IDs can be supplied by the scanned repository's configuration. Keep
    # stable rule identity without copying potentially credential-shaped text.
    if value:
        return "rule-" + hashlib.sha256(("vibescan-rule-v1\0" + str(value)).encode("utf-8")).hexdigest()[:16]
    return category


def serialize(findings, summary, version):
    """Return SARIF 2.1.0 using controlled labels, never raw evidence excerpts."""
    rules = {}
    results = []
    for finding in findings:
        scanner = _known(finding.get("scanner"), SCANNERS, "other")
        category = _known(finding.get("category"), CATEGORIES, "insecure_pattern")
        rule_id = f"vibescan/{scanner}/{_rule_suffix(finding.get('ruleId'), category)}"
        rules.setdefault(rule_id, {"id": rule_id,
                                   "shortDescription": {"text": f"{category.replace('_', ' ')} ({scanner})"},
                                   "properties": {"tags": [scanner, category]}})
        severity = _known(finding.get("severity"), set(LEVELS), "medium")
        result = {"ruleId": rule_id, "level": LEVELS[severity],
                  "message": {"text": f"VibeScan {category.replace('_', ' ')} finding from {scanner}; inspect the redacted JSON report."},
                  "partialFingerprints": {"vibescan/v1": _fingerprint(finding.get("fingerprint"), rule_id)},
                  "properties": {"severity": severity,
                                 "confidence": _known(finding.get("confidence"), {"high", "medium", "low"}, "unknown")}}
        path = _safe_path(finding.get("filePath"))
        if path:
            physical = {"artifactLocation": {"uri": path, "uriBaseId": "%SRCROOT%"}}
            line = finding.get("lineStart")
            end = finding.get("lineEnd")
            if type(line) is int and line > 0:
                region = {"startLine": line}
                if type(end) is int and end >= line:
                    region["endLine"] = end
                physical["region"] = region
            result["locations"] = [{"physicalLocation": physical}]
        results.append(result)

    status = _known(summary.get("scanStatus"), {"complete", "partial", "failed"}, "failed")
    allowed_engines = SCANNERS - {"other"}
    coverage = {"scanStatus": status,
                "enginesRan": sorted(set(x for x in summary.get("enginesRan", []) if x in allowed_engines)),
                "degradedScanners": sorted(set(x for x in summary.get("degradedScanners", []) if x in allowed_engines))}
    toolchain = summary.get("toolchain")
    if isinstance(toolchain, dict):
        coverage["toolchainLockfile"] = _known(toolchain.get("lockfile"), {"present", "absent", "malformed"}, "unknown")
        coverage["toolchainVerifyMode"] = _known(toolchain.get("verifyMode"), {"strict", "permissive"}, "unknown")
        engines = toolchain.get("engines") if isinstance(toolchain.get("engines"), dict) else {}
        coverage["toolchainEngines"] = {
            name: {"pinned": _safe_label(record.get("pinned")),
                   "status": _safe_label(record.get("status"))}
            for name, record in engines.items()
            if name in SCANNERS and isinstance(record, dict)
        }
        sast = toolchain.get("sast") if isinstance(toolchain.get("sast"), dict) else {}
        coverage["toolchainSast"] = {"selectedEngine": _known(sast.get("selectedEngine"),
                                                                {"opengrep", "semgrep"}, "unknown"),
                                     "status": _safe_label(sast.get("status")),
                                     "pinned": _safe_label(sast.get("pinned"))}
        rule_metadata = toolchain.get("rules") if isinstance(toolchain.get("rules"), dict) else {}
        coverage["toolchainRules"] = {"pinnedCommit": _safe_label(rule_metadata.get("pinnedCommit")),
                                      "actualCommit": _safe_label(rule_metadata.get("actualCommit")),
                                      "status": _safe_label(rule_metadata.get("status"))}
    driver = {"name": "VibeScan", "version": str(version),
              "informationUri": "https://github.com/shobhitbhatnagar/vibescan",
              "rules": [rules[k] for k in sorted(rules)]}
    return {"$schema": SCHEMA_URI, "version": "2.1.0",
            "runs": [{"tool": {"driver": driver}, "results": results,
                      "properties": coverage}]}


def write(path, findings, summary, version):
    output = Path(path)
    document = serialize(findings, summary, version)
    temporary = output.with_name(output.name + ".tmp")
    temporary.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, output)
