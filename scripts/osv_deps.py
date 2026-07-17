#!/usr/bin/env python3
"""Parse dependency manifests under a target dir and query OSV.dev for known vulns.

Supports package.json (npm) and requirements.txt (PyPI). Emits JSON:
{"findings": [{"package","version","ecosystem","id","summary","severity","manifest"}]}
Emits a coverage-honest status (success/partial/failed/unsupported/not_applicable) with declared/collected/queried/skipped counts, parse errors, unsupported manifests, and skipped specs so the pipeline degrades cleanly.
"""
import json
import os
import re
import sys
import urllib.request

OSV_API = "https://api.osv.dev/v1/query"


def _query_osv(name, version, ecosystem):
    if os.environ.get("VIBESCAN_OFFLINE"):
        raise RuntimeError("offline")
    body = json.dumps(
        {"version": version, "package": {"name": name, "ecosystem": ecosystem}}
    ).encode()
    req = urllib.request.Request(OSV_API, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=8) as resp:
        return json.loads(resp.read())


def _osv_severity(vuln):
    # Prefer CVSS-derived database_specific severity if present, else map by keywords.
    sev = (vuln.get("database_specific", {}) or {}).get("severity", "")
    if isinstance(sev, str) and sev:
        s = sev.lower()
        if "critical" in s:
            return "critical"
        if "high" in s:
            return "high"
        if "moderate" in s or "medium" in s:
            return "medium"
        if "low" in s:
            return "low"
    return "high"  # a matched, known vuln with no rating is treated as high by default


EXACT_NPM = re.compile(r"^v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")


def _collect_npm(path):
    deps, skipped, ok = {}, [], True
    try:
        with open(path) as f:
            data = json.load(f)
    except Exception:
        return deps, skipped, False   # recognized manifest, but unparseable
    for key in ("dependencies", "devDependencies"):
        for name, spec in (data.get(key) or {}).items():
            spec_s = str(spec).strip()
            # Only a complete exact semver is assessable. Ranges (^1.2, ~1.2, >=1.2),
            # wildcards (1.2.x), compound (1.2.3 || 4.0.0), hyphen ranges, tags (latest),
            # and URLs/workspaces are skipped rather than mis-resolved to one version.
            if EXACT_NPM.fullmatch(spec_s):
                deps[name] = spec_s.lstrip("v")
            else:
                skipped.append({"package": name, "specification": spec_s})
    return deps, skipped, ok


def _collect_pypi(path):
    deps, skipped, ok = {}, [], True
    try:
        with open(path) as f:
            for line in f:
                line = line.split("#")[0].strip()
                if not line or line.startswith("-"):
                    continue
                m = re.match(r"^([A-Za-z0-9_.\-]+)\s*==\s*(\d[\w.\-]*)$", line)
                if m:
                    deps[m.group(1)] = m.group(2)
                    continue
                m2 = re.match(r"^([A-Za-z0-9_.\-]+)\s*(.+)$", line)
                if m2:
                    skipped.append({"package": m2.group(1), "specification": m2.group(2).strip()})
    except Exception:
        return deps, skipped, False
    return deps, skipped, ok


def main():
    target = sys.argv[1]
    findings = []
    manifests = collected = queried = errors = 0
    unsupported_files = []
    skipped_specs = []
    parse_errors = []
    UNSUPPORTED = {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
                   "poetry.lock", "Pipfile.lock", "uv.lock", "go.mod", "go.sum", "Cargo.lock",
                   "Gemfile.lock", "composer.lock", "packages.lock.json",
                   # ecosystem manifests we detect but don't assess yet — surfaced as
                   # unsupported so a Maven/Gradle/etc. project can't read as "0 findings / clean"
                   "pom.xml", "build.gradle", "build.gradle.kts", "Cargo.toml",
                   "composer.json", "Gemfile", "Pipfile"}
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in ("node_modules", ".git", ".vibescan")]
        for fn in files:
            full = os.path.join(root, fn)
            rel = os.path.relpath(full, target)
            if fn == "package.json":
                pkgs, sk, ok, eco = (*_collect_npm(full), "npm")
            elif fn in ("requirements.txt", "requirements.in"):
                pkgs, sk, ok, eco = (*_collect_pypi(full), "PyPI")
            else:
                if fn in UNSUPPORTED:
                    unsupported_files.append(rel)
                continue
            manifests += 1
            if not ok:
                parse_errors.append(rel)
                continue
            for s in sk:
                s["manifest"] = rel
                skipped_specs.append(s)
            for name, version in pkgs.items():
                collected += 1
                try:
                    res = _query_osv(name, version, eco)
                    queried += 1
                except Exception:
                    errors += 1
                    continue
                for vuln in res.get("vulns", []) or []:
                    findings.append(
                        {
                            "package": name,
                            "version": version,
                            "ecosystem": eco,
                            "id": vuln.get("id", ""),
                            "summary": (vuln.get("summary") or vuln.get("details", ""))[:200],
                            "severity": _osv_severity(vuln),
                            "manifest": rel,
                        }
                    )
    # Coverage-honest status. The key distinction is "no dependencies exist" vs
    # "dependencies exist but VibeScan could not assess them":
    #   failed   = supported packages existed but every query errored (API unreachable)
    #   partial  = some queries errored, some specs skipped, or some manifest unparseable
    #   unsupported = recognized manifests declared deps but none were parseable, only
    #                 unparseable lockfiles were present, or a manifest failed to parse
    #   not_applicable = no recognized manifests, or manifests declaring zero deps
    declared = collected + len(skipped_specs)
    if parse_errors and collected:
        status = "partial"
    elif parse_errors:
        status = "unsupported"
    elif collected and queried == 0:
        status = "failed"
    elif collected and (errors or skipped_specs or unsupported_files):
        status = "partial"
    elif collected:
        status = "success"
    elif declared > 0:
        status = "unsupported"
    elif unsupported_files:
        status = "unsupported"
    else:
        status = "not_applicable"
    print(json.dumps({
        "status": status,
        "manifestsFound": manifests,
        "packagesDeclared": declared,
        "packagesCollected": collected,
        "packagesQueried": queried,
        "packagesSkipped": len(skipped_specs),
        "queryErrors": errors,
        "unsupportedManifests": len(unsupported_files),
        "unsupportedManifestFiles": unsupported_files,
        "manifestParseErrors": parse_errors,
        "skippedSpecifications": skipped_specs[:50],
        "skippedSpecificationsTruncated": len(skipped_specs) > 50,
        "findings": findings,
    }))


if __name__ == "__main__":
    main()
