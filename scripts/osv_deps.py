#!/usr/bin/env python3
"""Parse dependency manifests under a target dir and query OSV.dev for known vulns.

Supports package.json (npm) and requirements.txt (PyPI). Emits JSON:
{"findings": [{"package","version","ecosystem","id","summary","severity","manifest"}]}
Fails gracefully to an empty list on network errors so the pipeline degrades cleanly.
"""
import json
import os
import re
import sys
import urllib.request

OSV_API = "https://api.osv.dev/v1/query"


def _query_osv(name, version, ecosystem):
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


def _collect_npm(path):
    deps = {}
    try:
        with open(path) as f:
            data = json.load(f)
    except Exception:
        return deps
    for key in ("dependencies", "devDependencies"):
        for name, spec in (data.get(key) or {}).items():
            ver = re.sub(r"^[\^~>=<\s]+", "", str(spec)).split()[0] if spec else ""
            if ver and re.match(r"^\d", ver):
                deps[name] = ver
    return deps


def _collect_pypi(path):
    deps = {}
    try:
        with open(path) as f:
            for line in f:
                line = line.split("#")[0].strip()
                m = re.match(r"^([A-Za-z0-9_.\-]+)\s*==\s*([\w.\-]+)", line)
                if m:
                    deps[m.group(1)] = m.group(2)
    except Exception:
        pass
    return deps


def main():
    target = sys.argv[1]
    findings = []
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in ("node_modules", ".git", ".vibescan")]
        for fn in files:
            full = os.path.join(root, fn)
            rel = os.path.relpath(full, target)
            if fn == "package.json":
                pkgs, eco = _collect_npm(full), "npm"
            elif fn in ("requirements.txt", "requirements.in"):
                pkgs, eco = _collect_pypi(full), "PyPI"
            else:
                continue
            for name, version in pkgs.items():
                try:
                    res = _query_osv(name, version, eco)
                except Exception:
                    # network/offline: emit nothing rather than crashing the stage
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
    print(json.dumps({"findings": findings}))


if __name__ == "__main__":
    main()
