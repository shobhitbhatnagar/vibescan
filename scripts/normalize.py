#!/usr/bin/env python3
"""Merge raw engine outputs into VibeScan's unified finding schema + a markdown report.

Usage: normalize.py <target-dir> <raw-dir> <degraded-csv>
Writes <target-dir>/.vibescan/findings.json and report.md.
"""
import hashlib
import json
import os
import re
import sys

SEV_WEIGHT = {"critical": 40, "high": 20, "medium": 8, "low": 3, "info": 0}
SEV_ORDER = ["critical", "high", "medium", "low", "info"]
SARIF_SEV = {"error": "high", "warning": "medium", "note": "low", "none": "info"}
SECRET_RE = re.compile(r"(AKIA[0-9A-Z]{8,}|[A-Za-z0-9_\-]{32,}|-----BEGIN [A-Z ]+PRIVATE KEY-----)")

# Gitleaks rule IDs that are entropy/pattern-based and prone to false positives.
# A match from one of these is real signal but low-confidence — worth verifying,
# not worth screaming "critical". Named-provider rules (aws, stripe, github, etc.)
# stay critical because they match a specific, unambiguous credential shape.
LOW_CONF_SECRET_RE = re.compile(r"generic|entropy|high-?entropy|api-?key$", re.I)

# Path segments where secrets/patterns are usually fixtures, not production risk.
TEST_PATH_RE = re.compile(
    r"(^|/)(tests?|__tests__|__mocks__|specs?|fixtures?|mocks?|examples?|samples?|"
    r"e2e|testdata|\.storybook|demo)(/|$)|\.(test|spec|stories|fixture)\.",
    re.I,
)


def is_test_path(p):
    return bool(TEST_PATH_RE.search(p or ""))


def downgrade(sev):
    return SEV_ORDER[min(SEV_ORDER.index(sev) + 1, len(SEV_ORDER) - 1)]


def fingerprint(*parts):
    return hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()[:16]


def norm(s):
    """Collapse whitespace/case so fingerprints track the code, not the line number."""
    return re.sub(r"\s+", " ", (s or "").strip().lower())[:200]


def redact(text):
    if not text:
        return ""
    return SECRET_RE.sub("[REDACTED]", text)[:2000]


def rel(target, path):
    try:
        return os.path.relpath(path, target)
    except Exception:
        return path


def load(raw, name, default):
    try:
        with open(os.path.join(raw, name)) as f:
            return json.load(f)
    except Exception:
        return default


def from_gitleaks(target, data):
    out = []
    for r in data or []:
        line = r.get("StartLine") or r.get("Line") or None
        f = rel(target, r.get("File", ""))
        rule_id = r.get("RuleID") or ""
        title = rule_id or r.get("Description") or "Hardcoded secret"
        low_conf = bool(LOW_CONF_SECRET_RE.search(rule_id)) or not rule_id
        raw_match = r.get("Match", "") or r.get("Secret", "")
        out.append(
            {
                "category": "secret_exposure",
                "severity": "medium" if low_conf else "critical",
                "confidence": "low" if low_conf else "high",
                "_verify": "entropy/generic match — verify this is a live secret, not a placeholder or fixture" if low_conf else None,
                "title": title.replace("-", " ").title(),
                "evidenceExcerpt": redact(raw_match),
                "filePath": f,
                "lineStart": line,
                "lineEnd": line,
                "remediationText": "Remove the secret from source, rotate it, and load it from an environment variable or a secrets manager.",
                "fingerprint": fingerprint("secret", f, title, norm(raw_match) or line),
                "scanner": "gitleaks",
            }
        )
    return out


def classify_sast(rule_id, message):
    # Category reflects the vulnerability TYPE, independent of which rule file or
    # engine found it. Strip the vibescan- prefix so rule naming doesn't skew this.
    rid = re.sub(r"^vibescan-(ai-)?", "", rule_id.lower())
    text = f"{rid} {message}".lower()
    if any(k in text for k in ("hallucinat", "nonexistent package", "insecure default")):
        return "ai_specific"
    if any(k in text for k in ("sqli", "sql inject", "cmdi", "command inject", "rce", "eval(", "arbitrary code", "deserial", "pickle", "ssti", "template inject")):
        return "injection"
    if any(k in text for k in ("xss", "innerhtml")):
        return "injection"
    if any(k in text for k in ("auth", "jwt", "session", "hardcoded password")):
        return "auth_issue"
    if any(k in text for k in ("cors", "tls", "ssl", "config", "insecure random")):
        return "config_issue"
    if any(k in text for k in ("data exposure", "leak", "stack trace")):
        return "data_exposure"
    return "insecure_pattern"


def from_sarif(target, data):
    out = []
    for run in (data or {}).get("runs", []) or []:
        driver = (run.get("tool", {}) or {}).get("driver", {}) or {}
        rule_meta = {r.get("id"): r for r in (driver.get("rules", []) or [])}
        for res in run.get("results", []) or []:
            rid = res.get("ruleId", "")
            msg = (res.get("message", {}) or {}).get("text", "")
            level = (res.get("level") or rule_meta.get(rid, {}).get("defaultConfiguration", {}).get("level") or "warning").lower()
            severity = SARIF_SEV.get(level, "medium")
            loc = (res.get("locations") or [{}])[0]
            phys = (loc.get("physicalLocation") or {})
            f = rel(target, ((phys.get("artifactLocation") or {}).get("uri") or ""))
            region = phys.get("region") or {}
            ls = region.get("startLine")
            le = region.get("endLine") or ls
            snippet = ((region.get("snippet") or {}).get("text") or "").strip()
            category = classify_sast(rid, msg)
            # scanner = which engine found it: our bundled rule packs vs generic opengrep.
            scanner = "ai_patterns" if "vibescan-" in rid else "opengrep"
            out.append(
                {
                    "category": category,
                    "severity": severity,
                    "title": (msg[:80] if msg else rid) or "Insecure pattern",
                    "evidenceExcerpt": redact(snippet or msg),
                    "filePath": f,
                    "lineStart": ls,
                    "lineEnd": le,
                    "remediationText": rule_meta.get(rid, {}).get("help", {}).get("text", "") or "Refactor to remove the unsafe construct; use parameterized/escaped APIs.",
                    "fingerprint": fingerprint(category, f, rid, norm(snippet) or ls),
                    "scanner": scanner,
                }
            )
    return out


def from_osv(target, data):
    out = []
    for v in (data or {}).get("findings", []) or []:
        title = f"{v['package']}@{v['version']} — {v.get('id','known vulnerability')}"
        out.append(
            {
                "category": "dependency_risk",
                "severity": v.get("severity", "high"),
                "title": title,
                "evidenceExcerpt": (v.get("summary") or "")[:2000],
                "filePath": v.get("manifest", ""),
                "lineStart": None,
                "lineEnd": None,
                "remediationText": f"Upgrade {v['package']} to a patched version. See https://osv.dev/vulnerability/{v.get('id','')}.",
                "fingerprint": fingerprint("dep", v["package"], v["version"], v.get("id", "")),
                "scanner": "osv",
            }
        )
    return out


def from_web(target, raw):
    """Passive DAST findings from web_scan.py (already in schema, scanner=dast)."""
    data = load(raw, "web.json", {"findings": []})
    out = []
    for w in (data or {}).get("findings", []) or []:
        w = dict(w)
        w.setdefault("scanner", "dast")
        w["fingerprint"] = w.get("fingerprint") or fingerprint(
            "dast", w.get("filePath", ""), w.get("title", ""))
        w["evidenceExcerpt"] = redact(w.get("evidenceExcerpt", ""))
        out.append(w)
    return out


def from_manual(target):
    """Fold in analyst/LLM-reviewed findings written to .vibescan/manual.json.

    These capture logic-level issues the engines can't pattern-match — broken access
    control / IDOR, tenant isolation, crypto misuse, auth flaws — so a real review
    ends up in the same report as the engine output, not just in chat.
    """
    path = os.path.join(target, ".vibescan", "manual.json")
    try:
        data = json.load(open(path))
    except Exception:
        return []
    out = []
    valid_cats = {"secret_exposure", "injection", "auth_issue", "dependency_risk",
                  "ai_specific", "config_issue", "data_exposure", "insecure_pattern"}
    for m in data.get("findings", []) or []:
        sev = str(m.get("severity", "medium")).lower()
        if sev not in SEV_WEIGHT:
            sev = "medium"
        cat = m.get("category", "insecure_pattern")
        if cat not in valid_cats:
            cat = "insecure_pattern"
        fp = m.get("fingerprint") or fingerprint(
            "manual", m.get("filePath", ""), m.get("title", ""), norm(m.get("evidenceExcerpt", ""))
        )
        out.append(
            {
                "category": cat,
                "severity": sev,
                "confidence": m.get("confidence", "high"),
                "title": m.get("title", "Manual review finding"),
                "evidenceExcerpt": redact(m.get("evidenceExcerpt", "")),
                "filePath": m.get("filePath", ""),
                "lineStart": m.get("lineStart"),
                "lineEnd": m.get("lineEnd") or m.get("lineStart"),
                "remediationText": m.get("remediationText", ""),
                "fingerprint": fp,
                "scanner": "review",
            }
        )
    return out


def risk_band(by_sev):
    """Headline band reflects the WORST severity actually present. 'critical' and 'high'
    require at least one such finding, so a large volume of medium/low findings can no longer
    saturate the additive score into a critical headline (the additive riskScore still
    captures volume for prioritization)."""
    if by_sev.get("critical", 0) > 0:
        return "critical"
    if by_sev.get("high", 0) > 0:
        return "high"
    if by_sev.get("medium", 0) > 0:
        return "medium"
    if by_sev.get("low", 0) > 0:
        return "low"
    return "clean"


def main():
    target, raw, degraded_csv = sys.argv[1], sys.argv[2], sys.argv[3]
    baseline_path = sys.argv[4] if len(sys.argv) > 4 else ""
    applicable_csv = sys.argv[5] if len(sys.argv) > 5 else ""
    degraded = [d for d in degraded_csv.split(",") if d]
    applicable = [a for a in applicable_csv.split(",") if a] or ["gitleaks", "opengrep", "osv"]
    ran = [e for e in applicable if e not in degraded]
    missing = [e for e in applicable if e in degraded]
    if not ran:
        scan_status = "failed"
    elif missing:
        scan_status = "partial"
    else:
        scan_status = "complete"

    osv_raw = load(raw, "osv.json", {"findings": []})
    web_raw = load(raw, "web.json", {})
    toolchain = load(raw, "toolchain.json", None)
    findings = []
    findings += from_gitleaks(target, load(raw, "gitleaks.json", []))
    findings += from_sarif(target, load(raw, "sast.sarif", {"runs": []}))
    findings += from_osv(target, osv_raw)
    findings += from_web(target, raw)
    findings += from_manual(target)

    # defensive: never let a bad severity crash scoring/sorting
    for f in findings:
        if f.get("severity") not in SEV_WEIGHT:
            f["severity"] = "medium"

    # confidence + path adjustments: fixtures/tests are rarely production risk,
    # and low-confidence secret matches shouldn't dominate the headline score.
    for f in findings:
        notes = []
        verify = f.pop("_verify", None)
        if verify:
            notes.append(verify)
        if is_test_path(f.get("filePath", "")):
            f["severity"] = downgrade(f["severity"])
            f["confidence"] = "low"
            notes.append("in test/fixture path — downweighted")
        if notes:
            f["notes"] = "; ".join(notes)

    # de-dupe by fingerprint
    seen, deduped = set(), []
    for f in findings:
        if f["fingerprint"] not in seen:
            seen.add(f["fingerprint"])
            deduped.append(f)
    findings = sorted(deduped, key=lambda x: SEV_ORDER.index(x["severity"]))

    by_sev = {s: 0 for s in SEV_ORDER}
    by_cat = {}
    for f in findings:
        by_sev[f["severity"]] += 1
        by_cat[f["category"]] = by_cat.get(f["category"], 0) + 1

    score = min(100, sum(SEV_WEIGHT[f["severity"]] for f in findings))

    # --- diff against a previous scan, if one was provided ------------------
    diff = None
    if baseline_path and os.path.exists(baseline_path):
        try:
            prev = json.load(open(baseline_path))
            prev_by_fp = {f["fingerprint"]: f for f in prev.get("findings", [])}
        except Exception:
            prev_by_fp = {}
        cur_fps = {f["fingerprint"] for f in findings}
        new_fps = []
        for f in findings:
            if f["fingerprint"] in prev_by_fp:
                f["status"] = "persisting"
            else:
                f["status"] = "new"
                new_fps.append(f["fingerprint"])
        fixed = [f for fp, f in prev_by_fp.items() if fp not in cur_fps]
        diff = {
            "comparedTo": baseline_path,
            "new": len(new_fps),
            "fixed": len(fixed),
            "persisting": len(findings) - len(new_fps),
            "fixedFindings": [
                {"title": f.get("title"), "filePath": f.get("filePath"),
                 "severity": f.get("severity"), "fingerprint": f.get("fingerprint")}
                for f in fixed
            ],
        }

    if findings:
        overall = risk_band(by_sev)
        risk_score = score
    elif scan_status == "complete":
        overall = "clean"
        risk_score = 0
    else:
        # engines that should have run didn't — a zero here would be a lie
        overall = "unknown"
        risk_score = None

    summary = {
        "scanStatus": scan_status,
        "overallRisk": overall,
        "riskScore": risk_score,
        "totalFindings": len(findings),
        "bySeverity": by_sev,
        "byCategory": by_cat,
        "enginesRan": ran,
        "degradedScanners": degraded,
    }
    if findings and scan_status != "complete":
        summary["riskScoreQualifier"] = "floor: incomplete coverage — real risk may be higher"

    cov_notes = []
    osv_status = osv_raw.get("status")
    perr = osv_raw.get("manifestParseErrors") or []
    if perr:
        cov_notes.append("Dependency manifest could not be parsed: " + ", ".join(perr) + ".")
    if osv_status == "unsupported":
        files = osv_raw.get("unsupportedManifestFiles") or []
        skipped = osv_raw.get("skippedSpecifications") or []
        if files:
            cov_notes.append("Dependency manifests were found but none are supported: "
                             + ", ".join(files) + ".")
        if skipped:
            shown = ", ".join(f"{s.get('package')} ({s.get('specification')})" for s in skipped[:6])
            more = "" if len(skipped) <= 6 else f", +{len(skipped) - 6} more"
            cov_notes.append("Dependencies were declared but their versions could not be resolved: "
                             + shown + more + ".")
        if not files and not skipped:
            cov_notes.append("Recognized dependency manifests could not be assessed.")
    elif osv_status == "partial":
        cov_notes.append(f"OSV coverage was incomplete: {osv_raw.get('packagesQueried', 0)} of "
                         f"{osv_raw.get('packagesDeclared', osv_raw.get('packagesCollected', 0))} "
                         "declared dependencies assessed.")
    elif osv_status == "failed":
        cov_notes.append("OSV could not query the dependency API; dependencies were not assessed.")
    if isinstance(web_raw, dict) and web_raw.get("status") == "failed":
        cov_notes.append("DAST could not reach the target; no web assessment was performed.")
    if cov_notes:
        summary["coverageNotes"] = cov_notes
    # per-engine notes (timeout vs unavailable vs error) written by the scanner
    try:
        eng_notes = json.loads(open(os.path.join(raw, "engine_notes.json")).read())
        if eng_notes:
            summary.setdefault("coverageNotes", []).extend(eng_notes)
    except Exception:
        pass
    if toolchain:
        summary["toolchain"] = toolchain

    if diff:
        summary["changesSinceLastScan"] = {k: diff[k] for k in ("new", "fixed", "persisting")}

    out_dir = os.path.join(target, ".vibescan")
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "findings.json"), "w") as f:
        json.dump({"summary": summary, "findings": findings}, f, indent=2)

    # markdown report
    lines = ["# VibeScan report", ""]
    if scan_status == "failed":
        lines.append(f"> ⛔ **Assessment incomplete — required engines did not complete "
                     f"({', '.join(missing)}). No conclusion about code safety can be made.**")
        lines.append("")
    elif scan_status == "partial":
        lines.append(f"> ⚠️ **Partial scan — {', '.join(missing)} did not complete. "
                     f"Findings below are a floor, not a complete result.**")
        lines.append("")
    score_str = f"{risk_score}/100" if risk_score is not None else "n/a (incomplete)"
    lines.append(f"**Overall risk:** {overall.upper()}  ·  **Score:** {score_str}  ·  **Findings:** {len(findings)}")
    status_line = f"**Scan status:** {scan_status}"
    if missing:
        status_line += f"  ·  **Incomplete:** {', '.join(missing)}"
    lines.append(status_line)
    counts = ", ".join(f"{by_sev[s]} {s}" for s in SEV_ORDER if by_sev[s])
    lines.append(f"**Breakdown:** {counts or 'none'}")
    for note in summary.get("coverageNotes", []):
        lines.append(f"**Coverage:** {note}")
    tc = summary.get("toolchain")
    if tc and tc.get("lockfile") == "present":
        parts = []
        g = (tc.get("engines") or {}).get("gitleaks", {})
        if g.get("pinned"):
            parts.append(f"gitleaks {g['pinned']} ({g.get('verification', '?')}/{g.get('status', '?')})")
        s = tc.get("sast") or {}
        if s.get("selectedEngine"):
            parts.append(f"SAST {s['selectedEngine']} ({s.get('verification', '?')}/{s.get('status', '?')})")
        rc = tc.get("rules") or {}
        if rc.get("pinnedCommit"):
            parts.append(f"rules pinned@{rc['pinnedCommit']} actual@{rc.get('actualCommit') or '?'} ({rc.get('status', '?')})")
        if parts:
            lines.append("**Toolchain:** " + "; ".join(parts))
    elif tc and tc.get("lockfile") in ("absent", "malformed"):
        lines.append(f"**Toolchain:** {tc['lockfile']} lockfile — engines unpinned this run")
    high_conf = [f for f in findings if f.get("confidence") != "low"]
    if findings and not high_conf:
        lines.append("")
        lines.append("> ⚠️ **Every finding is low-confidence** (entropy/generic matches or test-path hits). "
                     "The headline band is driven by items worth verifying, not confirmed issues — the true risk is likely lower.")
    elif findings and findings[0].get("confidence") == "low":
        lines.append("")
        lines.append("> ⚠️ The top-severity finding is low-confidence — verify it before trusting the headline band.")
    if diff:
        lines.append("")
        lines.append(f"**Changes since last scan:** 🆕 {diff['new']} new · ✅ {diff['fixed']} fixed · ➡️ {diff['persisting']} still open")
        if diff["fixedFindings"]:
            lines.append("")
            lines.append("_Fixed since last scan:_")
            for f in diff["fixedFindings"]:
                lines.append(f"- ~~[{f['severity'].upper()}] {f['title']} ({f['filePath']})~~")
    lines.append("")
    if not findings:
        if scan_status == "complete":
            lines.append("No findings. All applicable engines ran.")
        else:
            lines.append("No findings were produced, but the scan was incomplete — see the status above.")
    for i, f in enumerate(findings, 1):
        loc = f["filePath"] + (f":{f['lineStart']}" if f["lineStart"] else "")
        tag = " 🆕" if f.get("status") == "new" else ""
        conf = "  · ⚠️ verify" if f.get("confidence") == "low" else ""
        header = f"## {i}. [{f['severity'].upper()}] {f['title']}{tag}{conf}"
        lines.append(header)
        lines.append(f"- **Category:** {f['category']}  ·  **Scanner:** {f['scanner']}  ·  **Location:** `{loc}`")
        if f.get("evidenceExcerpt"):
            lines.append(f"- **Evidence:** `{f['evidenceExcerpt'][:160]}`")
        if f.get("notes"):
            lines.append(f"- **Note:** {f['notes']}")
        lines.append(f"- **Fix:** {f['remediationText']}")
        lines.append(f"- `fingerprint: {f['fingerprint']}`")
        lines.append("")
    with open(os.path.join(out_dir, "report.md"), "w") as f:
        f.write("\n".join(lines))

    print(f"normalized {len(findings)} finding(s), status {scan_status}, risk {overall} ({score_str})")


if __name__ == "__main__":
    main()
