#!/usr/bin/env python3
"""Render a self-contained report.html from .vibescan/findings.json.

Instrument-panel aesthetic: near-black ground, monospace for machine data,
semantic-only signal color, verdict banner + engine scorecard + finding cards.
No external assets — the file opens and shares standalone.

Usage: render_html.py <target-dir>
"""
import html
import json
import os
import sys

BAND_COLOR = {
    "critical": "#f85149", "high": "#f0883e", "medium": "#d29922",
    "low": "#3fb950", "clean": "#3fb950", "unknown": "#8b949e",
}
SEV_COLOR = {
    "critical": "#f85149", "high": "#f0883e", "medium": "#d29922",
    "low": "#58a6ff", "info": "#8b949e",
}
SCANNER_LABEL = {
    "gitleaks": "Gitleaks", "opengrep": "Opengrep", "ai_patterns": "AI-pattern rules",
    "osv": "OSV.dev", "betterleaks": "Betterleaks", "review": "Manual review",
    "dast": "Web (DAST)",
}


def esc(x):
    return html.escape(str(x if x is not None else ""))


def card(f):
    sev = f.get("severity", "info")
    color = SEV_COLOR.get(sev, "#8b949e")
    loc = esc(f.get("filePath", ""))
    if f.get("lineStart"):
        loc += f":{f['lineStart']}"
    verify = ('<span class="chip verify">⚠ verify</span>'
              if f.get("confidence") == "low" else "")
    new = '<span class="chip new">NEW</span>' if f.get("status") == "new" else ""
    ev = esc(f.get("evidenceExcerpt", ""))[:200]
    note = f'<div class="note">{esc(f.get("notes"))}</div>' if f.get("notes") else ""
    ev_block = f'<pre class="evidence">{ev}</pre>' if ev else ""
    return f"""
    <article class="finding" style="--sev:{color}">
      <div class="finding-head">
        <span class="sev" style="background:{color}">{esc(sev.upper())}</span>
        <h3>{esc(f.get('title',''))}</h3>
        {new}{verify}
      </div>
      <div class="meta">
        <span>{esc(f.get('category',''))}</span>
        <span>{esc(SCANNER_LABEL.get(f.get('scanner',''), f.get('scanner','')))}</span>
        <span class="loc">{loc}</span>
      </div>
      {ev_block}
      {note}
      <div class="fix"><span>FIX</span>{esc(f.get('remediationText',''))}</div>
      <div class="fp">{esc(f.get('fingerprint',''))}</div>
    </article>"""


def main():
    target = sys.argv[1]
    data = json.load(open(os.path.join(target, ".vibescan", "findings.json")))
    s = data.get("summary", {})
    findings = data.get("findings", [])
    scan_status = s.get("scanStatus", "complete")
    band = s.get("overallRisk", "clean")
    score = s.get("riskScore", 0)
    by_sev = s.get("bySeverity", {})
    degraded = s.get("degradedScanners", [])
    engines_ran = s.get("enginesRan", [])
    changes = s.get("changesSinceLastScan")
    incomplete = scan_status != "complete"
    band_color = BAND_COLOR.get(band, "#8b949e")
    if incomplete:
        band_color = "#d29922" if scan_status == "partial" else "#8b949e"

    # engine scorecard — AI-pattern rules run inside SAST, so fold them into opengrep;
    # show only engines that were actually applicable (ran or degraded), incl. DAST.
    counts_by_scanner = {}
    for f in findings:
        k = f.get("scanner")
        k = "opengrep" if k == "ai_patterns" else k
        counts_by_scanner[k] = counts_by_scanner.get(k, 0) + 1
    ENGINE_LABELS = [("gitleaks", "secrets"), ("opengrep", "SAST"),
                     ("osv", "dependencies"), ("dast", "web (DAST)")]
    engines = [(k, lb) for (k, lb) in ENGINE_LABELS if k in engines_ran or k in degraded] \
        or [("gitleaks", "secrets"), ("opengrep", "SAST"), ("osv", "dependencies")]
    if findings:
        cards = "".join(card(f) for f in findings)
    elif scan_status == "complete":
        cards = ('<p class="empty">✓ No secrets, injection, insecure patterns, or vulnerable '
                 'dependencies detected. All applicable engines ran.</p>')
    else:
        cards = ('<p class="empty-incomplete">No findings were produced, but the scan was '
                 'incomplete (see the banner above). This is not a clean result.</p>')

    low_conf_only = findings and all(f.get("confidence") == "low" for f in findings)
    caveat = ""
    if low_conf_only:
        caveat = ('<div class="caveat">Every finding is low-confidence (entropy/generic or '
                  'test-path). The headline band is driven by items worth verifying, not '
                  'confirmed issues — the true risk is likely lower.</div>')

    engine_cells = ""
    for key, label in engines:
        deg = key in degraded
        n = counts_by_scanner.get(key, 0)
        status = "—" if deg else str(n)
        cls = "deg" if deg else ("hit" if n else "clean")
        engine_cells += f'<div class="engine {cls}"><div class="en">{esc(label)}</div><div class="ev">{status}</div></div>'

    sev_pills = "".join(
        f'<span class="pill" style="--c:{SEV_COLOR.get(k)}">{by_sev.get(k)} {k}</span>'
        for k in ("critical", "high", "medium", "low", "info") if by_sev.get(k)
    )
    if not sev_pills:
        if scan_status == "complete":
            sev_pills = '<span class="pill" style="--c:#3fb950">0 findings</span>'
        elif scan_status == "failed":
            sev_pills = '<span class="pill" style="--c:#8b949e">no usable assessment</span>'
        else:
            sev_pills = '<span class="pill" style="--c:#d29922">0 findings · incomplete coverage</span>'

    changes_strip = ""
    if changes:
        changes_strip = (f'<div class="changes">Since last scan · '
                         f'<b class="new">{changes["new"]} new</b> · '
                         f'<b class="fixed">{changes["fixed"]} fixed</b> · '
                         f'<b>{changes["persisting"]} still open</b></div>')

    score_display = "N/A" if score is None else esc(score)
    score_unit = "" if score is None else '<small>/100</small>'
    incomplete_html = ""
    if incomplete:
        if scan_status == "failed":
            _msg = (f"Required engines did not complete ({esc(', '.join(degraded))}). "
                    "No conclusion about code safety can be made.")
        else:
            _msg = (f"{esc(', '.join(degraded))} did not complete. Findings are a floor, not a "
                    "complete assessment — absence of findings is not a clean result.")
        incomplete_html = f'<div class="incomplete">⛔ ASSESSMENT INCOMPLETE — {_msg}</div>'

    cov = s.get("coverageNotes", [])
    cov_html = ""
    if cov:
        items = "".join(f"<li>{esc(c)}</li>" for c in cov)
        cov_html = f'<div class="covnotes"><b>Coverage notes</b><ul>{items}</ul></div>'

    if scan_status == "failed":
        band_label, subtitle = "Assessment incomplete", ""
    elif scan_status == "partial" and not findings:
        band_label, subtitle = "Partial — inconclusive", ""
    elif scan_status == "partial":
        band_label, subtitle = f"{esc(band)} risk · partial coverage", ""
    elif band == "clean":
        n_engines = len([e for e in ("gitleaks", "opengrep", "osv") if e not in degraded])
        band_label = "✓ Clean"
        subtitle = f'<div class="subtitle">No issues found · {n_engines} engine{"s" if n_engines != 1 else ""} ran clean</div>'
    else:
        band_label, subtitle = f"{esc(band)} risk", ""

    doc = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VibeScan report</title>
<style>
:root {{ color-scheme: dark; }}
* {{ box-sizing: border-box; }}
body {{
  margin:0; background:#0e1116; color:#f7f8f9;
  font: 15px/1.55 system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
  padding: 40px 20px;
}}
.wrap {{ max-width: 820px; margin: 0 auto; }}
.mono {{ font-family: ui-monospace, "SF Mono", "JetBrains Mono", Menlo, monospace; }}
.brand {{ display:flex; align-items:center; gap:10px; color:#8b949e; font-size:13px; letter-spacing:.08em; text-transform:uppercase; margin-bottom:20px; }}
.brand b {{ color:#39c5cf; }}
.verdict {{
  border:1px solid #21262d; border-left:4px solid {band_color};
  border-radius:10px; background:#161b22; padding:22px 24px; margin-bottom:16px;
}}
.verdict .band {{ font-size:13px; letter-spacing:.1em; text-transform:uppercase; color:{band_color}; font-weight:700; }}
.verdict .score {{ font-size:44px; font-weight:800; line-height:1.1; margin:4px 0 2px;
  font-family: ui-monospace, "SF Mono", Menlo, monospace; }}
.verdict .score small {{ font-size:18px; color:#8b949e; font-weight:600; }}
.verdict .subtitle {{ font-size:13.5px; color:#3fb950; margin-top:2px; }}
.pills {{ display:flex; gap:8px; flex-wrap:wrap; margin-top:10px; }}
.pill {{ font-size:12px; padding:3px 9px; border-radius:20px; border:1px solid var(--c);
  color:var(--c); font-family: ui-monospace, Menlo, monospace; }}
.changes {{ font-size:13px; color:#8b949e; margin-top:12px; font-family: ui-monospace, Menlo, monospace; }}
.changes b {{ color:#f7f8f9; }} .changes .new {{ color:#f0883e; }} .changes .fixed {{ color:#3fb950; }}
.scorecard {{ display:grid; grid-template-columns:repeat(4,1fr); gap:8px; margin-bottom:16px; }}
.engine {{ background:#161b22; border:1px solid #21262d; border-radius:8px; padding:12px; text-align:center; }}
.engine .en {{ font-size:12px; color:#8b949e; text-transform:uppercase; letter-spacing:.05em; }}
.engine .ev {{ font-size:24px; font-weight:800; font-family: ui-monospace, Menlo, monospace; margin-top:2px; }}
.engine.clean .ev {{ color:#3fb950; }} .engine.hit .ev {{ color:#f0883e; }} .engine.deg .ev {{ color:#8b949e; }}
.caveat {{ background:rgba(210,153,34,.1); border:1px solid #d29922; color:#e3b341;
  border-radius:8px; padding:12px 14px; font-size:13px; margin-bottom:16px; }}
.incomplete {{ background:rgba(210,153,34,.12); border:1px solid #d29922; color:#e3b341;
  border-radius:10px; padding:16px 18px; font-size:14px; font-weight:600; margin-bottom:16px; }}
.empty-incomplete {{ color:#e3b341; }}
.deg-note {{ font-size:12px; color:#8b949e; margin-bottom:16px; }}
.covnotes {{ background:#161b22; border:1px solid #21262d; border-radius:8px; padding:12px 16px;
  font-size:13px; color:#c9d1d9; margin-bottom:16px; }}
.covnotes ul {{ margin:6px 0 0; padding-left:18px; }} .covnotes b {{ color:#e3b341; }}
h2.section {{ font-size:13px; text-transform:uppercase; letter-spacing:.08em; color:#8b949e; margin:24px 0 10px; }}
.finding {{ background:#161b22; border:1px solid #21262d; border-left:3px solid var(--sev);
  border-radius:8px; padding:16px 18px; margin-bottom:12px; }}
.finding-head {{ display:flex; align-items:center; gap:10px; flex-wrap:wrap; }}
.finding-head h3 {{ margin:0; font-size:15px; font-weight:650; flex:0 1 auto; }}
.sev {{ font-size:11px; font-weight:800; color:#0e1116; padding:2px 7px; border-radius:5px;
  font-family: ui-monospace, Menlo, monospace; }}
.chip {{ font-size:11px; padding:2px 7px; border-radius:12px; font-family: ui-monospace, Menlo, monospace; }}
.chip.verify {{ background:rgba(210,153,34,.15); color:#e3b341; border:1px solid #d29922; }}
.chip.new {{ background:rgba(240,136,62,.15); color:#f0883e; border:1px solid #f0883e; }}
.meta {{ display:flex; gap:14px; flex-wrap:wrap; font-size:12px; color:#8b949e; margin:8px 0;
  font-family: ui-monospace, Menlo, monospace; }}
.meta .loc {{ color:#39c5cf; }}
.evidence {{ background:#0e1116; border:1px solid #21262d; border-radius:6px; padding:8px 10px;
  font-family: ui-monospace, Menlo, monospace; font-size:12.5px; color:#e6edf3; overflow-x:auto; margin:8px 0; }}
.note {{ font-size:12.5px; color:#e3b341; margin:6px 0; }}
.fix {{ font-size:13.5px; margin-top:8px; }}
.fix span {{ display:inline-block; font-size:10px; font-weight:800; color:#3fb950; letter-spacing:.1em;
  margin-right:8px; vertical-align:1px; }}
.fp {{ font-family: ui-monospace, Menlo, monospace; font-size:11px; color:#484f58; margin-top:8px; }}
.empty {{ color:#3fb950; }}
footer {{ margin-top:28px; font-size:12px; color:#484f58; text-align:center; font-family: ui-monospace, Menlo, monospace; }}
@media (max-width:560px) {{ .scorecard {{ grid-template-columns:repeat(2,1fr); }} }}
</style></head>
<body><div class="wrap">
  <div class="brand mono">🛡 <b>VibeScan</b> · security report</div>
  {incomplete_html}
  <div class="verdict">
    <div class="band">{band_label}</div>
    <div class="score">{score_display}{score_unit}</div>
    {subtitle}
    <div class="pills">{sev_pills}</div>
    {changes_strip}
  </div>
  {caveat}
  <div class="scorecard">{engine_cells}</div>
  {"<div class='deg-note mono'>Did not complete: " + esc(", ".join(degraded)) + "</div>" if degraded else ""}
  {cov_html}
  <h2 class="section">Findings ({len(findings)})</h2>
  {cards}
  <footer>Generated by VibeScan · fingerprints are stable across scans</footer>
</div></body></html>"""

    out = os.path.join(target, ".vibescan", "report.html")
    with open(out, "w") as f:
        f.write(doc)
    print(f"html report: {out}")


if __name__ == "__main__":
    main()
