# VibeScan — a Claude Skill for security scanning

> **Installing:** upload only `vibescan.skill`. Any loose files shipped alongside it are for review/diffing, not for installation.

A self-contained [Claude Skill](https://docs.claude.com) that scans code for exposed
secrets, injection and other insecure patterns, AI-generated ("vibe-coded") anti-patterns,
and known-vulnerable dependencies — then returns findings with severity, evidence, and
plain-English fixes. No hosted service, no account: the scan runs entirely in Claude's
code-execution sandbox using open-source engines.

## What it uses

| Category | Engine | License |
|---|---|---|
| Secrets | Gitleaks | MIT |
| SAST (injection, XSS, etc.) | Opengrep / Semgrep engine + bundled `ai-patterns.yml` | LGPL 2.1 (engine); bundled pack is original |
| SAST (multi-language, auto-selected) | opengrep-rules mirror | LGPL 2.1 + Commons Clause (no-sell) |
| Dependency vulnerabilities | OSV.dev API | Apache 2.0 |

TruffleHog (AGPL) and Semgrep's registry / `--config auto` path (login + telemetry) are
intentionally avoided. The opengrep-rules mirror carries a Commons Clause (no-sell) — this is a
mixed-license build. See `THIRD_PARTY_LICENSES.md`.

## Install as a skill

Download `vibescan.skill` from the [releases](../../releases) and click **Save skill** in
Claude, or add the folder to your skills directory. Then just ask Claude things like:

- "Scan this code for security issues: …"
- "Security-review the repo https://github.com/OWASP/NodeGoat"
- "Check my project for hardcoded secrets and vulnerable dependencies"

### Claude Code (put it on disk directly)

Account-skill sync into a Claude Code container can be flaky — if a session reports the skill
isn't found, install it on disk yourself, which always works:

```bash
git clone <your-repo-url> ~/.claude/skills/vibescan
# or, from a checkout of this repo:
bash install.sh
```

Then run "scan" in that session. (If your Code environment lists skills under a different path,
point `install.sh` at it: `bash install.sh /that/path/.claude/skills`.)

## Run standalone

Cross-platform — runs anywhere Python does (macOS, Linux, Windows):

```bash
python3 scripts/scan.py <dir-or-repo-url>        # macOS / Linux
python scripts\scan.py  <dir-or-repo-url>        # Windows
# writes <target>/.vibescan/findings.json, report.md, report.html
```

A repo URL is cloned durably into `~/.vibescan/repos/<name>/` and re-scans diff against the
previous run. (`scripts/run_scan.sh` / `scan_repo.sh` remain as macOS/Linux shims.)

**Platform coverage:** gitleaks (secrets) and OSV (dependencies) run natively everywhere,
including Windows; SAST (semgrep/opengrep) has no native Windows build, so on native Windows the
SAST stage degrades — use WSL for full coverage. Only `python3` and `git` are required.

Engines auto-install on first run (with a notice) — missing ones degrade gracefully. Skip with
`--no-install`; see [`references/engines.md`](references/engines.md).

## Trustworthy severity

How the headline risk band avoids false alarms:

- **Secret confidence tiering** — named-provider matches (AWS, Stripe, GitHub, private keys)
  are critical; entropy/generic matches are medium and flagged **⚠️ verify**.
- **Path awareness** — findings in `test/`, `fixtures/`, `spec/`, `examples/` and `*.test.*`
  files are down-weighted one level, since they're rarely production risk.
- **Honest headline** — when the score is driven entirely by low-confidence items, the report
  says so up front instead of leading with a scary number.
- **Allowlist aware** — a repo's own `.gitleaks.toml` is respected, and inline
  `# gitleaks:allow` works.

## Custom rules

Drop additional Opengrep/Semgrep `*.yml` files into `assets/rules/` — they're picked up
automatically. Rule `severity: ERROR` maps to high, `WARNING` to medium, `INFO` to low.
Multi-language coverage beyond this pack comes from the auto-selected opengrep-rules mirror
(see License).

## License

VibeScan's own code and the bundled `ai-patterns.yml` pack are MIT (see `LICENSE`). The
scanner also uses the opengrep-rules mirror for multi-language SAST, which is LGPL 2.1 +
Commons Clause (no-sell); it is fetched at runtime into `~/.vibescan/` or vendored as a
submodule. This makes the project mixed-license: fine for personal, internal, and free use,
but not for a paid or SaaS product while the mirror is present. Full terms and the notice
requirement are in `THIRD_PARTY_LICENSES.md`. For a fully MIT/sellable build, run without the
mirror and SAST falls back to the bundled pack only.
