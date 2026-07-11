# VibeScan — a Claude Skill for security scanning

A self-contained [Claude Skill](https://docs.claude.com) that scans code for exposed
secrets, injection and other insecure patterns, AI-generated ("vibe-coded") anti-patterns,
and known-vulnerable dependencies — then returns findings with severity, evidence, and
plain-English fixes. No hosted service, no account: the scan runs entirely in Claude's
code-execution sandbox using open-source engines.

## What it uses

| Category | Engine | License |
|---|---|---|
| Secrets | Gitleaks | MIT |
| SAST (injection, XSS, etc.) | Opengrep / Semgrep engine + bundled rules | LGPL 2.1 (engine); rules are original |
| Dependency vulnerabilities | OSV.dev API | Apache 2.0 |

TruffleHog (AGPL) and Semgrep's registry rules (SaaS-restricted) are intentionally avoided.

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
git clone https://github.com/shobhitbhatnagar/vibescan.git ~/.claude/skills/vibescan
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

The headline risk band is built to be right *before* a human second-guesses it:

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

## License

MIT — see [`LICENSE`](LICENSE). The bundled rule files and scanner scripts are original work.
The third-party engines are *invoked, not redistributed*, and keep their own licenses: Gitleaks
(MIT), Opengrep/Semgrep engine (LGPL 2.1), OSV.dev data (Apache 2.0). None are bundled in this
repo; they're downloaded at runtime from their own sources.
