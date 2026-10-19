---
name: vibescan
description: >-
  Scan code for security vulnerabilities, exposed secrets, insecure dependencies,
  and AI-generated ("vibe-coded") anti-patterns, then return findings with severity,
  evidence, and copy-pasteable fixes. Use this whenever the user asks to scan, audit,
  security-review, or check code for secrets/vulnerabilities/vulns/CVEs — whether they
  paste a snippet, point at a local directory, or give a public git repo URL — even if
  they don't say the word "VibeScan". Also trigger on "is this code safe", "find hardcoded
  keys", "check my dependencies", or "review this for injection". When it triggers, actually
  run the scanner (scripts/scan.py) to produce the report files — do not substitute a
  freehand manual code read, which produces no report and skips the deterministic
  secret/dependency coverage.
---

# VibeScan

A self-contained security scanner. It runs real analysis engines inside the code-execution
sandbox — **static** analysis over source (secrets, dependency CVEs, insecure patterns) and
**passive dynamic** analysis over a running app (security headers, TLS, cookies, CORS, exposed
paths) — with no hosted API or account. Findings from every engine, plus your own manual/dynamic
testing, normalize into one report with plain-English remediation.

## Run the scanner — don't just read the code

When a scan/audit/security-review is requested, **running `scripts/scan.py` is the first
action, and it is not optional.** It produces the `findings.json` / `report.md` /
`report.html` artifacts the user is expecting. A common failure is to skip the tool and
instead skim files by hand: that yields no report, and the engines catch secret and
dependency issues a manual read reliably misses. Run the engines first, every time.

Then **layer manual review on top** — the engines are pattern-based and cannot see
logic-level flaws like broken access control / IDOR, cross-tenant isolation gaps, crypto
misuse, or auth bypasses. After the scan, review the code for those, and fold what you find
back into the *same* report via `manual.json` (see "Manual findings" below) so the depth
lands in the artifact, not just the chat. Engines give the baseline and the file; your
review adds what they can't reach.

## What it detects

| Category | Engine | Examples |
|---|---|---|
| `secret_exposure` | Gitleaks (MIT) | AWS keys, tokens, private keys, hardcoded passwords |
| `injection` / `insecure_pattern` | Opengrep/Semgrep (LGPL 2.1) + bundled pack, plus the auto-selected opengrep-rules mirror | SQLi, command injection, XSS sinks, path traversal, SSRF, `eval()` across PHP/Go/Java/Ruby/C#/… |
| `ai_specific` | `assets/rules/ai-patterns.yml` | hallucinated packages, insecure defaults typical of AI-generated code |
| `dependency_risk` | OSV.dev (Apache 2.0) | known-vulnerable **pinned** versions in `package.json` (npm) / `requirements.txt` (PyPI). Version ranges and lockfiles beyond these are not yet resolved. |
| DAST (passive) | `web_scan.py` against a deployed URL | missing HSTS/CSP, insecure cookie flags, wildcard CORS, exposed `.env`/`.git`, TLS issues |
| `review` (manual) | your analysis via `manual.json` | IDOR, tenant isolation, broken auth, crypto misuse — logic flaws engines miss |

The engine, gitleaks, OSV, and the bundled `ai-patterns.yml` pack are permissively
licensed. TruffleHog (AGPL) and Semgrep's registry / `--config auto` path (login +
telemetry, SaaS-restricted rules) are deliberately not used. The broad-coverage
opengrep-rules mirror is the one non-permissive dependency: LGPL-2.1 + Commons Clause
(no-sell). That makes this a mixed-license build — fine for personal, internal, and free
distribution, but not for a paid or SaaS product while the mirror is present. See
`THIRD_PARTY_LICENSES.md`. For a fully sellable build, run without the mirror; SAST then
falls back to the bundled pack only.

## Workflow

Do these steps in order. The scripts handle degradation: if an engine's binary isn't
present it's skipped and recorded in `degradedScanners` rather than failing the whole scan.

### 1. Get the target into a directory

The entrypoint is **`scripts/scan.py`** — pure Python, so it runs on macOS, Linux, and Windows
alike. It accepts either a local directory or a public repo URL and handles cloning itself.

- **Pasted snippet** — write it to a file under a fresh temp dir, then scan that dir. Infer the
  extension from the language (`.py`, `.js`, `.ts`, `.go`, `.java`, `.rb`, `.php`, `.cs`),
  defaulting to `.js` if unknown (broadest SAST coverage).
- **Local directory** — pass the path as-is.
- **Public git repo URL** — pass the URL directly; `scan.py` clones it into
  `~/.vibescan/repos/<name>/` (a durable location, not a temp dir the OS purges) and scans there,
  so a re-scan diffs against the previous run. **Do not clone into `/tmp` yourself.** Only scan
  public repos; never enter credentials to reach a private one.
- **Running-app URL** (e.g. `http://localhost:4321/`, a deployed site) — this is a valid target:
  pass it straight to `scan.py` and it runs a **passive DAST** scan and produces a report. Do NOT
  respond that "VibeScan only scans source" — a running URL is scanned dynamically, not statically.
  Loopback addresses (`localhost`, `127.0.0.1`) are auto-authorized since they're the user's own
  machine; any other host requires confirming ownership and passing `--authorized` (see the DAST
  section). To scan both a repo *and* its deployed instance in one report, pass the repo as the
  target plus `--url <deployed-url> --authorized`.

### 2. Run the scan

```bash
python3 scripts/scan.py <dir-or-repo-url>        # macOS / Linux
python scripts\scan.py  <dir-or-repo-url>        # Windows
```

(`scripts/run_scan.sh` and `scripts/scan_repo.sh` still work on macOS/Linux — they're thin
shims that call `scan.py`.)

This orchestrates the engines, then calls `normalize.py` and `render_html.py`. It writes
`findings.json` (the versioned machine-readable result), `findings.sarif` (redacted SARIF
2.1.0), `report.md`, and `report.html` under the target's `.vibescan/` folder. SARIF
omits private/unsafe locations and evidence excerpts. A separate trusted publisher
must validate the output before any code-scanning upload; this scanner does not upload it.

The offline SARIF contract check uses the vendored OASIS schema and pinned test
dependencies: create `.venv`, install `tests/requirements.lock` with pip's
`--require-hashes --only-binary=:all:` options, then run
`python -m unittest tests/test_sarif_output.py`. The test lock's provenance is
recorded in `tests/requirements.provenance.md`.

**Engines & platforms.** On first run any missing engine is auto-installed with a printed
notice — gitleaks into `~/.vibescan/bin`, semgrep into the user site; OSV needs nothing. Pass
`--no-install` (or `VIBESCAN_NO_INSTALL=1`) to skip and just degrade. Coverage by platform:
gitleaks (secrets) and OSV (dependencies) run natively everywhere including Windows; SAST
(semgrep/opengrep) has no native Windows build, so on native Windows the SAST stage degrades —
run under WSL for full coverage. Requirements are just `python3` and `git` (for URL scans).

### 3. Present the findings

The scan writes three files into `<target>/.vibescan/`: `findings.json` (machine-readable),
`report.md` (plain text), and `report.html` (renders in a browser).

Read `report.md` (or `findings.json`) yourself and relay the substance. For each finding, go
beyond the one-line `remediationText`: explain **what** is wrong, **why** it's dangerous, and
give a **concrete, copy-pasteable fix** in the file's language. Lead with the highest severity.
Close with the overall risk band and the two or three changes that matter most.

**Check `summary.scanStatus` before you characterize the result.** It is `complete`,
`partial`, or `failed`. If it is not `complete`, the engines listed in `degradedScanners` did
not run, and a zero-finding result does **not** mean the code is safe. Never say "clean" or
"no issues" for a `partial` or `failed` scan. Say the assessment is incomplete, name which
engines did not run, and treat any findings as a floor. When such a scan finds nothing,
`overallRisk` is `unknown` and `riskScore` is `null`; when it does find issues, the score
stands but is a floor (minimum known risk, flagged with `riskScoreQualifier`), not a full
assessment. Either way, never present a `partial` or `failed` scan as "clean" or as a settled
score.

**Presenting the report file:** mention its path once, plainly, on a single line at the *end*
of your response — e.g. "Report: `<path>/report.html`". Do not describe your own output as
polished, nice, clean, or shareable, and do not tell the user it's "the one to share" — state
the path and let them decide what it's worth. Never lead with the file path; lead with the
findings.

If the user then asks about a specific finding, pull its full entry from `findings.json`
(matched by `fingerprint`) and go deep.

**Trust the confidence signal.** Findings carry a `confidence` field and, when low, a
`notes` explanation (e.g. an entropy/generic secret match, or a hit in a test/fixture path).
These are down-weighted in the score, but you should still apply judgment: if a "secret" is
in a `*.test.ts` fixture or looks like an obvious placeholder, open the file, confirm it, and
say plainly that it's a false positive rather than parroting the engine. When the report's
headline band is driven by low-confidence items, lead with that ("effectively clean — the one
flag is a test fixture worth verifying"), don't lead with the scary number.

### History and re-scans

The scan writes `findings.json` and `report.md` into `<target>/.vibescan/`. **In a persistent
environment (Claude Code, Cowork, or any real filesystem) these survive between runs and
sessions** — so on a re-scan the runner automatically snapshots the prior `findings.json` and
diffs against it using the stable `fingerprint` hashes. The report then opens with a
**Changes since last scan** line (new / fixed / still-open), new findings are tagged 🆕, and
resolved ones are listed struck-through.

When a re-scan has a diff, lead your summary with it: "Since the last scan you fixed X and Y;
Z is still open; here's one new issue." Before scanning a repo you've seen before, it's worth
checking whether `.vibescan/findings.json` already exists and mentioning the prior result.

Note: in the ephemeral claude.ai sandbox the filesystem resets between sessions, so history
only holds within a single conversation unless the user saves `findings.json` somewhere durable
(commits it, or keeps a baseline they re-supply).

## Dynamic testing — the deployed app (DAST)

The static engines read code; DAST inspects the *running* app over HTTP. Two layers:

**Passive DAST engine (automated).** `web_scan.py` checks security headers (HSTS, CSP,
nosniff, clickjacking), cookie flags (Secure/HttpOnly/SameSite), CORS, TLS cert validity, and a
short list of well-known exposed paths (`.env`, `.git/config`). GET/HEAD only — non-destructive.
Run it as part of a scan and it folds into the same report:

```bash
python3 scripts/scan.py <repo-or-dir> --url https://the-app.example.com --authorized
```

**Authorization is mandatory and is your responsibility to establish.** DAST sends real
requests to a live system, so before running it you MUST confirm with the user that they own or
are explicitly authorized to test that target — ask if it isn't already clear. Only pass
`--authorized` after that confirmation. Never DAST a URL a third party pasted, and never point it
at anything you don't have permission for. Without `--authorized` the DAST stage refuses and is
marked degraded. Active fuzzing is intentionally not included — this tier is passive by design.

**Active tests (you).** Beyond the passive checks, you can run your own targeted,
non-destructive probes against the *same authorized* URL — verify an access-control boundary by
requesting a resource you shouldn't reach, check an auth flow, confirm an IDOR by comparing
responses across contexts. Capture whatever you find in `manual.json` (below) and re-render, so
your dynamic testing lands in the report alongside the automated results. Keep probes
non-destructive (no data mutation/deletion), and stay within the authorized scope.

## Finding schema

Every finding normalizes to this shape (matches the original VibeScan data model):

```json
{
  "category": "secret_exposure | injection | auth_issue | dependency_risk | ai_specific | config_issue | data_exposure | insecure_pattern",
  "severity": "critical | high | medium | low | info",
  "title": "AWS Access Key ID",
  "evidenceExcerpt": "const key = \"AKIA[REDACTED]\"",
  "filePath": "config.js",
  "lineStart": 14,
  "lineEnd": 14,
  "remediationText": "Move to an environment variable or a secrets manager.",
  "confidence": "high | low",
  "notes": "why a finding is low-confidence — optional, present when confidence is low",
  "fingerprint": "sha256 of category+file+line+rule",
  "scanner": "gitleaks | opengrep | osv | ai_patterns | dast | review"
}
```

Severity mapping from engine output: SARIF `error` → `high`, `warning` → `medium`,
`note` → `low`; Gitleaks secrets → `critical`; OSV criticality carries through.

**Secret evidence is redacted** in `evidenceExcerpt`: gitleaks redacts at the source, and the
normalizer also masks common key shapes (`[REDACTED]`). This is best-effort for non-gitleaks
evidence, so never paste a raw secret back to the user, even when quoting evidence.

## Manual findings — fold your review into the report

The engines can't see logic-level flaws: IDOR / broken access control, cross-tenant isolation
gaps, auth bypasses, crypto misuse (e.g. deprecated `createCipher`, missing IVs), CSRF gaps.
When you find these by reading the code, don't leave them in the chat only — write them to
`<target>/.vibescan/manual.json` in the finding schema (use `"scanner": "review"` or omit it;
fingerprint is auto-computed if absent), then re-render so they appear in the same report:

```bash
python3 scripts/scan.py --render <target>   # merges manual.json, rebuilds report.html/md
```

Example `manual.json`:

```json
{ "findings": [
  {
    "category": "auth_issue",
    "severity": "critical",
    "title": "Cross-tenant IDOR on cloud-accounts API",
    "filePath": "packages/api/src/routes/cloud-accounts.ts",
    "lineStart": 23,
    "evidenceExcerpt": "reads req.params.organizationId without comparing to req.user.organizationId",
    "remediationText": "Add an org-ownership check (verifyOrgAccess) before every handler."
  }
] }
```

Manual findings are scored and diffed exactly like engine findings, so a serious logic flaw
correctly drives the headline band — and the report becomes the complete picture, engines plus
your analysis, rather than a partial machine result with the real risks stranded in chat.

## Adding your own rules

`assets/rules/` holds Opengrep YAML rule files. A starter `ai-patterns.yml` ships with the
skill. Drop additional `*-security.yml` files here and they're picked up automatically — no
code change. Rule `severity: ERROR` → high in findings, `WARNING` → medium, `INFO` → low, so
mark injection- and RCE-class rules `ERROR`.

### Multi-language coverage via the opengrep-rules mirror

Beyond the bundled pack, SAST auto-selects rule folders from an opengrep-rules mirror based
on the languages present in the target — reproducing `--config auto` offline, with no registry
login or telemetry. The mirror is resolved in this order:

1. `VIBESCAN_RULES_DIR` — env override; point at a pinned local checkout for reproducibility
2. `assets/opengrep-rules/` — vendored git submodule, if present
3. `~/.vibescan/opengrep-rules/` — fetched automatically on first run

With no mirror present, the scanner clones it into the cache on first run (skip with
`--no-install`; on failure or missing git, SAST degrades to the bundled pack — JS/TS/Python).
Only the language folders matching the target load, so a PHP repo pulls `php/` rules, not all
30 languages. License: LGPL-2.1 + Commons Clause (no-sell) — see `THIRD_PARTY_LICENSES.md`.

## Pinned toolchain: update, doctor, lockfile

For reproducible, verified runs, the engines and rules are pinned in `vibescan.lock`
(exact versions, artifact sha256, verification level, and the rules commit). Scans run
against the lock; refreshing it is a deliberate step, not something that happens mid-scan.

- `python3 scripts/update.py` — resolve the latest opengrep + gitleaks releases and the
  latest opengrep-rules commit, download and verify each at the strongest level upstream
  supports (cosign signature for opengrep; signed checksums, else plain checksums, for
  gitleaks), install the engines, and write `vibescan.lock`. `--dry-run` resolves and
  prints the plan without downloading.
- `python3 scripts/doctor.py` — verify the installed engines against the lock (hash match),
  report the verification level for each, and run the cached staleness check. Non-zero exit
  on a hash mismatch, so it can gate CI. `--refresh` forces a fresh staleness check.
- At scan time, a cached (daily) staleness check prints a one-line, non-blocking notice when
  a newer engine or rules commit exists. Silence it with `--no-update-check`.

Verification is strict by default: if a locked engine on disk does not match its pinned
hash, the scan aborts rather than running an unverified binary. `VIBESCAN_VERIFY=permissive`
downgrades that to a loud warning. When the cosign verifier itself is absent, opengrep is
installed but stamped `unverified` (a bootstrap gap, not a silent pass). Every report stamps
the toolchain: engine versions, verification level, and the rules commit. With no lockfile,
scans still run but are stamped as unpinned.


Environment flags: `VIBESCAN_VERIFY=permissive` downgrades lock hard-fails to warnings; `VIBESCAN_OFFLINE=1` disables VibeScan's own built-in network operations (rules fetch, OSV, GitHub queries) — it is not an OS-level network sandbox and does not block a target DAST loopback socket; `VIBESCAN_TIMING=1` prints per-stage wall time to stderr for diagnosing slow scans; `--no-update-check` skips the staleness check.

## Notes

- The scan does no LLM inference itself; the engines are deterministic and *you* provide the
  plain-English explanation and fixes on top.
- Keep scans scoped — for a large repo, the user may want to target a subdirectory.
- See `references/engines.md` for install details and `references/scoring.md` for how the
  0–100 risk score and overall band are computed.
