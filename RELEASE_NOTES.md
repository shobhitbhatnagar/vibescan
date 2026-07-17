# VibeScan — Release Notes

## v0.3.0 — Pinned toolchain, verified rules, and coverage-honest reporting


This release makes VibeScan's verdicts trustworthy and reproducible. The through-line is that
a scan now never claims **clean** for something it did not actually assess, and the engines and
rules it runs are pinned and cryptographically verifiable.

### Highlights

- **Pinned toolchain (`vibescan.lock`).** New `update` and `doctor` commands fetch, verify, and
  pin the engines and rules; scans run against the lock and stamp the exact versions, verification
  level, and rules commit into every report.
- **Coverage-honest status.** Every scan reports `scanStatus` (`complete`/`partial`/`failed`)
  separately from the risk verdict. Missing engines, unassessable dependencies, or an unreachable
  DAST target produce `unknown` / `partial`, never a false `clean`.
- **Hardened passive DAST.** Per-cookie assessment, an active Origin-reflection probe, and
  baseline-compared exposed-path checks that don't false-positive on SPA/404 shells.
- **A genuinely hermetic test suite** (29 offline cases) that is the deterministic release gate.

### New features

- `scripts/update.py` (`vibescan update`) — resolves the latest opengrep + gitleaks releases and
  the latest opengrep-rules commit, downloads and verifies each at the strongest level upstream
  supports (cosign signature for opengrep; signed checksums for gitleaks), installs the engines,
  and writes `vibescan.lock`. `--dry-run` resolves and prints the plan without downloading.
- `scripts/doctor.py` (`vibescan doctor`) — verifies installed engines against the lock (hash
  match), reports the verification level for each, and runs a cached staleness check. Non-zero
  exit on a hash mismatch so it can gate CI. `--refresh` forces a fresh check.
- `scripts/lockfile.py` — lock schema, artifact hashing, verification helpers, and the cached
  (daily) engine/rules staleness check.
- Scan-time toolchain verification and a non-blocking "update available" notice
  (`--no-update-check` to skip).

### Trust & reproducibility fixes

- **Unreachable DAST** now returns `failed`/degraded, never `complete`/`clean`/0.
- **`--render`** preserves the original coverage state (via `raw/execution.json`) instead of
  resetting engines to "all ran, none degraded."
- **Rules pinning is enforced, not just recorded:** the mirror's actual `HEAD` is checked out to
  and verified against the locked commit; a mismatch aborts. The working tree must be clean
  (`git status --porcelain`), and the origin is verified against the pinned `host/owner/repo`
  (host is pinned — an attacker host with the same path is rejected). Verification fails closed:
  if `git status` can't be determined, the scan aborts in strict mode.
- **No silent engine substitution:** a lock that pins opengrep aborts rather than quietly running
  an unpinned semgrep; the toolchain stamp records the engine actually selected.
- Lock commit must be a 12–40 char hex sha (no short-prefix ambiguity).
- Strict verification is the default; `VIBESCAN_VERIFY=permissive` downgrades hard-fails to
  warnings. `VIBESCAN_OFFLINE=1` disables VibeScan's own network operations. `VIBESCAN_TIMING=1`
  prints per-stage wall time for diagnosing slow scans.

### Dependency scanning

- Only exact-pinned versions are assessed; ranges, wildcards (`1.2.x`), compound (`1.2.3 || 4.0.0`),
  hyphen ranges, and tags (`latest`) are reported as skipped rather than mis-resolved.
- Malformed and recognized-but-unparseable manifests degrade to `partial`, never `not_applicable`/
  clean. OSV emits declared/collected/queried/skipped counts, skipped specs, parse errors, and
  unsupported-manifest lists, with truncation flagged.
- Ecosystem manifests VibeScan doesn't assess yet (Maven `pom.xml`, Gradle, `Cargo.toml`,
  `composer.json`, `Gemfile`, `Pipfile`) are recognized as **unsupported** and degrade the scan to
  `partial` with a coverage note, so a Java/Rust/PHP project can't read as "0 findings / clean".

### DAST hardening

- Each `Set-Cookie` is assessed independently (attributes parsed structurally, so a cookie
  name/value substring can't fake a `Secure`/`HttpOnly`/`SameSite` flag); findings report the
  cookie name only, never its value.
- Active CORS **Origin-reflection probe** (not full preflight analysis).
- Exposed-path checks compare against a random-path baseline and are redirect-aware; suppression
  is on exact body-hash match only (equal length alone never suppresses a real file). Fingerprint
  reads up to 64 KB.
- Tarball extraction hardened (streamed single validated regular-file member; no path traversal).

### Reporting

- **Headline band reflects the worst severity actually present.** `overallRisk` is `critical`/
  `high` only when at least one such finding exists — a large volume of medium/low findings can no
  longer saturate the additive score into a `critical` headline (the `riskScore` still captures
  volume for prioritization). Example: 0 critical, 0 high, 40 medium, 45 low now reads `medium`.
- **Engine-failure notes distinguish timeout-under-load from engine-unavailable** (and a hard
  error), so a scan degraded by contention reads differently from a missing engine.
- Reports (`findings.json`, `report.md`, `report.html`) stamp the toolchain, verification levels,
  rules commit, and coverage notes. Incomplete scans render an "ASSESSMENT INCOMPLETE" state
  instead of a green zero-findings pill.

### Reproducible validation bundle

- `tests/validate.py` automates the manual validation plan into a repeatable evidence
  artifact: it clones each target repo (recording the exact commit SHA), runs a real scan
  with `VIBESCAN_TIMING=1`, captures raw `findings.json`, timing, and logs, checks for leaked
  engine processes (filtering the driver's own matches), records environment + engine versions,
  and writes a `manifest.json` + `summary.md` linking every recorded result to its scan output.
  Run: `python3 tests/validate.py --local` (no network), `--min`, or full. `--write-lock` records
  resolved commit SHAs to `tests/repos.lock` for deterministic re-runs. The manifest carries a
  schema version, VibeScan version + git commit, per-artifact sha256 hashes, and an exit reason
  (completed/timeout/error) for each target — complete, tamper-evident provenance.

### Tests

- `tests/e2e_test.py` — 29 hermetic cases (offline-enforced, per-case watchdog + cleanup,
  process-group kills so a stuck child can't stall the suite) plus opt-in `--live` cases. Covers
  the full scan-status matrix, lockfile integrity, rules commit/dirty/origin verification, engine
  substitution, and the DAST behaviors (cookie substring, CORS reflection, equal-length exposure,
  SPA suppression). Run: `python3 tests/e2e_test.py` (add `--live` for real engines).

### Known limitations (intentionally deferred)

- Reports are not written atomically.
- CORS testing is an Origin-reflection probe only (no OPTIONS preflight).
- PyPI requirement parsing is limited to simple pinned lines; complex requirement syntax is
  reported as incomplete coverage.
- The risk score is an additive heuristic for prioritization, not a formal risk quantification.
- No hosted-service SSRF controls (not applicable to local skill use).

### Scope

Results are advisory. A clean result is not a guarantee; coverage depends on the engines and
supported ecosystems that completed successfully. Suitable for free/personal/beta use.
