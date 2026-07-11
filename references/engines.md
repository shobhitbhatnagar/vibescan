# Engines

# Engines

**By default you don't need to install anything manually.** On the first scan, `run_scan.sh`
auto-installs any missing engine with a printed notice — gitleaks into `~/.vibescan/bin` and
semgrep into the user site. OSV needs no install (it's an API call). Pass `--no-install` (or
`VIBESCAN_NO_INSTALL=1`) to skip that, in which case a missing engine is simply skipped and
reported as degraded. The manual steps below are for that case, or for pinning specific versions.

All three engines are also optional at runtime — a missing one is recorded in
`degradedScanners` and the scan continues.

## Gitleaks (secrets) — MIT

```bash
# Linux x86_64
GL=8.28.0
curl -sSL "https://github.com/gitleaks/gitleaks/releases/download/v${GL}/gitleaks_${GL}_linux_x64.tar.gz" \
  | tar -xz -C /usr/local/bin gitleaks
gitleaks version
```

## Opengrep (SAST) — LGPL 2.1

Opengrep is the Semgrep-compatible fork VibeScan standardized on. If Opengrep isn't
available, the runner falls back to `semgrep` automatically (same rule format).

```bash
# via pip (works in most sandboxes)
pip install semgrep --break-system-packages   # fallback engine
# or install the opengrep binary per its release instructions
```

The runner passes `--config assets/rules` so every `*.yml` rule file in that directory
is loaded. `severity: ERROR` → high, `WARNING` → medium, `INFO` → low.

## OSV.dev (dependency vulnerabilities) — Apache 2.0

No install needed — `osv_deps.py` queries the public OSV API over HTTPS. It parses
`package.json` (npm) and `requirements.txt` (PyPI). Extend `_collect_*` in that script
to add ecosystems (Go modules, Maven, RubyGems, etc.). If the sandbox is offline, this
stage degrades to an empty result.

## Not used (on purpose)

- **TruffleHog** — AGPL-3.0, a copyleft SaaS risk.
- **Semgrep registry rules** — Semgrep Rules License v1.0 restricts competing-product use.
  The Opengrep/Semgrep *engine* is fine; only the registry rule content is avoided. All
  rules shipped in `assets/rules/` are original VibeScan-authored patterns.
