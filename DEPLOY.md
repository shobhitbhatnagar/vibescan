# Deploying VibeScan v0.3.0 with Claude Code

Two ways to ship this release. Both are safe: nothing is pushed until you confirm, and the
hermetic test suite must pass first.

## Prerequisites

- The updated files are in your local clone (unzip `vibescan-repo-update.zip` over your
  working copy, or let Claude Code apply the changes).
- `vibescan.skill` is in the repo root (used as a GitHub release asset — it is **not**
  committed; see `.gitignore`).
- `git` remote `origin` points at `github.com/shobhitbhatnagar/vibescan`.
- For the GitHub release step: `gh` CLI installed and authenticated (`gh auth status`).
- `python3` available (the test gate runs `tests/e2e_test.py`).

---

## Option A — let Claude Code do it (paste this prompt)

> You're in my `vibescan` repository. I want to ship release **v0.3.0**. Do this, and stop
> and ask for my confirmation before anything that pushes or publishes:
>
> 1. Run `python3 tests/e2e_test.py` and confirm it reports `29/29 passed`. If anything
>    fails, stop and show me the output.
> 2. Show me `git status --short` and a concise summary of what changed.
> 3. Make sure `.gitignore` excludes `vibescan.skill`, `validation-bundle/`, and
>    `__pycache__/`. Add them if missing.
> 4. Once I approve: stage everything, commit with the message
>    `Release v0.3.0: pinned toolchain, verified rules, coverage-honest reporting, DAST + test hardening, reproducible validation`,
>    create an annotated tag `v0.3.0`, and push the branch and the tag to `origin`.
> 5. Create a GitHub release for `v0.3.0` with `RELEASE_NOTES.md` as the body and attach
>    `vibescan.skill`. Use `gh release create`.
> 6. Remind me to also upload `vibescan.skill` in Claude → Settings → Capabilities → Skills
>    to update the live skill.
>
> Do not force-push or rewrite history. If the tag already exists, don't recreate it.

---

## Option B — run the script

From the repo root:

```bash
DRY_RUN=1 ./deploy.sh     # preview every git/gh command, change nothing
./deploy.sh               # real deploy (gates on tests, asks before pushing)
```

The script: runs the test gate → shows the diff → asks to proceed → commits → tags `v0.3.0`
→ pushes → creates the GitHub release with `RELEASE_NOTES.md` and attaches `vibescan.skill`
(and a validation bundle if one has been generated under `validation-bundle/`).

---

## Optional — attach reproducible validation evidence

Before (or after) releasing, generate the evidence bundle and attach it to the release:

```bash
python3 tests/validate.py --write-lock --min    # clones key repos, real engines, records SHAs
# then re-run deploy.sh, or:
gh release upload v0.3.0 validation-bundle.tar.gz --clobper
```

This needs network and the real engines and takes a while (WebGoat/BenchmarkJava are large).
Run it in an environment with time and connectivity. The bundle contains the manifest,
per-target `findings.json`, timing logs, environment, engine versions, and artifact hashes.

---

## What actually gets deployed where

- **GitHub repo/release** — source of record: the code, `RELEASE_NOTES.md`, and the
  `vibescan.skill` asset. This is what `deploy.sh` / Option A handle.
- **Live Claude skill** — separate step: upload `vibescan.skill` in
  Claude → Settings → Capabilities → Skills. Claude Code cannot do this for you; it's a
  manual upload in the Claude app.
