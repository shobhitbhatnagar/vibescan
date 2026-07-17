#!/usr/bin/env bash
# VibeScan release deploy helper.
#
# Run from the repo root AFTER the updated files are in place. It gates on the hermetic
# test suite, shows what will change, then (on confirmation) commits, tags, pushes, and
# creates a GitHub release with RELEASE_NOTES.md as the body and vibescan.skill attached.
#
# Nothing destructive: no force-push, no history rewrite. Confirmation is required before
# any push or release. Set DRY_RUN=1 to print the git/gh commands without executing them.
#
#   ./deploy.sh                 # normal deploy (asks before pushing)
#   DRY_RUN=1 ./deploy.sh       # show exactly what it would do, change nothing
#   SKIP_TESTS=1 ./deploy.sh    # skip the test gate (not recommended)
set -euo pipefail

VERSION="$(cat VERSION 2>/dev/null || echo 0.3.0)"
TAG="v${VERSION}"
DRY_RUN="${DRY_RUN:-0}"
SKIP_TESTS="${SKIP_TESTS:-0}"

say()  { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
run()  { if [ "$DRY_RUN" = "1" ]; then printf '[dry-run] %s\n' "$*"; else eval "$*"; fi; }

# 0. sanity: are we actually in the vibescan repo?
if [ ! -f SKILL.md ] || [ ! -f scripts/scan.py ]; then
  echo "error: run this from the vibescan repo root (SKILL.md + scripts/scan.py not found)"; exit 1
fi
git rev-parse --is-inside-work-tree >/dev/null 2>&1 || { echo "error: not a git repo"; exit 1; }

# 1. pre-flight: the hermetic suite must pass before we ship anything
if [ "$SKIP_TESTS" != "1" ]; then
  say "Pre-flight: hermetic test suite (python3 tests/e2e_test.py)"
  python3 tests/e2e_test.py || { echo "tests failed — aborting deploy"; exit 1; }
else
  echo "-- skipping tests (SKIP_TESTS=1)"
fi

# 2. show what will change
say "Changes to be committed"
git status --short || true
echo
echo "Version : ${VERSION}"
echo "Tag     : ${TAG}"
echo "Remote  : $(git remote get-url origin 2>/dev/null || echo '(no origin)')"

# 3. confirm
say "About to commit, tag ${TAG}, push to origin, and create a GitHub release"
if [ "$DRY_RUN" != "1" ]; then
  read -r -p "Proceed? [y/N] " ans
  [ "${ans:-N}" = "y" ] || { echo "aborted — nothing pushed"; exit 0; }
fi

# 4. commit (skip if nothing staged)
run "git add -A"
if [ "$DRY_RUN" = "1" ] || ! git diff --cached --quiet; then
  run "git commit -m 'Release ${TAG}: pinned toolchain, verified rules, coverage-honest reporting, DAST + test hardening, reproducible validation'"
else
  echo "-- working tree already committed; skipping commit"
fi

# 5. tag (annotated; skip if it already exists)
if git rev-parse "$TAG" >/dev/null 2>&1; then
  echo "-- tag ${TAG} already exists; leaving it as-is"
else
  run "git tag -a '${TAG}' -m 'VibeScan ${TAG}'"
fi

# 6. push branch + tag
run "git push origin HEAD"
run "git push origin '${TAG}'"

# 7. GitHub release (needs gh authenticated: gh auth status)
say "GitHub release"
if command -v gh >/dev/null 2>&1; then
  attach=""
  [ -f vibescan.skill ] && attach="vibescan.skill"
  # attach the newest validation bundle if one has been generated
  latest_bundle="$(ls -td validation-bundle/*/ 2>/dev/null | head -1 || true)"
  if [ -n "${latest_bundle}" ]; then
    run "tar -czf validation-bundle.tar.gz -C validation-bundle '$(basename "${latest_bundle}")'"
    attach="${attach} validation-bundle.tar.gz"
  fi
  if gh release view "${TAG}" >/dev/null 2>&1; then
    echo "-- release ${TAG} already exists; uploading assets only"
    [ -n "${attach}" ] && run "gh release upload '${TAG}' ${attach} --clobber"
  else
    run "gh release create '${TAG}' ${attach} --title 'VibeScan ${TAG}' --notes-file RELEASE_NOTES.md"
  fi
else
  echo "-- gh CLI not found. Create the release manually:"
  echo "     Draft a release on tag ${TAG}, paste RELEASE_NOTES.md as the body,"
  echo "     and attach vibescan.skill (and the validation bundle if generated)."
fi

say "Done"
echo "Remember: also upload vibescan.skill in Claude → Settings → Capabilities → Skills"
echo "to update the live skill (the GitHub release is the source-of-record, not the live skill)."
