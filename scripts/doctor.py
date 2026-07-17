#!/usr/bin/env python3
"""`vibescan doctor` — verify the current install and report staleness.

Checks the installed engines against vibescan.lock (hash match), reports the verification
level recorded for each, and runs the cached staleness check against upstream. Read-only;
never installs or downloads. Exit code is non-zero if a pinned engine fails hash
verification, so it can gate CI.

  vibescan doctor            # verify + cached staleness
  vibescan doctor --refresh  # force a fresh staleness check (ignores the daily cache)
"""
import argparse
import os
import sys
from shutil import which

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lockfile  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--refresh", action="store_true", help="force a fresh staleness check")
    args = ap.parse_args()

    print("VibeScan doctor")
    print(f"  cosign verifier : {'present' if lockfile.have_cosign() else 'ABSENT'}")

    lock = lockfile.load_lock()
    problems = 0

    if lock == "malformed":
        print("  lockfile        : MALFORMED — run `vibescan update`")
        sys.exit(1)
    if not lock:
        print("  lockfile        : none — engines run unpinned. Run `vibescan update` to pin + verify.")
        return

    print(f"  lockfile        : {lockfile.lock_path()}")
    print("\nInstalled engines vs lock:")
    for name in ("gitleaks", "opengrep"):
        spec = (lock.get("engines") or {}).get(name)
        if not spec:
            print(f"  {name:9}: not pinned")
            continue
        path = which(name)
        if not path:
            print(f"  {name:9}: pinned {spec['version']} — NOT installed ({spec.get('verification')})")
            continue
        ok = lockfile.verify_hash(path, spec.get("sha256", ""))
        mark = "OK" if ok else "HASH MISMATCH"
        if not ok:
            problems += 1
        print(f"  {name:9}: {spec['version']}  {mark}  [{spec.get('verification')}]  {path}")

    rules = lock.get("rules") or {}
    print(f"  rules    : @{(rules.get('commit') or '?')[:12]}  [{rules.get('verification')}]")

    print("\nStaleness (cached daily; --refresh to force):")
    st = lockfile.check_staleness(lock, force=args.refresh)
    if not st.get("online") and not any(c["latest"] for c in st["components"]):
        print("  offline or rate-limited — skipped")
    else:
        for c in st["components"]:
            latest = c["latest"] or "unknown"
            print(f"  {c['name']:9}: pinned {c['pinned']}  latest {latest}  -> {c['status']}")

    sys.exit(1 if problems else 0)


if __name__ == "__main__":
    main()
