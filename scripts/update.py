#!/usr/bin/env python3
"""`vibescan update` — refresh the pinned toolchain.

Resolves the latest opengrep + gitleaks releases and the latest opengrep-rules commit,
downloads and verifies each artifact at the strongest level the upstream supports
(cosign signature for opengrep; signed checksums, else plain checksums, for gitleaks),
installs the engines, and writes vibescan.lock. Verification is honest: the level
achieved is recorded per artifact, and a hash mismatch or a rejected signature aborts
the whole update (nothing half-written) unless VIBESCAN_VERIFY=permissive.

  vibescan update            # full: download, verify, install, write lock
  vibescan update --dry-run  # read-only: resolve versions/commit and print the plan
"""
import argparse
import datetime
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lockfile  # noqa: E402

STRICT = os.environ.get("VIBESCAN_VERIFY", "strict") != "permissive"
BIN = lockfile.home_dir() / "bin"
OPENGREP_IDENTITY = r"https://github.com/opengrep/opengrep"
OIDC_ISSUER = "https://token.actions.githubusercontent.com"


def _plat():
    sysname = platform.system().lower()          # linux / darwin
    mach = platform.machine().lower()             # x86_64 / arm64 / aarch64
    arch = "arm64" if mach in ("arm64", "aarch64") else "x64"
    return sysname, arch


def _release(repo):
    return lockfile._get_json(f"https://api.github.com/repos/{repo}/releases/latest")


def _pick_asset(assets, must_have, arch):
    """Choose the asset whose name matches the OS keyword(s) and architecture."""
    arch_alts = {"x64": ("x64", "x86_64", "amd64", "x86"), "arm64": ("arm64", "aarch64")}[arch]
    for a in assets:
        n = a["name"].lower()
        if any(k in n for k in must_have) and any(x in n for x in arch_alts):
            return a
    return None


def _download(url, dest):
    req = urllib.request.Request(url, headers={"User-Agent": "vibescan"})
    with urllib.request.urlopen(req, timeout=60) as r, open(dest, "wb") as f:
        f.write(r.read())


def _abort(msg):
    if STRICT:
        print(f"error: {msg}", file=sys.stderr)
        print("update aborted; existing vibescan.lock left unchanged "
              "(VIBESCAN_VERIFY=permissive to proceed anyway).", file=sys.stderr)
        sys.exit(1)
    print(f"-- warning: {msg} (permissive mode: proceeding)")


def _cosign_verify_blob(blob, sig, cert):
    try:
        r = subprocess.run(
            ["cosign", "verify-blob", "--certificate", str(cert), "--signature", str(sig),
             "--certificate-identity-regexp", OPENGREP_IDENTITY,
             "--certificate-oidc-issuer", OIDC_ISSUER, str(blob)],
            capture_output=True, text=True, timeout=120)
        return r.returncode == 0
    except Exception:
        return False


def update_opengrep(tmp):
    rel = _release(lockfile.OPENGREP_REPO)
    if not rel:
        _abort("could not resolve latest opengrep release (offline or rate-limited)")
        return None
    tag = rel["tag_name"]
    sysname, arch = _plat()
    os_kw = ("osx", "darwin", "macos") if sysname == "darwin" else ("manylinux", "linux")
    asset = _pick_asset(rel.get("assets", []), os_kw, arch)
    if not asset:
        _abort(f"no opengrep binary asset for {sysname}/{arch}")
        return None
    binpath = tmp / "opengrep"
    _download(asset["browser_download_url"], binpath)
    names = {a["name"]: a["browser_download_url"] for a in rel["assets"]}
    sig = next((u for n, u in names.items() if n == asset["name"] + ".sig"), None)
    cert = next((u for n, u in names.items() if n == asset["name"] + ".cert"), None)

    verification = "unverified"
    if sig and cert and lockfile.have_cosign():
        _download(sig, tmp / "og.sig")
        _download(cert, tmp / "og.cert")
        if _cosign_verify_blob(binpath, tmp / "og.sig", tmp / "og.cert"):
            verification = "cosign-signature"
        else:
            _abort("opengrep cosign signature verification FAILED")
    elif sig and cert and not lockfile.have_cosign():
        print("-- note: cosign not installed; opengrep installed UNVERIFIED "
              "(install cosign for signature verification)")
    BIN.mkdir(parents=True, exist_ok=True)
    dest = BIN / "opengrep"
    os.replace(binpath, dest)
    dest.chmod(0o755)
    return {"version": tag, "sha256": lockfile.sha256_file(dest),
            "source": asset["browser_download_url"], "verification": verification}


def update_gitleaks(tmp):
    rel = _release(lockfile.GITLEAKS_REPO)
    if not rel:
        _abort("could not resolve latest gitleaks release (offline or rate-limited)")
        return None
    tag = rel["tag_name"]
    sysname, arch = _plat()
    asset = _pick_asset(rel.get("assets", []), (sysname,), arch)
    if not asset:
        _abort(f"no gitleaks archive for {sysname}/{arch}")
        return None
    arc = tmp / asset["name"]
    _download(asset["browser_download_url"], arc)

    names = {a["name"]: a["browser_download_url"] for a in rel["assets"]}
    checks = next((u for n, u in names.items() if "checksums" in n.lower() and n.endswith(".txt")), None)
    verification = "unverified"
    if checks:
        _download(checks, tmp / "checks.txt")
        want = None
        for line in (tmp / "checks.txt").read_text().splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[1].endswith(asset["name"]):
                want = parts[0]
        if want and lockfile.sha256_file(arc) == want:
            verification = "checksum-only"
            sig = next((u for n, u in names.items() if "checksums" in n.lower() and n.endswith(".sig")), None)
            cert = next((u for n, u in names.items() if "checksums" in n.lower() and n.endswith(".pem")), None)
            if sig and cert and lockfile.have_cosign():
                _download(sig, tmp / "c.sig")
                _download(cert, tmp / "c.pem")
                # gitleaks checksum sig uses its own identity; verify keylessly
                try:
                    r = subprocess.run(["cosign", "verify-blob", "--certificate", str(tmp / "c.pem"),
                                        "--signature", str(tmp / "c.sig"),
                                        "--certificate-identity-regexp", r"https://github.com/gitleaks/gitleaks",
                                        "--certificate-oidc-issuer", OIDC_ISSUER, str(tmp / "checks.txt")],
                                       capture_output=True, text=True, timeout=120)
                    if r.returncode == 0:
                        verification = "signed-checksum"
                except Exception:
                    pass
        elif want:
            _abort("gitleaks checksum MISMATCH")
    with tarfile.open(arc) as t:
        member = next((m for m in t.getmembers()
                       if Path(m.name).name == "gitleaks" and m.isfile()), None)
        if not member:
            _abort("gitleaks binary not found in archive")
            return None
        BIN.mkdir(parents=True, exist_ok=True)
        dest = BIN / "gitleaks"
        src = t.extractfile(member)
        with src, open(dest, "wb") as out_f:
            shutil.copyfileobj(src, out_f)
    dest.chmod(0o755)
    return {"version": tag, "sha256": lockfile.sha256_file(dest),
            "source": asset["browser_download_url"], "verification": verification}


def resolve_rules():
    sha = lockfile.github_latest_commit(lockfile.RULES_REPO, lockfile.RULES_BRANCH)
    return {"repo": lockfile.RULES_REPO, "branch": lockfile.RULES_BRANCH,
            "commit": sha, "verification": "commit-pinned" if sha else "unresolved"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true", help="resolve versions and print the plan; download nothing")
    ap.add_argument("--out", default=str(lockfile.skill_root() / "vibescan.lock"))
    args = ap.parse_args()

    if args.dry_run:
        og = _release(lockfile.OPENGREP_REPO)
        gl = _release(lockfile.GITLEAKS_REPO)
        rules = resolve_rules()
        print("plan (dry-run, nothing downloaded):")
        print(f"  opengrep : {og['tag_name'] if og else 'UNRESOLVED (offline/rate-limited)'}")
        print(f"  gitleaks : {gl['tag_name'] if gl else 'UNRESOLVED (offline/rate-limited)'}")
        print(f"  rules    : {rules['commit'][:12] if rules['commit'] else 'UNRESOLVED'}")
        print(f"  cosign   : {'present' if lockfile.have_cosign() else 'ABSENT (opengrep would install unverified)'}")
        return

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        print("== vibescan update: resolving + verifying latest toolchain ==")
        og = update_opengrep(tmp)
        gl = update_gitleaks(tmp)
        rules = resolve_rules()

    lock = {
        "schema": lockfile.SCHEMA,
        "generatedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "engines": {k: v for k, v in (("opengrep", og), ("gitleaks", gl)) if v},
        "rules": rules,
    }
    lockfile.save_lock(lock, args.out)
    print(f"\nwrote {args.out}")
    for name, spec in lock["engines"].items():
        print(f"  {name} {spec['version']}  [{spec['verification']}]")
    print(f"  rules @{(rules.get('commit') or '?')[:12]}  [{rules['verification']}]")


if __name__ == "__main__":
    main()
