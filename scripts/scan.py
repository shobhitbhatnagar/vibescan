#!/usr/bin/env python3
"""VibeScan — cross-platform scan orchestrator (macOS, Linux, Windows).

Runs gitleaks (secrets), opengrep/semgrep (SAST), and OSV.dev (deps) over a local
directory or a public git repo URL, then normalizes + renders the report. Pure Python
+ stdlib for everything except the engines themselves, so it runs anywhere Python does.

Usage:
    python scan.py <dir-or-repo-url> [--no-install]

Missing engines are auto-installed (with a notice) unless --no-install / VIBESCAN_NO_INSTALL=1.
"""
import argparse
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path
from urllib.parse import urlparse

GIT_HOSTS = ("github.com", "gitlab.com", "bitbucket.org", "dev.azure.com",
             "git.sr.ht", "codeberg.org", "gitea.com")


def is_web_url(s):
    return bool(re.match(r"^https?://", s or ""))


def is_git_url(s):
    if not s:
        return False
    if s.endswith(".git") or re.match(r"^(git@|ssh://)", s):
        return True
    if is_web_url(s):
        host = (urlparse(s).hostname or "").lower()
        return any(host == h or host.endswith("." + h) for h in GIT_HOSTS)
    return False


def is_loopback(url):
    host = (urlparse(url).hostname or "").lower()
    return host in ("localhost", "127.0.0.1", "0.0.0.0", "::1") or host.startswith("127.")


def dast_target_dir(url):
    p = urlparse(url)
    name = re.sub(r"[^A-Za-z0-9._-]", "_", (p.hostname or "site") + (f"_{p.port}" if p.port else ""))
    d = home() / "dast" / name
    d.mkdir(parents=True, exist_ok=True)
    return d

HERE = Path(__file__).resolve().parent
RULES = HERE.parent / "assets" / "rules"
GL_VERSION = "8.28.0"
IS_WINDOWS = platform.system().lower() == "windows"
DEVNULL = subprocess.DEVNULL


def home():
    return Path(os.environ.get("VIBESCAN_HOME", Path.home() / ".vibescan"))


def bin_dir():
    d = home() / "bin"
    d.mkdir(parents=True, exist_ok=True)
    return d


def add_paths():
    extra = os.pathsep.join([str(bin_dir()), str(Path.home() / ".local" / "bin")])
    os.environ["PATH"] = extra + os.pathsep + os.environ.get("PATH", "")


def have(name):
    return shutil.which(name) is not None


def have_sast():
    return have("opengrep") or have("semgrep")


# --- engine installation --------------------------------------------------
def _gitleaks_asset():
    machine = platform.machine().lower()
    arch = "arm64" if machine in ("arm64", "aarch64") else "x64"
    if IS_WINDOWS:
        return f"gitleaks_{GL_VERSION}_windows_{arch}.zip", "zip", "gitleaks.exe"
    if platform.system().lower() == "darwin":
        return f"gitleaks_{GL_VERSION}_darwin_{arch}.tar.gz", "tar", "gitleaks"
    return f"gitleaks_{GL_VERSION}_linux_{arch}.tar.gz", "tar", "gitleaks"


def install_gitleaks():
    asset, kind, binname = _gitleaks_asset()
    url = f"https://github.com/gitleaks/gitleaks/releases/download/v{GL_VERSION}/{asset}"
    print(f"   · installing gitleaks (secret scanner) -> {bin_dir()}")
    try:
        tmp = Path(tempfile.mkdtemp())
        archive = tmp / asset
        urllib.request.urlretrieve(url, archive)
        opener = tarfile.open if kind == "tar" else zipfile.ZipFile
        with opener(archive) as ar:
            names = ar.getnames() if kind == "tar" else ar.namelist()
            member = next((n for n in names if Path(n).name == binname), None)
            if member is None:
                raise RuntimeError("binary not found in archive")
            ar.extract(member, bin_dir())
        out = bin_dir() / Path(member).name
        final = bin_dir() / binname
        if out != final:
            out.replace(final)
        if not IS_WINDOWS:
            final.chmod(0o755)
        print("   ✓ gitleaks ready")
        return True
    except Exception as e:
        print(f"   ✗ gitleaks install failed ({e}) — secrets scan will be skipped (degraded)")
        return False


def install_semgrep():
    if IS_WINDOWS:
        print("   ✗ SAST (semgrep/opengrep) has no native Windows build — run VibeScan under WSL")
        print("     for SAST coverage. Secrets (gitleaks) and dependency scanning still work here.")
        return False
    print("   · installing semgrep (SAST engine) via pip — this can take a minute")
    for extra in (["--user"], ["--user", "--break-system-packages"]):
        try:
            r = subprocess.run(
                [sys.executable, "-m", "pip", "install", "-q", "semgrep", *extra],
                stdout=DEVNULL, stderr=DEVNULL,
            )
            if r.returncode == 0:
                print("   ✓ semgrep ready")
                return True
        except Exception:
            pass
    print("   ✗ semgrep install failed — SAST scan will be skipped (degraded)")
    return False


def ensure_engines(no_install):
    add_paths()
    missing = []
    if not have("gitleaks"):
        missing.append("gitleaks(secrets)")
    if not have_sast():
        missing.append("semgrep(SAST)")
    if not missing:
        return
    joined = " ".join(missing)
    if no_install:
        print(f"== VibeScan: missing engines [ {joined} ] — skipping auto-install (--no-install).")
        print("   Those scans will be marked degraded. See references/engines.md to install manually. ==")
        return
    print(f"== VibeScan: missing engines [ {joined} ]. Auto-installing into {home()}")
    print("   (OSV dependency scanning needs no install). Re-run with --no-install to skip. ==")
    if not have("gitleaks"):
        install_gitleaks()
    if not have_sast():
        install_semgrep()
    add_paths()


# --- target resolution ----------------------------------------------------
def resolve_target(arg):
    is_url = bool(re.match(r"^(https?://|git@|ssh://|file://)", arg)) or arg.endswith(".git")
    if not is_url:
        return Path(arg)
    name = re.sub(r"[^A-Za-z0-9._-]", "_", Path(arg.rstrip("/").replace(".git", "")).name)
    dest = home() / "repos" / name
    (home() / "repos").mkdir(parents=True, exist_ok=True)
    if (dest / ".git").exists():
        print(f"== updating existing clone at {dest} (scan history preserved) ==")
        subprocess.run(["git", "-C", str(dest), "fetch", "--depth", "1", "origin"], stdout=DEVNULL, stderr=DEVNULL)
        subprocess.run(["git", "-C", str(dest), "reset", "--hard", "origin/HEAD"], stdout=DEVNULL, stderr=DEVNULL)
    else:
        print(f"== cloning {arg} -> {dest} ==")
        if dest.exists():
            shutil.rmtree(dest, ignore_errors=True)
        if subprocess.run(["git", "clone", "--depth", "1", arg, str(dest)]).returncode != 0:
            print("clone failed")
            sys.exit(1)
    return dest


# --- engines --------------------------------------------------------------
def run_gitleaks(target, raw):
    report = raw / "gitleaks.json"
    if not have("gitleaks"):
        report.write_text("[]")
        return False
    print("-> secrets (gitleaks)")
    cmd = ["gitleaks", "detect", "--no-git", "--source", str(target),
           "--report-format", "json", "--report-path", str(report),
           "--redact", "--exit-code", "0"]
    cfg = Path(target) / ".gitleaks.toml"
    if cfg.exists():
        cmd += ["--config", str(cfg)]
        print("   using repo .gitleaks.toml allowlist")
    try:
        subprocess.run(cmd, stdout=DEVNULL, stderr=DEVNULL)
    except Exception:
        pass
    if not report.exists():
        report.write_text("[]")
    return True


def run_sast(target, raw):
    out = raw / "sast.sarif"
    engine = "opengrep" if have("opengrep") else ("semgrep" if have("semgrep") else None)
    if not engine:
        out.write_text('{"runs":[]}')
        return False
    print(f"-> sast ({engine})")
    cmd = [engine, "--config", str(RULES), "--sarif", "--output", str(out),
           "--quiet", "--disable-version-check", str(target)]
    try:
        subprocess.run(cmd, stdout=DEVNULL, stderr=DEVNULL)
    except Exception:
        pass
    if not out.exists():
        out.write_text('{"runs":[]}')
    return True


def run_osv(target, raw):
    print("-> dependencies (osv.dev)")
    out = raw / "osv.json"
    try:
        r = subprocess.run([sys.executable, str(HERE / "osv_deps.py"), str(target)],
                           capture_output=True, text=True, timeout=180)
        out.write_text(r.stdout if r.stdout.strip() else '{"findings":[]}')
    except Exception:
        out.write_text('{"findings":[]}')


# --- main -----------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="VibeScan cross-platform scanner")
    ap.add_argument("target", help="local directory or public git repo URL")
    ap.add_argument("--no-install", action="store_true", help="don't auto-install missing engines")
    ap.add_argument("--render", action="store_true",
                    help="re-render report from existing scan + .vibescan/manual.json (no engine run)")
    ap.add_argument("--url", help="also run passive DAST against this deployed URL (requires --authorized)")
    ap.add_argument("--authorized", action="store_true",
                    help="assert you own / are explicitly authorized to test --url")
    args = ap.parse_args()
    no_install = args.no_install or os.environ.get("VIBESCAN_NO_INSTALL") == "1"

    # --render: fold manual findings into the report without re-scanning.
    if args.render:
        target = Path(args.target)
        raw = target / ".vibescan" / "raw"
        if not raw.exists():
            print("error: no prior scan to render — run a full scan first", file=sys.stderr)
            sys.exit(1)
        subprocess.run([sys.executable, str(HERE / "normalize.py"), str(target), str(raw), "", ""])
        subprocess.run([sys.executable, str(HERE / "render_html.py"), str(target)], stdout=DEVNULL)
        out = target / ".vibescan"
        print(f"re-rendered with manual findings:\n  {out / 'report.html'}")
        return

    # Positional target that is a running-app URL (not a git repo) -> DAST scan.
    if is_web_url(args.target) and not is_git_url(args.target):
        url = args.target
        authorized = args.authorized or is_loopback(url)
        print(f"== VibeScan: dynamic (DAST) scan of {url} ==")
        if not authorized:
            print(f"== refusing to probe {url} without --authorized. DAST sends real requests to a")
            print("   live app — only test targets you own or are authorized to test. Re-run with")
            print("   --authorized to confirm. ==")
            sys.exit(2)
        if is_loopback(url):
            print("   (loopback address — treated as your own local app)")
        target = dast_target_dir(url)
        out = target / ".vibescan"
        raw = out / "raw"
        raw.mkdir(parents=True, exist_ok=True)
        baseline = ""
        if (out / "findings.json").exists():
            shutil.copy(out / "findings.json", out / "previous.json")
            baseline = str(out / "previous.json")
            print("-- prior scan found; will report changes since last run")
        print(f"-> web (passive DAST) {url}")
        try:
            r = subprocess.run([sys.executable, str(HERE / "web_scan.py"), url, "--authorized"],
                               capture_output=True, text=True, timeout=120)
            (raw / "web.json").write_text(r.stdout if r.stdout.strip() else '{"findings":[]}')
        except Exception:
            (raw / "web.json").write_text('{"findings":[]}')
        # static engines don't apply to a bare URL — supply empty inputs so normalize is happy
        (raw / "gitleaks.json").write_text("[]")
        (raw / "sast.sarif").write_text('{"runs":[]}')
        (raw / "osv.json").write_text('{"findings":[]}')
        subprocess.run([sys.executable, str(HERE / "normalize.py"), str(target), str(raw), "", baseline])
        subprocess.run([sys.executable, str(HERE / "render_html.py"), str(target)], stdout=DEVNULL)
        print(f"\nfindings: {out / 'findings.json'}")
        print(f"report:   {out / 'report.md'}")
        print(f"html:     {out / 'report.html'}")
        return

    target = resolve_target(args.target)
    if not target.is_dir():
        print(f"error: target directory not found: {target}", file=sys.stderr)
        sys.exit(1)

    print(f"== VibeScan: scanning {target} ==")
    ensure_engines(no_install)

    out = target / ".vibescan"
    raw = out / "raw"
    raw.mkdir(parents=True, exist_ok=True)

    baseline = ""
    if (out / "findings.json").exists():
        shutil.copy(out / "findings.json", out / "previous.json")
        baseline = str(out / "previous.json")
        print("-- prior scan found; will report changes since last run")

    degraded = []
    if not run_gitleaks(target, raw):
        print("-- gitleaks unavailable, skipping secrets scan")
        degraded.append("gitleaks")
    if not run_sast(target, raw):
        print("-- no SAST engine available, skipping")
        degraded.append("opengrep")
    run_osv(target, raw)

    # Optional passive DAST against a deployed URL — gated on explicit authorization.
    if args.url:
        web_out = raw / "web.json"
        if not args.authorized:
            print(f"== VibeScan DAST: refusing to probe {args.url} without --authorized.")
            print("   DAST sends real requests to a LIVE app — only test targets you own or are")
            print("   authorized to test. Re-run with --authorized to confirm. Skipping DAST. ==")
            web_out.write_text('{"findings":[]}')
            degraded.append("dast")
        else:
            print(f"-> web (passive DAST) {args.url}")
            try:
                r = subprocess.run([sys.executable, str(HERE / "web_scan.py"), args.url, "--authorized"],
                                   capture_output=True, text=True, timeout=120)
                web_out.write_text(r.stdout if r.stdout.strip() else '{"findings":[]}')
            except Exception:
                web_out.write_text('{"findings":[]}')
                degraded.append("dast")

    subprocess.run([sys.executable, str(HERE / "normalize.py"),
                    str(target), str(raw), ",".join(degraded), baseline])
    r = subprocess.run([sys.executable, str(HERE / "render_html.py"), str(target)],
                       stdout=DEVNULL)
    if r.returncode != 0:
        print("-- warning: HTML report generation failed (findings.json and report.md still written)")

    print(f"\nfindings: {out / 'findings.json'}")
    print(f"report:   {out / 'report.md'}")
    print(f"html:     {out / 'report.html'}")


if __name__ == "__main__":
    main()
