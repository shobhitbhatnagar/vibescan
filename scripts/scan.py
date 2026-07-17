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
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.parse
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
sys.path.insert(0, str(HERE))
import lockfile  # noqa: E402


def _stage(label, since):
    """Print per-stage wall time to stderr when VIBESCAN_TIMING is set (diagnostics)."""
    if os.environ.get("VIBESCAN_TIMING"):
        print(f"-- timing {label}: {time.monotonic() - since:.2f}s", file=sys.stderr)
    return time.monotonic()
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
        final = bin_dir() / binname
        with opener(archive) as ar:
            names = ar.getnames() if kind == "tar" else ar.namelist()
            member = next((n for n in names if Path(n).name == binname), None)
            if member is None:
                raise RuntimeError("binary not found in archive")
            # Don't extract by path (a malicious archive could use ../). Stream the one
            # regular-file member straight to the destination we choose.
            if kind == "tar":
                info = ar.getmember(member)
                if not info.isfile():
                    raise RuntimeError("archive member is not a regular file")
                src = ar.extractfile(info)
            else:
                src = ar.open(member)
            with src, open(final, "wb") as out_f:
                shutil.copyfileobj(src, out_f)
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


def _rules_head():
    """Actual commit of the resolved opengrep-rules mirror, or None if absent / not a checkout."""
    m = rules_mirror()
    if not m or not (m / ".git").exists():
        return None
    try:
        r = subprocess.run(["git", "-C", str(m), "rev-parse", "HEAD"], capture_output=True, text=True)
        return r.stdout.strip() if r.returncode == 0 else None
    except Exception:
        return None


def _rules_dirty():
    """Tri-state working-tree state: True=dirty, False=clean, None=could-not-determine.
    Security checks fail closed, so None must be treated as unverified by the caller."""
    m = rules_mirror()
    if not m or not (m / ".git").exists():
        return None
    try:
        r = subprocess.run(["git", "-C", str(m), "status", "--porcelain"], capture_output=True, text=True)
        if r.returncode != 0:
            return None
        return bool(r.stdout.strip())
    except Exception:
        return None


def _canonical_repo(url):
    """Normalize a git remote URL to 'host/owner/repo' (lowercased, no .git), or None.
    Rejects embedded credentials, query strings, and fragments (not a clean repo identity),
    and requires an exact owner/repo path. Fails closed on anything unexpected."""
    u = url.strip()
    m = re.match(r"^git@([^:/]+):(.+)$", u)                # scp-like: git@host:owner/repo
    if m:
        host, path = m.group(1), m.group(2)
    else:
        parts = urllib.parse.urlsplit(u)
        if parts.scheme not in ("http", "https", "ssh", "git"):
            return None
        if parts.username or parts.password or parts.query or parts.fragment:
            return None
        host, path = parts.hostname or "", parts.path
    path = re.sub(r"\.git$", "", path).strip("/")
    if not host or path.count("/") != 1:                  # exactly owner/repo
        return None
    return f"{host.lower()}/{path.lower()}"


def _rules_origin_matches(repo):
    """True if the mirror's origin canonically equals host/owner/repo pinned in the lock,
    False if it differs, None if no origin is configured or it can't be read. The host is
    pinned: a lock 'owner/repo' defaults to github.com/owner/repo, so an attacker host with
    the same path is rejected."""
    m = rules_mirror()
    if not repo or not m or not (m / ".git").exists():
        return None
    try:
        r = subprocess.run(["git", "-C", str(m), "remote", "get-url", "origin"],
                           capture_output=True, text=True)
        if r.returncode != 0 or not r.stdout.strip():
            return None
        actual = _canonical_repo(r.stdout.strip())
        if not actual:
            return False
        expected = repo.strip("/").lower()
        if expected.count("/") == 1:                      # bare owner/repo -> default host
            expected = "github.com/" + expected
        return actual == expected
    except Exception:
        return None


def pin_rules_to_lock(lock):
    """If the lock pins a rules commit and a git mirror exists, check it out to that exact
    commit so scans use the locked rules rather than whatever the default branch is now."""
    if not isinstance(lock, dict) or os.environ.get("VIBESCAN_OFFLINE"):
        return
    commit = (lock.get("rules") or {}).get("commit")
    m = rules_mirror()
    if not commit or not m or not (m / ".git").exists():
        return
    cur = subprocess.run(["git", "-C", str(m), "rev-parse", "HEAD"], capture_output=True, text=True)
    if cur.returncode == 0 and cur.stdout.strip() == commit:
        return
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
    fr = subprocess.run(["git", "-C", str(m), "fetch", "--depth", "1", "origin", commit],
                        env=env, stdout=DEVNULL, stderr=DEVNULL)
    if fr.returncode != 0:
        print(f"-- warning: could not fetch locked rules commit {commit[:12]} from origin")
    subprocess.run(["git", "-C", str(m), "checkout", "--detach", commit],
                   env=env, stdout=DEVNULL, stderr=DEVNULL)


def verify_toolchain(raw):
    """Verify installed engines + rules against vibescan.lock and write a toolchain stamp.
    Returns True if the scan must abort. Strict by default; VIBESCAN_VERIFY=permissive
    downgrades hard failures to warnings. Verifies the SAST engine actually selected (so a
    locked opengrep can't be silently replaced by semgrep) and the actual rules commit."""
    from shutil import which
    mode = os.environ.get("VIBESCAN_VERIFY", "strict")
    strict = mode != "permissive"
    lock = lockfile.load_lock()
    stamp = {"lockfile": "absent", "verifyMode": mode, "engines": {}, "sast": {}, "rules": {}}
    fatal = False

    def fail(msg):
        nonlocal fatal
        if strict:
            print(f"error: {msg} (set VIBESCAN_VERIFY=permissive to override)", file=sys.stderr)
            fatal = True
        else:
            print(f"-- warning: {msg}")

    if lock == "malformed":
        stamp["lockfile"] = "malformed"
        fail("vibescan.lock is malformed")
        (raw / "toolchain.json").write_text(json.dumps(stamp))
        return fatal
    if not lock:
        (raw / "toolchain.json").write_text(json.dumps(stamp))
        return False

    stamp["lockfile"] = "present"
    eng = lock.get("engines", {})

    # secrets engine
    gspec = eng.get("gitleaks") or {}
    gpath = which("gitleaks")
    grec = {"pinned": gspec.get("version"), "verification": gspec.get("verification", "unverified")}
    if gspec and gpath:
        grec["status"] = "verified" if lockfile.verify_hash(gpath, gspec.get("sha256", "")) else "hash-mismatch"
        if grec["status"] == "hash-mismatch":
            fail("gitleaks on PATH does not match the hash pinned in vibescan.lock")
    elif gspec:
        grec["status"] = "pinned-but-missing"
    else:
        grec["status"] = "present-unpinned" if gpath else "absent"
    stamp["engines"]["gitleaks"] = grec

    # SAST engine — verify the engine actually selected, never a silent substitute
    ospec = eng.get("opengrep") or {}
    og, sg = which("opengrep"), which("semgrep")
    selected = "opengrep" if og else ("semgrep" if sg else None)
    srec = {"pinned": ospec.get("version"), "verification": ospec.get("verification", "unverified"),
            "selectedEngine": selected, "path": og or sg}
    if selected == "opengrep" and ospec:
        srec["status"] = "verified" if lockfile.verify_hash(og, ospec.get("sha256", "")) else "hash-mismatch"
        if srec["status"] == "hash-mismatch":
            fail("opengrep on PATH does not match the hash pinned in vibescan.lock")
    elif selected == "semgrep" and ospec:
        srec["status"] = "substituted-unpinned"
        fail("lock pins opengrep but only semgrep is present — refusing to silently run an unpinned SAST engine")
    elif ospec and not selected:
        srec["status"] = "pinned-but-missing"
    else:
        srec["status"] = "present-unpinned" if selected else "absent"
    stamp["sast"] = srec

    # rules commit — verify the ACTUAL mirror checkout: right commit, clean working tree,
    # and (when an origin is set) the expected repository. A matching commit is not enough,
    # since files can be modified after checkout.
    rlock = lock.get("rules") or {}
    pinned = rlock.get("commit")
    actual = _rules_head()
    rrec = {"pinnedCommit": (pinned or "")[:12] or None, "actualCommit": (actual or "")[:12] or None,
            "verification": rlock.get("verification", "commit-pinned")}
    # a lock commit must be a full 40-hex sha (or an explicit >=12 abbreviation); short values
    # like "a" must never be accepted as a prefix match
    safe_pin = bool(pinned) and bool(re.fullmatch(r"[0-9a-fA-F]{12,40}", pinned))
    if pinned and not safe_pin:
        rrec["status"] = "invalid-pinned-commit"
        rrec["verification"] = "unverified"
        fail("vibescan.lock rules commit is not a valid 12-40 char git sha")
    elif safe_pin and actual:
        matches = actual == pinned or (len(pinned) >= 12 and actual.startswith(pinned))
        if not matches:
            rrec["status"] = "commit-mismatch"
            rrec["verification"] = "unverified"
            fail(f"rules mirror is at {actual[:12]} but the lock requires {pinned[:12]}")
        else:
            dirty = _rules_dirty()                       # True / False / None
            origin_ok = _rules_origin_matches(rlock.get("repo"))
            rrec["workingTreeClean"] = None if dirty is None else (not dirty)
            rrec["originVerified"] = origin_ok
            if dirty is None:
                rrec["status"] = "working-tree-unverifiable"
                rrec["verification"] = "unverified"
                fail("could not determine rules working-tree state (git status failed)")
            elif dirty:
                rrec["status"] = "working-tree-modified"
                rrec["verification"] = "unverified"
                fail("rules mirror has uncommitted/untracked changes — content no longer matches the pinned commit")
            elif origin_ok is False:
                rrec["status"] = "origin-mismatch"
                rrec["verification"] = "unverified"
                fail("rules mirror origin does not match the repository pinned in vibescan.lock")
            elif origin_ok is None:
                # commit + clean tree confirmed, but origin can't be verified (local checkout)
                rrec["status"] = "content-verified-origin-unknown"
                rrec["verification"] = "commit-and-clean-tree"
            else:
                rrec["status"] = "verified"
    elif safe_pin and not actual:
        rrec["status"] = "mirror-absent"
        rrec["verification"] = "unverified"
    else:
        rrec["status"] = "unpinned"
    stamp["rules"] = rrec

    (raw / "toolchain.json").write_text(json.dumps(stamp))
    return fatal


def ensure_engines(no_install):
    add_paths()
    missing = []
    if not have("gitleaks"):
        missing.append("gitleaks(secrets)")
    if not have_sast():
        missing.append("semgrep(SAST)")
    if missing:
        joined = " ".join(missing)
        if no_install:
            print(f"== VibeScan: missing engines [ {joined} ] — skipping auto-install (--no-install).")
            print("   Those scans will be marked degraded. See references/engines.md to install manually. ==")
        else:
            print(f"== VibeScan: missing engines [ {joined} ]. Auto-installing into {home()}")
            print("   (OSV dependency scanning needs no install). Re-run with --no-install to skip. ==")
            if not have("gitleaks"):
                install_gitleaks()
            if not have_sast():
                install_semgrep()
            add_paths()
    sync_rules_mirror(no_install)


# --- target resolution ----------------------------------------------------
def resolve_target(arg):
    # Local directory — scan in place.
    if not re.match(r"^(https?://|git@|ssh://|file://)", arg) and not arg.endswith(".git"):
        return Path(arg)
    # Free skill: only public HTTPS git URLs on known hosts. Reject ssh/file and
    # never prompt for credentials, so a private target fails cleanly instead of
    # silently authenticating or hanging.
    if re.match(r"^(git@|ssh://|file://)", arg):
        print("error: only public https:// git URLs are supported (no ssh/file targets).", file=sys.stderr)
        sys.exit(1)
    if not arg.startswith("https://"):
        print("error: only https:// git URLs are supported.", file=sys.stderr)
        sys.exit(1)
    host = (urlparse(arg).hostname or "").lower()
    if not any(host == h or host.endswith("." + h) for h in GIT_HOSTS):
        print(f"error: '{host}' is not an allowlisted public git host.", file=sys.stderr)
        sys.exit(1)

    canon = arg.rstrip("/")
    if canon.endswith(".git"):
        canon = canon[:-4]
    parts = [seg for seg in urlparse(canon).path.strip("/").split("/") if seg]
    owner = parts[-2] if len(parts) >= 2 else "_"
    repo = parts[-1] if parts else "repo"
    safe = lambda s: re.sub(r"[^A-Za-z0-9._-]", "_", s)
    # Cache path keyed on host/owner/repo + a hash of the full URL, so
    # company-a/backend and company-b/backend never collide.
    digest = hashlib.sha256(canon.encode()).hexdigest()[:8]
    dest = home() / "repos" / safe(host) / safe(owner) / f"{safe(repo)}-{digest}"
    dest.parent.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_CONFIG_NOSYSTEM="1",
               GIT_ASKPASS="", SSH_ASKPASS="")

    if (dest / ".git").exists():
        print(f"== updating existing clone at {dest} ==")
        fr = subprocess.run(["git", "-c", "credential.helper=", "-C", str(dest),
                             "fetch", "--depth", "1", "origin"],
                            env=env, stdout=DEVNULL, stderr=DEVNULL)
        rr = subprocess.run(["git", "-C", str(dest), "reset", "--hard", "FETCH_HEAD"],
                            env=env, stdout=DEVNULL, stderr=DEVNULL)
        if fr.returncode != 0 or rr.returncode != 0:
            print("error: failed to update existing clone; refusing to scan stale source.", file=sys.stderr)
            sys.exit(1)
    else:
        print(f"== cloning {arg} -> {dest} ==")
        if dest.exists():
            shutil.rmtree(dest, ignore_errors=True)
        if subprocess.run(["git", "-c", "credential.helper=", "clone", "--depth", "1", arg, str(dest)],
                          env=env).returncode != 0:
            print("clone failed (repo private, nonexistent, or unreachable)", file=sys.stderr)
            sys.exit(1)

    cp = subprocess.run(["git", "-C", str(dest), "rev-parse", "HEAD"],
                        env=env, capture_output=True, text=True)
    print(f"== scanned commit: {cp.stdout.strip() or 'unknown'} ==")
    return dest


# --- engines --------------------------------------------------------------
def _engine_note(raw, msg):
    p = raw / "engine_notes.json"
    try:
        notes = json.loads(p.read_text()) if p.exists() else []
    except Exception:
        notes = []
    notes.append(msg)
    p.write_text(json.dumps(notes))


def run_gitleaks(target, raw):
    report = raw / "gitleaks.json"
    if not have("gitleaks"):
        report.write_text("[]")
        _engine_note(raw, "Secrets scan did not run: gitleaks engine unavailable.")
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
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        report.write_text("[]")
        _engine_note(raw, "Secrets scan timed out (300s) — likely resource contention, not necessarily an engine fault; rerun in isolation.")
        return False
    except Exception:
        report.write_text("[]")
        _engine_note(raw, "Secrets scan errored before completing.")
        return False
    # --exit-code 0 forces 0 whether or not leaks are found, so nonzero means the
    # engine actually failed. Also require the report to be present and valid JSON.
    if r.returncode != 0:
        report.write_text("[]")
        return False
    try:
        json.load(open(report))
    except Exception:
        report.write_text("[]")
        return False
    return True


# --- opengrep-rules auto-select (offline, no registry) ---
# Detect the languages present in the target and pass only the matching opengrep-rules
# language folders to --config, alongside the always-on local pack.
EXT_TO_RULEDIR = {
    ".php": "php",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".py": "python", ".go": "go", ".java": "java", ".rb": "ruby", ".cs": "csharp",
    ".c": "c", ".h": "c", ".cpp": "c", ".cc": "c", ".cxx": "c", ".hpp": "c",
    ".rs": "rust", ".kt": "kotlin", ".kts": "kotlin", ".scala": "scala", ".sc": "scala",
    ".swift": "swift", ".ex": "elixir", ".exs": "elixir",
    ".clj": "clojure", ".cljs": "clojure", ".cljc": "clojure",
    ".sol": "solidity", ".sh": "bash", ".bash": "bash", ".tf": "terraform",
    ".html": "html", ".htm": "html", ".json": "json", ".yaml": "yaml", ".yml": "yaml",
    ".ml": "ocaml", ".mli": "ocaml", ".cls": "apex", ".trigger": "apex",
}
_WALK_SKIP = {".git", "node_modules", "vendor", "dist", "build", ".venv", "venv",
              "__pycache__", ".vibescan", ".next", "target"}
RULES_MIRROR_REPO = "https://github.com/opengrep/opengrep-rules.git"


def rules_mirror():
    """Locate an opengrep-rules mirror. Order: env override, vendored, ~/.vibescan
    cache. Returns None if absent (SAST then runs the local pack only)."""
    cands = []
    env = os.environ.get("VIBESCAN_RULES_DIR")
    if env:
        cands.append(Path(env))
    cands.append(HERE.parent / "assets" / "opengrep-rules")
    cands.append(home() / "opengrep-rules")
    for c in cands:
        if c.is_dir() and any(c.glob("*/")):
            return c
    return None


def sync_rules_mirror(no_install):
    """Fetch the opengrep-rules mirror into the cache on first run so SAST has
    multi-language coverage. No-op if a mirror already resolves. Degrades to the
    local pack (JS/TS/Python) on --no-install, missing git, or network failure."""
    if rules_mirror():
        return
    dest = home() / "opengrep-rules"
    if no_install or os.environ.get("VIBESCAN_OFFLINE"):
        print("== VibeScan: SAST rule mirror not found — skipping fetch (--no-install/offline).")
        print("   SAST will run the local pack only (JS/TS/Python). ==")
        return
    if not have("git"):
        print("   ✗ git unavailable — SAST runs the local pack only (JS/TS/Python)")
        return
    print(f"   · fetching opengrep-rules (multi-language SAST) -> {dest}")
    print("     LGPL-2.1 + Commons Clause; see THIRD_PARTY_LICENSES.md")
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
    try:
        r = subprocess.run(["git", "clone", "--depth", "1", RULES_MIRROR_REPO, str(dest)],
                           stdout=DEVNULL, stderr=DEVNULL, env=env)
        if r.returncode == 0 and (dest / "php").is_dir():
            print("   ✓ multi-language SAST rules ready")
        else:
            print("   ✗ rule fetch failed — SAST runs the local pack only")
    except Exception:
        print("   ✗ rule fetch failed — SAST runs the local pack only")


def select_rule_configs(target):
    """(config_paths, chosen_langs): always the local pack, plus one opengrep-rules
    language folder per language detected in the target."""
    configs = [str(RULES)]
    mirror = rules_mirror()
    if not mirror:
        return configs, []
    langs = set()
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in _WALK_SKIP]
        for fn in files:
            if fn == "Dockerfile" or fn.startswith("Dockerfile."):
                langs.add("dockerfile")
                continue
            d = EXT_TO_RULEDIR.get(os.path.splitext(fn)[1].lower())
            if d:
                langs.add(d)
    chosen = []
    for lang in sorted(langs):
        p = mirror / lang
        if p.is_dir():
            configs.append(str(p))
            chosen.append(lang)
    return configs, chosen


def run_sast(target, raw):
    out = raw / "sast.sarif"
    engine = "opengrep" if have("opengrep") else ("semgrep" if have("semgrep") else None)
    if not engine:
        out.write_text('{"runs":[]}')
        _engine_note(raw, "SAST did not run: no opengrep/semgrep engine available.")
        return False
    configs, chosen = select_rule_configs(target)
    label = f"{engine}; langs: {', '.join(chosen)}" if chosen else f"{engine}; local pack only"
    print(f"-> sast ({label})")
    cmd = [engine]
    for c in configs:
        cmd += ["--config", c]
    cmd += ["--sarif", "--output", str(out),
            "--quiet", "--disable-version-check", str(target)]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    except subprocess.TimeoutExpired:
        out.write_text('{"runs":[]}')
        _engine_note(raw, "SAST timed out (600s) — likely resource contention on a large target; rerun in isolation before trusting coverage.")
        return False
    except Exception:
        out.write_text('{"runs":[]}')
        _engine_note(raw, "SAST engine errored before completing.")
        return False
    # semgrep/opengrep: 0 = ran (with or without findings), 1 = findings under some
    # configs; anything higher is a real error. Require parseable SARIF with a runs key.
    if r.returncode not in (0, 1):
        out.write_text('{"runs":[]}')
        return False
    try:
        data = json.load(open(out))
        if "runs" not in data:
            raise ValueError("missing runs key")
    except Exception:
        out.write_text('{"runs":[]}')
        return False
    return True


def run_osv(target, raw):
    print("-> dependencies (osv.dev)")
    out = raw / "osv.json"
    try:
        r = subprocess.run([sys.executable, str(HERE / "osv_deps.py"), str(target)],
                           capture_output=True, text=True, timeout=180)
        payload = r.stdout if r.stdout.strip() else '{"status":"failed","findings":[]}'
        out.write_text(payload)
        data = json.loads(payload)
        # Only success and not_applicable count as covered. unsupported (manifests found
        # but not parseable), partial, and failed all mean dependency coverage is
        # incomplete, so they degrade the scan rather than passing as clean.
        return data.get("status") in ("success", "not_applicable")
    except Exception:
        out.write_text('{"status":"failed","findings":[]}')
        return False


# --- main -----------------------------------------------------------------
def run_web(url, out_path):
    """Run passive DAST and write out_path. Return True only if the target was reachable
    and the scan explicitly reported success. Unreachable/failed -> degraded."""
    try:
        r = subprocess.run([sys.executable, str(HERE / "web_scan.py"), url, "--authorized"],
                           capture_output=True, text=True, timeout=120)
    except Exception:
        out_path.write_text('{"status":"failed","findings":[]}')
        return False
    payload = r.stdout if r.stdout.strip() else '{"status":"failed","findings":[]}'
    out_path.write_text(payload)
    if r.returncode != 0:
        return False
    try:
        data = json.loads(payload)
    except Exception:
        return False
    return data.get("status") == "success" and isinstance(data.get("findings"), list)


def main():
    ap = argparse.ArgumentParser(description="VibeScan cross-platform scanner")
    ap.add_argument("target", help="local directory or public git repo URL")
    ap.add_argument("--no-install", action="store_true", help="don't auto-install missing engines")
    ap.add_argument("--no-update-check", action="store_true",
                    help="skip the cached engine/rules staleness check")
    ap.add_argument("--render", action="store_true",
                    help="re-render report from existing scan + .vibescan/manual.json (no engine run)")
    ap.add_argument("--url", help="also run passive DAST against this deployed URL (requires --authorized)")
    ap.add_argument("--authorized", action="store_true",
                    help="assert you own / are explicitly authorized to test --url")
    args = ap.parse_args()
    no_install = args.no_install or os.environ.get("VIBESCAN_NO_INSTALL") == "1"

    # --render: fold manual findings into the report without re-scanning. Must preserve
    # the original coverage state (degraded/applicable), or an honest partial report could
    # be silently promoted to complete/clean just by re-rendering.
    if args.render:
        target = Path(args.target)
        raw = target / ".vibescan" / "raw"
        if not raw.exists():
            print("error: no prior scan to render — run a full scan first", file=sys.stderr)
            sys.exit(1)
        applicable, degraded = "gitleaks,opengrep,osv", ""
        try:
            exe = json.loads((raw / "execution.json").read_text())
            applicable = ",".join(exe.get("applicable") or ["gitleaks", "opengrep", "osv"])
            degraded = ",".join(exe.get("degraded") or [])
        except Exception:
            try:  # fall back to the prior report's own record of what ran
                prev = json.loads((target / ".vibescan" / "findings.json").read_text())["summary"]
                degraded = ",".join(prev.get("degradedScanners") or [])
                applicable = ",".join((prev.get("enginesRan") or []) + (prev.get("degradedScanners") or []))
            except Exception:
                pass
        nr = subprocess.run([sys.executable, str(HERE / "normalize.py"),
                             str(target), str(raw), degraded, "", applicable])
        if nr.returncode != 0:
            print("error: normalization failed — report not updated.", file=sys.stderr)
            sys.exit(1)
        rr = subprocess.run([sys.executable, str(HERE / "render_html.py"), str(target)], stdout=DEVNULL)
        if rr.returncode != 0:
            print("-- warning: HTML report generation failed (findings.json and report.md still written)")
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
        web_degraded = "" if run_web(url, raw / "web.json") else "dast"
        # static engines don't apply to a bare URL — supply empty inputs so normalize is happy
        (raw / "gitleaks.json").write_text("[]")
        (raw / "sast.sarif").write_text('{"runs":[]}')
        (raw / "osv.json").write_text('{"status":"not_applicable","findings":[]}')
        (raw / "execution.json").write_text(json.dumps(
            {"applicable": ["dast"], "degraded": [web_degraded] if web_degraded else []}))
        nr = subprocess.run([sys.executable, str(HERE / "normalize.py"),
                             str(target), str(raw), web_degraded, baseline, "dast"])
        if nr.returncode != 0:
            print("error: normalization failed.", file=sys.stderr)
            sys.exit(1)
        rr = subprocess.run([sys.executable, str(HERE / "render_html.py"), str(target)], stdout=DEVNULL)
        if rr.returncode != 0:
            print("-- warning: HTML report generation failed (findings.json and report.md still written)")
        print(f"\nfindings: {out / 'findings.json'}")
        print(f"report:   {out / 'report.md'}")
        print(f"html:     {out / 'report.html'}")
        return

    target = resolve_target(args.target)
    if not target.is_dir():
        print(f"error: target directory not found: {target}", file=sys.stderr)
        sys.exit(1)

    print(f"== VibeScan: scanning {target} ==")
    _ts = time.monotonic()
    ensure_engines(no_install)
    _ts = _stage("engine-setup", _ts)

    out = target / ".vibescan"
    raw = out / "raw"
    raw.mkdir(parents=True, exist_ok=True)
    (raw / "engine_notes.json").unlink(missing_ok=True)
    pin_rules_to_lock(lockfile.load_lock())
    if verify_toolchain(raw):
        sys.exit(1)
    _ts = _stage("toolchain-verify", _ts)
    if not args.no_update_check and not os.environ.get("VIBESCAN_NO_UPDATE_CHECK"):
        note = lockfile.stale_summary(lockfile.check_staleness(lockfile.load_lock()))
        if note:
            print(f"== {note} ==")
        _ts = _stage("update-check", _ts)

    baseline = ""
    if (out / "findings.json").exists():
        shutil.copy(out / "findings.json", out / "previous.json")
        baseline = str(out / "previous.json")
        print("-- prior scan found; will report changes since last run")

    degraded = []
    if not run_gitleaks(target, raw):
        print("-- secrets scan did not complete (engine missing or failed)")
        degraded.append("gitleaks")
    _ts = _stage("gitleaks", _ts)
    if not run_sast(target, raw):
        print("-- SAST did not complete (engine missing or failed)")
        degraded.append("opengrep")
    _ts = _stage("sast", _ts)
    if not run_osv(target, raw):
        print("-- dependency coverage incomplete (unsupported manifests or OSV unavailable)")
        degraded.append("osv")
    _ts = _stage("osv", _ts)

    applicable = ["gitleaks", "opengrep", "osv"]
    # Optional passive DAST against a deployed URL — gated on explicit authorization.
    if args.url:
        applicable.append("dast")
        web_out = raw / "web.json"
        if not args.authorized:
            print(f"== VibeScan DAST: refusing to probe {args.url} without --authorized.")
            print("   DAST sends real requests to a LIVE app — only test targets you own or are")
            print("   authorized to test. Re-run with --authorized to confirm. Skipping DAST. ==")
            web_out.write_text('{"findings":[]}')
            degraded.append("dast")
        else:
            print(f"-> web (passive DAST) {args.url}")
            if not run_web(args.url, web_out):
                degraded.append("dast")

    if args.url:
        _ts = _stage("dast", _ts)

    (raw / "execution.json").write_text(json.dumps({"applicable": applicable, "degraded": degraded}))
    nr = subprocess.run([sys.executable, str(HERE / "normalize.py"),
                    str(target), str(raw), ",".join(degraded), baseline, ",".join(applicable)])
    if nr.returncode != 0:
        print("error: normalization failed — no report written for this run.", file=sys.stderr)
        sys.exit(1)
    _ts = _stage("normalize", _ts)
    r = subprocess.run([sys.executable, str(HERE / "render_html.py"), str(target)],
                       stdout=DEVNULL)
    if r.returncode != 0:
        print("-- warning: HTML report generation failed (findings.json and report.md still written)")
    _ts = _stage("render-html", _ts)

    print(f"\nfindings: {out / 'findings.json'}")
    print(f"report:   {out / 'report.md'}")
    print(f"html:     {out / 'report.html'}")
    _stage("finalize", _ts)


if __name__ == "__main__":
    main()
