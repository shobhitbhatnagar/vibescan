#!/usr/bin/env python3
"""VibeScan reproducible validation bundle.

Automates the manual validation plan into a repeatable evidence artifact: clones each
target repo (recording the exact commit SHA), runs a real scan with per-stage timing,
captures raw findings.json / timing / logs, checks for leaked engine processes (filtering
this driver's own matches), and writes a manifest linking every recorded conclusion to its
underlying scan output. Also records environment and engine versions.

  python3 tests/validate.py --local     # local edge cases only (no network) — fast
  python3 tests/validate.py --min       # minimum set: a few key repos + URL/local cases
  python3 tests/validate.py             # full plan (long: clones large repos, real engines)

Output: validation-bundle/<UTC-timestamp>/ with manifest.json, summary.md, env.txt, and a
per-target directory holding findings.json, timing.log, and scan.log.

Authorization: only the intentionally-vulnerable/demo targets below, or systems you own.
"""
import argparse
import datetime
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCAN = ROOT / "scripts" / "scan.py"
SCAN_TIMEOUT = int(os.environ.get("VIBESCAN_VALIDATE_TIMEOUT", "1200"))
MANIFEST_SCHEMA = 1


def _sha256(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def vibescan_version():
    vf = ROOT / "VERSION"
    return vf.read_text().strip() if vf.exists() else "unknown"


def vibescan_git_commit():
    try:
        r = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"],
                           capture_output=True, text=True, timeout=15)
        return r.stdout.strip() if r.returncode == 0 else "unknown"
    except Exception:
        return "unknown"

# Intentionally-vulnerable / demo / mature-comparison targets from the manual plan.
REPOS = [
    ("juice-shop", "https://github.com/juice-shop/juice-shop.git", "vuln", True),
    ("DVWA", "https://github.com/digininja/DVWA.git", "vuln", True),
    ("WebGoat", "https://github.com/WebGoat/WebGoat.git", "vuln-java-maven", True),
    ("VAmPI", "https://github.com/erev0s/VAmPI.git", "vuln-python", False),
    ("BenchmarkJava", "https://github.com/OWASP-Benchmark/BenchmarkJava.git", "timing", False),
    ("flask", "https://github.com/pallets/flask.git", "mature", False),
    ("requests", "https://github.com/psf/requests.git", "mature", True),
    ("express", "https://github.com/expressjs/express.git", "mature", False),
]
URLS = [
    ("connection-failure", "http://127.0.0.1:65534/", True),
]


def run_cmd(cmd, timeout, env=None, cwd=None):
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         text=True, start_new_session=True, env=env, cwd=cwd)
    try:
        out, _ = p.communicate(timeout=timeout)
        return p.returncode, out, False
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(p.pid), 9)
        except ProcessLookupError:
            pass
        out, _ = p.communicate()
        return None, (out or ""), True


def leaked_processes(exclude_pid):
    """pgrep for engine/scanner processes, filtering this driver and its own command line."""
    try:
        r = subprocess.run(["pgrep", "-af", "scan.py|opengrep|semgrep|gitleaks|osv"],
                           capture_output=True, text=True)
    except Exception:
        return []
    out = []
    for line in r.stdout.splitlines():
        pid = line.split(" ", 1)[0]
        if pid == str(exclude_pid) or pid == str(os.getpid()):
            continue
        if "validate.py" in line or "pgrep" in line:
            continue
        out.append(line)
    return out


def summarize(findings_path):
    try:
        s = json.loads(Path(findings_path).read_text())["summary"]
    except Exception:
        return {}
    return {
        "scanStatus": s.get("scanStatus"),
        "overallRisk": s.get("overallRisk"),
        "riskScore": s.get("riskScore"),
        "totalFindings": s.get("totalFindings"),
        "bySeverity": s.get("bySeverity"),
        "enginesRan": s.get("enginesRan"),
        "degradedScanners": s.get("degradedScanners"),
        "coverageNotes": s.get("coverageNotes", []),
    }


def scan_target(target_arg, name, bundle, clone_dir=None):
    tdir = bundle / name
    tdir.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, VIBESCAN_TIMING="1")
    t0 = time.monotonic()
    rc, out, timed_out = run_cmd([sys.executable, str(SCAN), target_arg], SCAN_TIMEOUT, env=env)
    elapsed = round(time.monotonic() - t0, 1)
    (tdir / "scan.log").write_text(out or "")
    (tdir / "timing.log").write_text("\n".join(l for l in (out or "").splitlines() if "timing" in l))
    # locate findings.json (repo scans write into <target>/.vibescan)
    summ = {}
    src = None
    if clone_dir:
        src = Path(clone_dir) / ".vibescan" / "findings.json"
    else:
        # URL scans write into a cache dir printed in the log
        for line in (out or "").splitlines():
            if line.strip().startswith("findings:"):
                src = Path(line.split("findings:", 1)[1].strip())
    if src and src.exists():
        shutil.copy(src, tdir / "findings.json")
        summ = summarize(src)
    leaked = leaked_processes(os.getpid())
    exit_reason = "timeout" if timed_out else ("completed" if rc == 0 else "error")
    arts = {
        "scanLog": {"path": f"{name}/scan.log", "sha256": _sha256(tdir / "scan.log")},
        "timingLog": {"path": f"{name}/timing.log", "sha256": _sha256(tdir / "timing.log")},
        "findings": ({"path": f"{name}/findings.json", "sha256": _sha256(tdir / "findings.json")}
                     if summ else None),
    }
    return {
        "name": name, "target": target_arg, "exit": rc, "exitReason": exit_reason,
        "timedOut": timed_out, "elapsedSec": elapsed,
        "leakedProcesses": leaked, "reportPresent": bool(summ), **summ, "artifacts": arts,
    }


def local_cases(bundle, work):
    cases = []
    # malformed manifest
    d = work / "bad-json"; d.mkdir(parents=True)
    (d / "package.json").write_text('{"dependencies": invalid }\n')
    cases.append(("local-malformed-manifest", str(d), d))
    # unpinned (range) dependency
    d = work / "no-lock"; d.mkdir(parents=True)
    (d / "package.json").write_text('{"name":"no-lock","dependencies":{"lodash":"^4.17.0"}}\n')
    cases.append(("local-no-lockfile", str(d), d))
    # embedded test secret (FAKE values chosen to trip detection; AKIA...EXAMPLE is
    # allowlisted by gitleaks as the documented dummy, so it would read clean)
    d = work / "secret"; d.mkdir(parents=True)
    (d / "app.py").write_text(
        'GITHUB_TOKEN = "ghp_0123456789abcdefABCDEF0123456789abcd"  # fake, detection test\n'
        'generic_key = "a6e7700158396a0781723c7b4418c0efacbbac4d0d4ec73b492e14e7c0b4c871"\n')
    cases.append(("local-embedded-secret", str(d), d))
    # command injection
    d = work / "cmd"; d.mkdir(parents=True)
    (d / "app.py").write_text('import os\nfrom flask import Flask, request\napp = Flask(__name__)\n'
                              '@app.route("/")\ndef run():\n    return os.popen(request.args.get("cmd","")).read()\n')
    cases.append(("local-command-injection", str(d), d))
    # unsupported ecosystem (Maven)
    d = work / "maven"; d.mkdir(parents=True)
    (d / "pom.xml").write_text("<project/>\n")
    (d / "App.java").write_text("class App {}\n")
    cases.append(("local-maven-unsupported", str(d), d))
    results = []
    for name, arg, cd in cases:
        print(f"-> {name}")
        results.append(scan_target(arg, name, bundle, clone_dir=cd))
    return results


def clone(url, dest, pinned=None):
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
    cmd = ["git", "clone", "--depth", "1"]
    if pinned:
        cmd += ["--no-single-branch"]
    r = subprocess.run(cmd + [url, str(dest)], capture_output=True, text=True, env=env, timeout=600)
    if r.returncode != 0:
        return None
    if pinned:
        subprocess.run(["git", "-C", str(dest), "fetch", "--depth", "1", "origin", pinned],
                       env=env, capture_output=True, timeout=300)
        subprocess.run(["git", "-C", str(dest), "checkout", "--detach", pinned],
                       env=env, capture_output=True)   # falls back to HEAD if unavailable
    sha = subprocess.run(["git", "-C", str(dest), "rev-parse", "HEAD"],
                         capture_output=True, text=True).stdout.strip()
    return sha


def engine_versions():
    v = {}
    for e, arg in (("gitleaks", ["version"]), ("opengrep", ["--version"]), ("semgrep", ["--version"])):
        if shutil.which(e):
            try:
                v[e] = subprocess.run([e] + arg, capture_output=True, text=True, timeout=30).stdout.strip()[:60]
            except Exception:
                v[e] = "error"
    return v


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--local", action="store_true", help="local edge cases only (no network)")
    ap.add_argument("--min", action="store_true", help="minimum set (key repos + local/url cases)")
    ap.add_argument("--write-lock", action="store_true",
                    help="record resolved commit SHAs to tests/repos.lock for deterministic re-runs")
    args = ap.parse_args()

    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    bundle = ROOT / "validation-bundle" / stamp
    bundle.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp())

    lock_path = ROOT / "tests" / "repos.lock"
    lock = {}
    if lock_path.exists() and not args.write_lock:
        try:
            lock = json.loads(lock_path.read_text())
        except Exception:
            lock = {}

    env_info = {
        "utc": stamp, "os": platform.platform(), "python": platform.python_version(),
        "cpuCount": os.cpu_count(),
        "vibescanVersion": vibescan_version(),
        "vibescanGitCommit": vibescan_git_commit(),
        "engines": engine_versions(),
        "scanTimeoutSec": SCAN_TIMEOUT,
        "reposPinned": bool(lock) and not args.write_lock,
    }
    (bundle / "env.txt").write_text(json.dumps(env_info, indent=2))

    results, repo_shas = [], {}
    if not args.local:
        repos = [r for r in REPOS if (r[3] or not args.min)]
        for name, url, kind, in_min in repos:
            pinned = (lock.get(name) or {}).get("commit")
            print(f"== cloning {name}{' @ ' + pinned[:12] if pinned else ''} ==")
            dest = work / name
            sha = clone(url, dest, pinned=pinned)
            if not sha:
                results.append({"name": name, "target": name, "error": "clone failed (offline/rate-limited)"})
                continue
            repo_shas[name] = {"url": url, "commit": sha, "kind": kind, "pinned": bool(pinned)}
            print(f"-> scanning {name} @ {sha[:12]}")
            r = scan_target(str(dest), name, bundle, clone_dir=dest)
            r["commit"] = sha
            r["kind"] = kind
            results.append(r)
        for name, url, in_min in URLS:
            if args.min and not in_min:
                continue
            print(f"-> url {name}")
            results.append(scan_target(url, name, bundle))

    results += local_cases(bundle, work)

    if args.write_lock and repo_shas:
        lock_out = {n: {"url": v["url"], "commit": v["commit"]} for n, v in repo_shas.items()}
        lock_path.write_text(json.dumps(lock_out, indent=2) + "\n")
        print(f"wrote {lock_path} ({len(lock_out)} repos pinned)")

    manifest = {"schema": MANIFEST_SCHEMA, "environment": env_info,
                "repoCommits": repo_shas, "results": results}
    (bundle / "manifest.json").write_text(json.dumps(manifest, indent=2))

    # human-readable summary table
    lines = [f"# VibeScan validation bundle — {stamp}", "",
             f"OS: {env_info['os']} | Python {env_info['python']} | CPUs {env_info['cpuCount']}",
             f"Engines: {env_info['engines']}", "",
             "| Target | Commit | Exit | Status | Risk | Findings | Engines | Degraded | Elapsed | Leaked |",
             "|---|---|---|---|---|---|---|---|---|---|"]
    for r in results:
        if r.get("error"):
            lines.append(f"| {r['target']} | — | — | ERROR: {r['error']} | | | | | | |")
            continue
        lines.append("| {t} | {c} | {e} | {s} | {rk} | {n} | {en} | {dg} | {el}s | {lk} |".format(
            t=r.get("name", r["target"]), c=(r.get("commit", "")[:12] or "local"),
            e=("timeout" if r.get("timedOut") else r.get("exit")),
            s=r.get("scanStatus", "-"), rk=r.get("overallRisk", "-"),
            n=r.get("totalFindings", "-"),
            en=",".join(r.get("enginesRan", []) or []), dg=",".join(r.get("degradedScanners", []) or []),
            el=r.get("elapsedSec", "-"), lk=("NONE" if not r.get("leakedProcesses") else "LEAK")))
    (bundle / "summary.md").write_text("\n".join(lines) + "\n")

    shutil.rmtree(work, ignore_errors=True)
    print(f"\nbundle written: {bundle}")
    print(f"  manifest.json, summary.md, env.txt + per-target findings/timing/logs")


if __name__ == "__main__":
    main()
