#!/usr/bin/env python3
"""VibeScan scan-status + toolchain + DAST matrix — hermetic by default.

Hermetic tier: FAKE engines, VIBESCAN_NO_INSTALL=1, VIBESCAN_NO_UPDATE_CHECK=1,
VIBESCAN_OFFLINE=1 (all outbound network hard-disabled in the scanner), isolated
HOME/VIBESCAN_HOME, explicit VIBESCAN_LOCK, and VIBESCAN_RULES_DIR pointed at a dummy so
the mirror is never cloned. DAST cases use an in-process localhost server (not external
network). Each scan runs in its own process group and is killed (group-wide) on timeout,
so a stuck child can't stall the suite. Temp dirs are cleaned after each case.

  python3 tests/e2e_test.py          # hermetic tier (offline, deterministic)
  python3 tests/e2e_test.py --live   # also run live-engine + live-update cases
"""
import hashlib
import http.server
import json
import os
import shutil
import signal
import socket
import socketserver
import stat
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCAN = ROOT / "scripts" / "scan.py"
HERMETIC_TIMEOUT = 30
CASE_TIMEOUT = 60
_TMP = []
_CASE = ""

BENIGN = "x = 1\nprint(x)\n"
VULN = "import subprocess, pickle\n\ndef h(c, d):\n    subprocess.run(c, shell=True)\n    return pickle.loads(d)\n"
FAKE_GITLEAKS = ('#!/usr/bin/env bash\nprev=""\nfor a in "$@"; do\n'
                 '  if [ "$prev" = "--report-path" ]; then printf "[]" > "$a"; fi\n'
                 '  prev="$a"\ndone\nexit 0\n')
FAKE_OPENGREP = ('#!/usr/bin/env bash\nprev=""\nfor a in "$@"; do\n'
                 '  if [ "$prev" = "--output" ]; then printf \'{"runs":[]}\' > "$a"; fi\n'
                 '  prev="$a"\ndone\nexit 0\n')
GL_SHA = hashlib.sha256(FAKE_GITLEAKS.encode()).hexdigest()
OG_SHA = hashlib.sha256(FAKE_OPENGREP.encode()).hexdigest()


def _mkdtemp():
    d = tempfile.mkdtemp(); _TMP.append(d); return Path(d)


def _exec(path, content):
    path.write_text(content)
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


def hermetic_env(with_engines=True, lock=None, semgrep_only=False, rules_dir=None):
    home = _mkdtemp()
    vh = home / ".vibescan"
    bindir = vh / "bin"
    bindir.mkdir(parents=True, exist_ok=True)
    if with_engines:
        _exec(bindir / "gitleaks", FAKE_GITLEAKS)
        _exec(bindir / ("semgrep" if semgrep_only else "opengrep"), FAKE_OPENGREP)
    if rules_dir is None:
        rules_dir = home / "rules"
        (rules_dir / "python").mkdir(parents=True, exist_ok=True)
    env = dict(HOME=str(home), VIBESCAN_HOME=str(vh), VIBESCAN_NO_INSTALL="1",
               VIBESCAN_NO_UPDATE_CHECK="1", VIBESCAN_OFFLINE="1", VIBESCAN_RULES_DIR=str(rules_dir),
               PATH="/usr/bin:/bin", VIBESCAN_LOCK=str(lock) if lock else str(home / "none.lock"))
    if os.environ.get("VIBESCAN_TIMING"):
        env["VIBESCAN_TIMING"] = "1"
    return env


def live_env():
    home = os.environ.get("HOME", "/root")
    vh = f"{home}/.vibescan"
    return dict(os.environ, HOME=home, VIBESCAN_HOME=vh, VIBESCAN_NO_UPDATE_CHECK="1",
                VIBESCAN_LOCK=str(_mkdtemp() / "none.lock"),
                PATH=f"{os.environ.get('PATH','')}:{vh}/bin:{home}/.local/bin")


def build(files):
    d = _mkdtemp()
    for name, content in files.items():
        p = d / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return d


def make_lock(path, gl_sha=GL_SHA, og_sha=OG_SHA, rules_commit="abc123def456"):
    lock = {"schema": 1, "generatedAt": "t",
            "engines": {"gitleaks": {"version": "v8.30.1", "sha256": gl_sha, "verification": "signed-checksum"},
                        "opengrep": {"version": "v1.25.0", "sha256": og_sha, "verification": "cosign-signature"}},
            "rules": {"repo": "opengrep/opengrep-rules", "commit": rules_commit, "verification": "commit-pinned"}}
    Path(path).write_text(json.dumps(lock))
    return path


def git_rules(commit_content="rules: []\n"):
    """Create a git rules mirror with one commit; return (dir, commit_sha)."""
    d = _mkdtemp(); rules = d / "rules"; (rules / "python").mkdir(parents=True)
    (rules / "python" / "r.yml").write_text(commit_content)
    genv = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t",
                GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@t")
    for c in (["git", "init", "-q", str(rules)], ["git", "-C", str(rules), "add", "-A"],
              ["git", "-C", str(rules), "commit", "-q", "-m", "x"]):
        subprocess.run(c, env=genv, capture_output=True)
    sha = subprocess.run(["git", "-C", str(rules), "rev-parse", "HEAD"],
                         capture_output=True, text=True).stdout.strip()
    return rules, sha, genv


def git_with_origin(url):
    rules, _sha, genv = git_rules()
    subprocess.run(["git", "-C", str(rules), "remote", "add", "origin", url], env=genv, capture_output=True)
    return rules


def load_scan():
    import importlib.util
    spec = importlib.util.spec_from_file_location("vibescan_scan", ROOT / "scripts" / "scan.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def with_rules_dir(rdir, fn):
    old = os.environ.get("VIBESCAN_RULES_DIR")
    os.environ["VIBESCAN_RULES_DIR"] = str(rdir)
    try:
        return fn()
    finally:
        if old is None:
            os.environ.pop("VIBESCAN_RULES_DIR", None)
        else:
            os.environ["VIBESCAN_RULES_DIR"] = old


def run(target, env, extra=None, timeout=HERMETIC_TIMEOUT, need_summary=True):
    label = _CASE or target.name
    p = subprocess.Popen([sys.executable, str(SCAN), str(target)] + (extra or []),
                         env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         text=True, start_new_session=True)
    try:
        _out, _err = p.communicate(timeout=timeout)
    except BaseException:
        # covers subprocess.TimeoutExpired AND an outer SIGALRM/KeyboardInterrupt: always
        # kill the whole process group so a hung scan can't orphan and stall the suite
        try:
            os.killpg(os.getpgid(p.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            _out, _err = p.communicate(timeout=5)
        except Exception:
            _out, _err = "", ""
        if os.environ.get("VIBESCAN_TIMING") and _err:   # surface stages up to the interruption
            sys.stderr.write(f"\n[timing {label} — interrupted]\n{_err}")
            sys.stderr.flush()
        raise
    if os.environ.get("VIBESCAN_TIMING") and _err:
        sys.stderr.write(f"\n[timing {label}]\n{_err}")
        sys.stderr.flush()
    fj = target / ".vibescan" / "findings.json"
    summary = json.loads(fj.read_text())["summary"] if fj.exists() else None
    if need_summary and summary is None:
        raise AssertionError(f"scan produced no findings.json; rc={p.returncode}; stderr={(_err or '')[:300]}")
    hp = target / ".vibescan" / "report.html"
    return p.returncode, summary, (hp.read_text() if hp.exists() else ""), _err


def start_server(handler_fn):
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self): handler_fn(self)
    srv = socketserver.TCPServer(("127.0.0.1", 0), H)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    return srv, srv.server_address[1], th


def stop_server(srv, th):
    try:
        srv.shutdown()
    finally:
        srv.server_close()
        th.join(timeout=2)


def titles_of(target):
    fj = target / ".vibescan" / "findings.json"
    if not fj.exists():
        return []
    return [f.get("title", "") for f in json.loads(fj.read_text()).get("findings", [])]


def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p




HERMETIC, LIVE = [], []


def case(bucket, name):
    def deco(fn):
        bucket.append((name, fn)); return fn
    return deco


@case(HERMETIC, "no deps + clean -> complete/clean")
def _():
    _, s, _h, _ = run(build({"a.py": BENIGN}), hermetic_env())
    assert s["scanStatus"] == "complete" and s["overallRisk"] == "clean" and s["riskScore"] == 0, s


@case(HERMETIC, "unsupported lockfile -> partial/unknown + note")
def _():
    _, s, h, _ = run(build({"poetry.lock": "x", "a.py": BENIGN}), hermetic_env())
    assert s["scanStatus"] == "partial" and any("poetry.lock" in c for c in s.get("coverageNotes", [])), s
    assert '#3fb950">0 findings' not in h


@case(HERMETIC, "unresolved specs -> partial + note")
def _():
    files = {"package.json": '{"dependencies":{"express":"latest","lodash":"^4.0"}}', "a.py": BENIGN}
    _, s, _h, _ = run(build(files), hermetic_env())
    assert s["scanStatus"] == "partial" and any("could not be resolved" in c for c in s.get("coverageNotes", [])), s


@case(HERMETIC, "compound/wildcard npm ranges -> not exact")
def _():
    _, s, _h, _ = run(build({"package.json": '{"dependencies":{"a":"1.2.x","b":"1.2.3 || 4.0.0"}}', "a.py": BENIGN}), hermetic_env())
    assert s["scanStatus"] == "partial" and "osv" in s["degradedScanners"], s


@case(HERMETIC, "malformed manifest -> partial, not clean")
def _():
    _, s, _h, _ = run(build({"package.json": '{"dependencies":{"lodash":"4.17.21",}}', "a.py": BENIGN}), hermetic_env())
    assert s["overallRisk"] != "clean" and any("could not be parsed" in c for c in s.get("coverageNotes", [])), s


@case(HERMETIC, "both engines down -> partial/unknown, no green pill")
def _():
    _, s, h, _ = run(build({"a.py": VULN}), hermetic_env(with_engines=False), extra=["--no-install"])
    assert s["overallRisk"] == "unknown" and s["riskScore"] is None and "ASSESSMENT INCOMPLETE" in h, s


@case(HERMETIC, "malformed manual finding -> no crash")
def _():
    t = build({"a.py": BENIGN})
    (t / ".vibescan").mkdir(parents=True, exist_ok=True)
    (t / ".vibescan" / "manual.json").write_text('{"findings":[{"severity":"BOGUS","category":"nonsense","title":"x","filePath":"a.py"}]}')
    _, s, _h, _ = run(t, hermetic_env())
    assert s["totalFindings"] >= 1, s


@case(HERMETIC, "no lockfile -> unpinned, stamped absent")
def _():
    _, s, _h, _ = run(build({"a.py": BENIGN}), hermetic_env())
    assert s.get("toolchain", {}).get("lockfile") == "absent", s.get("toolchain")


@case(HERMETIC, "matching lock -> engines verified")
def _():
    _, s, _h, _ = run(build({"a.py": BENIGN}), hermetic_env(lock=make_lock(_mkdtemp() / "l.lock")))
    tc = s["toolchain"]
    assert tc["engines"]["gitleaks"]["status"] == "verified" and tc["sast"]["status"] == "verified", tc


@case(HERMETIC, "tampered lock hash -> abort")
def _():
    rc, s, _h, _ = run(build({"a.py": BENIGN}), hermetic_env(lock=make_lock(_mkdtemp() / "l.lock", gl_sha="0" * 64)), need_summary=False)
    assert rc != 0 and s is None, f"rc={rc}"


@case(HERMETIC, "malformed lock -> abort")
def _():
    home = _mkdtemp(); (home / "l.lock").write_text("{ not json ]")
    rc, s, _h, _ = run(build({"a.py": BENIGN}), hermetic_env(lock=home / "l.lock"), need_summary=False)
    assert rc != 0 and s is None, f"rc={rc}"


@case(HERMETIC, "permissive -> tampered lock warns, still scans")
def _():
    env = hermetic_env(lock=make_lock(_mkdtemp() / "l.lock", gl_sha="0" * 64)); env["VIBESCAN_VERIFY"] = "permissive"
    rc, s, _h, _ = run(build({"a.py": BENIGN}), env)
    assert rc == 0 and s and s["scanStatus"] == "complete", (rc, s)


@case(HERMETIC, "REGRESSION: semgrep under opengrep lock -> abort")
def _():
    env = hermetic_env(lock=make_lock(_mkdtemp() / "l.lock"), semgrep_only=True)
    rc, s, _h, err = run(build({"a.py": BENIGN}), env, need_summary=False)
    assert rc != 0 and s is None, f"rc={rc} :: {err[:120]}"


@case(HERMETIC, "REGRESSION: --render preserves partial status")
def _():
    env = hermetic_env()
    t = build({"poetry.lock": "x", "a.py": BENIGN})
    _, s1, _h, _ = run(t, env)
    assert s1["scanStatus"] == "partial", s1
    (t / ".vibescan" / "manual.json").write_text('{"findings":[]}')
    _, s2, _h, _ = run(t, env, extra=["--render"])
    assert s2["scanStatus"] == "partial" and "osv" in s2["degradedScanners"], f"render reset: {s2}"


@case(HERMETIC, "REGRESSION: unreachable DAST -> degraded, not clean")
def _():
    port = free_port()
    rc, s, _h, _ = run(build({"a.py": BENIGN}), hermetic_env(),
                       extra=["--url", f"http://127.0.0.1:{port}", "--authorized"])
    assert s["scanStatus"] != "complete" or s["overallRisk"] != "clean", s
    assert "dast" in s["degradedScanners"] and any("could not reach" in c.lower() for c in s.get("coverageNotes", [])), s


@case(HERMETIC, "REGRESSION: rules commit mismatch -> abort")
def _():
    rules, _sha, _g = git_rules()
    env = hermetic_env(lock=make_lock(_mkdtemp() / "l.lock", rules_commit="deadbeef" * 5), rules_dir=rules)
    rc, s, _h, err = run(build({"a.py": BENIGN}), env, need_summary=False)
    assert rc != 0 and s is None, f"rc={rc} :: {err[:120]}"


@case(HERMETIC, "REGRESSION: rules commit matches but tree dirty -> abort")
def _():
    rules, sha, _g = git_rules()
    (rules / "python" / "r.yml").write_text("rules: [tampered]\n")   # modify after commit
    env = hermetic_env(lock=make_lock(_mkdtemp() / "l.lock", rules_commit=sha), rules_dir=rules)
    rc, s, _h, err = run(build({"a.py": BENIGN}), env, need_summary=False)
    assert rc != 0 and s is None, f"dirty tree not rejected: rc={rc} :: {err[:120]}"


@case(HERMETIC, "REGRESSION: DAST cookie substring can't fake a flag")
def _():
    def h(req):
        req.send_response(200)
        req.send_header("Set-Cookie", "insecuretoken=abc; HttpOnly")  # no Secure/SameSite
        req.send_header("Content-Type", "text/html"); req.end_headers()
        req.wfile.write(b"<html>x</html>")
    srv, port, th = start_server(h)
    t = build({"a.py": BENIGN})
    try:
        run(t, hermetic_env(), extra=["--url", f"http://127.0.0.1:{port}", "--authorized"])
    finally:
        stop_server(srv, th)
    titles = titles_of(t)
    assert any("insecuretoken" in c and "Secure" in c for c in titles), titles


@case(HERMETIC, "REGRESSION: DAST equal-length distinct file not suppressed")
def _():
    def h(req):
        body = b"A" * 512 if req.path.startswith("/.env") else b"B" * 512  # same length, diff content
        req.send_response(200); req.send_header("Content-Type", "text/plain"); req.end_headers()
        req.wfile.write(body)
    srv, port, th = start_server(h)
    t = build({"a.py": BENIGN})
    try:
        run(t, hermetic_env(), extra=["--url", f"http://127.0.0.1:{port}", "--authorized"])
    finally:
        stop_server(srv, th)
    titles = titles_of(t)
    assert any("/.env" in c for c in titles), f"equal-length real file suppressed: {titles}"


@case(HERMETIC, "REGRESSION: DAST SPA (identical 200) -> no exposed-path findings")
def _():
    def h(req):
        req.send_response(200); req.send_header("Content-Type", "text/html"); req.end_headers()
        req.wfile.write(b"<html>same shell</html>")
    srv, port, th = start_server(h)
    t = build({"a.py": BENIGN})
    try:
        run(t, hermetic_env(), extra=["--url", f"http://127.0.0.1:{port}", "--authorized"])
    finally:
        stop_server(srv, th)
    assert not any("exposed sensitive path" in c for c in titles_of(t)), titles_of(t)


@case(HERMETIC, "REGRESSION: DAST reflects arbitrary Origin")
def _():
    def h(req):
        req.send_response(200)
        origin = req.headers.get("Origin")
        if origin:
            req.send_header("Access-Control-Allow-Origin", origin)
            req.send_header("Access-Control-Allow-Credentials", "true")
        req.send_header("Content-Type", "text/html"); req.end_headers()
        req.wfile.write(b"<html>x</html>")
    srv, port, th = start_server(h)
    t = build({"a.py": BENIGN})
    try:
        run(t, hermetic_env(), extra=["--url", f"http://127.0.0.1:{port}", "--authorized"])
    finally:
        stop_server(srv, th)
    assert any("reflects an arbitrary Origin" in c for c in titles_of(t)), titles_of(t)


@case(HERMETIC, "REGRESSION: origin canonicalization (unit)")
def _():
    cr = load_scan()._canonical_repo
    assert cr("https://github.com/opengrep/opengrep-rules.git") == "github.com/opengrep/opengrep-rules"
    assert cr("git@github.com:opengrep/opengrep-rules.git") == "github.com/opengrep/opengrep-rules"
    assert cr("https://evil.example/opengrep/opengrep-rules.git") == "evil.example/opengrep/opengrep-rules"
    assert cr("https://user:pass@github.com/opengrep/opengrep-rules.git") is None   # credentials
    assert cr("https://github.com/opengrep/opengrep-rules.git#frag") is None         # fragment
    assert cr("https://github.com/opengrep/opengrep-rules?x=1") is None              # query


@case(HERMETIC, "REGRESSION: origin host pinning accept/reject (unit)")
def _():
    scan = load_scan()

    def match(url):
        return with_rules_dir(git_with_origin(url), lambda: scan._rules_origin_matches("opengrep/opengrep-rules"))
    assert match("https://github.com/opengrep/opengrep-rules.git") is True
    assert match("git@github.com:opengrep/opengrep-rules.git") is True
    assert match("https://evil.example/opengrep/opengrep-rules.git") is False        # host pinned
    assert match("https://github.com/opengrep/opengrep-rules-malicious.git") is False
    assert match("https://github.com/opengrep/opengrep-rules-backup.git") is False
    # no origin configured -> None (unverifiable, not a match)
    rules, _sha, _g = git_rules()
    assert with_rules_dir(rules, lambda: scan._rules_origin_matches("opengrep/opengrep-rules")) is None


@case(HERMETIC, "REGRESSION: dirty tri-state (unit)")
def _():
    scan = load_scan()
    clean, _s, _g = git_rules()
    assert with_rules_dir(clean, lambda: scan._rules_dirty()) is False
    dirty, _s2, _g2 = git_rules()
    (dirty / "python" / "r.yml").write_text("changed\n")
    assert with_rules_dir(dirty, lambda: scan._rules_dirty()) is True
    nong = _mkdtemp(); (nong / "python").mkdir(parents=True)
    assert with_rules_dir(nong, lambda: scan._rules_dirty()) is None     # can't determine -> None


@case(HERMETIC, "REGRESSION: short pinned commit (1 & 11 char) -> abort")
def _():
    for bad in ("a", "0123456789a"):
        rules, _sha, _g = git_rules()
        env = hermetic_env(lock=make_lock(_mkdtemp() / "l.lock", rules_commit=bad), rules_dir=rules)
        rc, s, _h, err = run(build({"a.py": BENIGN}), env, need_summary=False)
        assert rc != 0 and s is None, f"short commit {bad!r} not rejected: rc={rc} :: {err[:120]}"


@case(HERMETIC, "REGRESSION: 12-char matching pinned commit -> accepted")
def _():
    rules, sha, _g = git_rules()
    env = hermetic_env(lock=make_lock(_mkdtemp() / "l.lock", rules_commit=sha[:12]), rules_dir=rules)
    rc, s, _h, err = run(build({"a.py": BENIGN}), env)
    assert rc == 0 and s and s["scanStatus"] == "complete", f"12-char match rejected: rc={rc} :: {err[:150]}"
    st = s["toolchain"]["rules"]["status"]
    assert st in ("verified", "content-verified-origin-unknown"), st


@case(HERMETIC, "REGRESSION: medium/low volume must not saturate to critical")
def _():
    t = build({"a.py": BENIGN})
    (t / ".vibescan").mkdir(parents=True, exist_ok=True)
    findings = ([{"severity": "medium", "category": "config_issue", "title": f"m{i}",
                  "filePath": "a.py", "confidence": "high"} for i in range(40)]
                + [{"severity": "low", "category": "config_issue", "title": f"l{i}",
                    "filePath": "a.py", "confidence": "high"} for i in range(45)])
    (t / ".vibescan" / "manual.json").write_text(json.dumps({"findings": findings}))
    _, s, _h, _ = run(t, hermetic_env())
    assert s["overallRisk"] == "medium", s["overallRisk"]          # worst severity present
    assert s["overallRisk"] not in ("critical", "high"), s


@case(HERMETIC, "REGRESSION: one critical -> critical band")
def _():
    t = build({"a.py": BENIGN})
    (t / ".vibescan").mkdir(parents=True, exist_ok=True)
    findings = ([{"severity": "critical", "category": "injection", "title": "c",
                  "filePath": "a.py", "confidence": "high"}]
                + [{"severity": "low", "category": "config_issue", "title": f"l{i}",
                    "filePath": "a.py", "confidence": "high"} for i in range(5)])
    (t / ".vibescan" / "manual.json").write_text(json.dumps({"findings": findings}))
    _, s, _h, _ = run(t, hermetic_env())
    assert s["overallRisk"] == "critical", s["overallRisk"]


@case(HERMETIC, "REGRESSION: Maven pom.xml -> partial + unsupported note")
def _():
    _, s, _h, _ = run(build({"pom.xml": "<project/>", "a.py": BENIGN}), hermetic_env())
    assert s["scanStatus"] == "partial", s["scanStatus"]
    assert any("pom.xml" in c for c in s.get("coverageNotes", [])), s.get("coverageNotes")


@case(LIVE, "vulnerable code, real engines -> complete + findings")
def _():
    _, s, _h, _ = run(build({"a.py": VULN}), live_env(), timeout=300)
    assert s["scanStatus"] == "complete" and s["totalFindings"] >= 2, s


@case(LIVE, "update --dry-run resolves versions")
def _():
    r = subprocess.run([sys.executable, str(ROOT / "scripts" / "update.py"), "--dry-run"],
                       capture_output=True, text=True, timeout=60)
    assert "opengrep :" in r.stdout and "gitleaks :" in r.stdout, r.stdout


def run_bucket(bucket, title):
    print(f"\n== {title} ==")
    failed = 0
    for name, fn in bucket:
        global _CASE
        _CASE = name
        mark = len(_TMP)
        t0 = time.monotonic()

        def _on_alarm(signum, frame):
            raise TimeoutError(f"case exceeded {CASE_TIMEOUT}s")
        old = signal.signal(signal.SIGALRM, _on_alarm)
        signal.alarm(CASE_TIMEOUT)
        try:
            fn()
            print(f"PASS  {name} ({time.monotonic()-t0:.2f}s)")
        except (TimeoutError, subprocess.TimeoutExpired) as e:
            print(f"TIMEOUT {name}  [{e}]")
            failed += 1
        except AssertionError as e:
            print(f"FAIL  {name}  [{e}]")
            failed += 1
        except Exception as e:
            print(f"ERROR {name}  [{type(e).__name__}: {e}]")
            failed += 1
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old)
            for d in _TMP[mark:]:                 # clean this case's temp dirs immediately
                shutil.rmtree(d, ignore_errors=True)
            del _TMP[mark:]
    return failed, len(bucket)


def main():
    try:
        failed, total = run_bucket(HERMETIC, "hermetic (default)")
        if "--live" in sys.argv:
            f2, t2 = run_bucket(LIVE, "live"); failed += f2; total += t2
        print(f"\n{total - failed}/{total} passed")
    finally:
        for d in _TMP:
            shutil.rmtree(d, ignore_errors=True)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
