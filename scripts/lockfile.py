#!/usr/bin/env python3
"""Lockfile + verification core for VibeScan's pinned-toolchain model.

A `vibescan.lock` records the exact engine versions, artifact hashes, verification
level achieved, and rules commit that a scan is allowed to use. Scans run against the
lock (reproducible, offline); `update` refreshes it (deliberate, verified). Nothing here
reaches the network unless a function explicitly does, and every network call degrades
quietly on error / rate-limit / offline rather than raising.
"""
import hashlib
import json
import os
import time
import urllib.request
from pathlib import Path

SCHEMA = 1
CHECK_TTL = int(os.environ.get("VIBESCAN_CHECK_INTERVAL", "86400"))  # daily by default
OPENGREP_REPO = "opengrep/opengrep"
GITLEAKS_REPO = "gitleaks/gitleaks"
RULES_REPO = "opengrep/opengrep-rules"
RULES_BRANCH = "main"


def skill_root():
    return Path(__file__).resolve().parent.parent


def home_dir():
    base = os.environ.get("VIBESCAN_HOME") or os.path.join(os.path.expanduser("~"), ".vibescan")
    return Path(base)


def lock_path():
    """Resolve the lockfile: explicit override, vendored repo root, then cache."""
    env = os.environ.get("VIBESCAN_LOCK")
    if env:
        return Path(env)
    root = skill_root() / "vibescan.lock"
    if root.exists():
        return root
    return home_dir() / "vibescan.lock"


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def load_lock(path=None):
    p = Path(path) if path else lock_path()
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text())
    except Exception:
        return "malformed"
    if not isinstance(data, dict) or data.get("schema") != SCHEMA:
        return "malformed"
    return data


def save_lock(data, path):
    Path(path).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def verify_hash(path, expected):
    """True iff the file at `path` matches the expected sha256. Missing file -> False."""
    try:
        return sha256_file(path) == expected
    except Exception:
        return False


def have_cosign():
    from shutil import which
    return which("cosign") is not None


# --- network (all failures degrade to None / quiet) --------------------------
def _get_json(url, timeout=10):
    if os.environ.get("VIBESCAN_OFFLINE"):
        return None
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json",
                                                    "User-Agent": "vibescan"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except Exception:
        return None


def github_latest_release(repo):
    data = _get_json(f"https://api.github.com/repos/{repo}/releases/latest")
    if isinstance(data, dict) and data.get("tag_name"):
        return data["tag_name"]
    return None


def github_latest_commit(repo, branch):
    data = _get_json(f"https://api.github.com/repos/{repo}/commits/{branch}")
    if isinstance(data, dict) and data.get("sha"):
        return data["sha"]
    return None


# --- cached staleness check --------------------------------------------------
def _cache_path():
    return home_dir() / "update-check.json"


def _read_cache():
    try:
        return json.loads(_cache_path().read_text())
    except Exception:
        return None


def _write_cache(payload):
    try:
        home_dir().mkdir(parents=True, exist_ok=True)
        _cache_path().write_text(json.dumps(payload))
    except Exception:
        pass


def check_staleness(lock, force=False):
    """Return {'checkedAt', 'online', 'components':[{name,pinned,latest,status}]}.

    Uses a daily cache so scans don't hammer the GitHub API (unauthenticated limit is
    60/hour). status is up-to-date | update-available | unknown. Never raises.
    """
    if not isinstance(lock, dict):
        return {"checkedAt": None, "online": False, "components": []}
    cached = _read_cache()
    if cached and not force and (time.time() - cached.get("checkedAt", 0) < CHECK_TTL):
        return cached

    eng = lock.get("engines", {})
    rules = lock.get("rules", {})
    comps, online = [], False

    def add(name, pinned, latest):
        nonlocal online
        if latest is None:
            comps.append({"name": name, "pinned": pinned, "latest": None, "status": "unknown"})
        else:
            online = True
            same = (pinned == latest) or (pinned or "").lstrip("v") == (latest or "").lstrip("v")
            comps.append({"name": name, "pinned": pinned, "latest": latest,
                          "status": "up-to-date" if same else "update-available"})

    add("opengrep", eng.get("opengrep", {}).get("version"), github_latest_release(OPENGREP_REPO))
    add("gitleaks", eng.get("gitleaks", {}).get("version"), github_latest_release(GITLEAKS_REPO))
    latest_commit = github_latest_commit(RULES_REPO, RULES_BRANCH)
    add("rules", (rules.get("commit") or "")[:12] or None,
        (latest_commit or "")[:12] or None)

    result = {"checkedAt": time.time(), "online": online, "components": comps}
    if online:
        _write_cache(result)
    return result


def stale_summary(staleness):
    """One-line notice for scan-time, or '' if nothing actionable/known."""
    ups = [c["name"] for c in staleness.get("components", []) if c["status"] == "update-available"]
    if ups:
        return f"update available for: {', '.join(ups)} — run `vibescan update`"
    return ""
