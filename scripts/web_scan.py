#!/usr/bin/env python3
"""VibeScan passive DAST — inspect a LIVE web app over HTTP (non-destructive).

Checks security headers, TLS/HSTS, per-cookie flags, CORS via an Origin-reflection probe (not full preflight analysis), version disclosure, and a small
set of well-known exposed paths (.env, .git). GET/HEAD only — no fuzzing, no writes, no
destructive methods. Emits findings in VibeScan's schema to stdout as {"findings":[...]}.

AUTHORIZATION: DAST sends real requests to a running system. This tool refuses to run
unless --authorized is passed, which asserts you own or are explicitly authorized to test
the target. Never point it at a URL you don't control.

Usage: web_scan.py <url> --authorized
"""
import json
import hashlib
import socket
import ssl
import sys
import uuid
import urllib.error
import urllib.request
from datetime import datetime, timezone
from urllib.parse import urlparse

TIMEOUT = 8
UA = "VibeScan-DAST/1.0 (passive; authorized-use-only)"
EXPOSED_PATHS = [
    "/.env", "/.git/config", "/.git/HEAD", "/.aws/credentials",
    "/config.json", "/.DS_Store", "/server-status", "/actuator/env",
]


def _finding(category, severity, title, remediation, url, evidence="", confidence="high"):
    return {
        "category": category, "severity": severity, "title": title,
        "evidenceExcerpt": evidence[:200], "filePath": url, "lineStart": None,
        "lineEnd": None, "remediationText": remediation, "confidence": confidence,
        "scanner": "dast",
    }


def _get(url, method="GET", origin=None):
    hdrs = {"User-Agent": UA}
    if origin:
        hdrs["Origin"] = origin
    req = urllib.request.Request(url, method=method, headers=hdrs)
    ctx = ssl.create_default_context()
    try:
        resp = urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx)
        raw = resp.headers
        d = {k.lower(): v for k, v in raw.items()}
        d["_set_cookies"] = raw.get_all("Set-Cookie") or []
        d["_final_url"] = resp.geturl()
        return resp.status, d, resp
    except urllib.error.HTTPError as e:
        raw = e.headers
        d = {k.lower(): v for k, v in (raw or {}).items()}
        d["_set_cookies"] = (raw.get_all("Set-Cookie") if raw else []) or []
        d["_final_url"] = getattr(e, "url", url)
        return e.code, d, None
    except Exception:
        return None, {}, None


def check_headers_and_cookies(url, headers, findings):
    scheme = urlparse(url).scheme
    if scheme == "http":
        findings.append(_finding(
            "data_exposure", "high", "App served over plaintext HTTP",
            "Serve exclusively over HTTPS and redirect HTTP → HTTPS.", url))
    if scheme == "https" and "strict-transport-security" not in headers:
        findings.append(_finding(
            "config_issue", "medium", "Missing HSTS header",
            "Add Strict-Transport-Security with a long max-age and includeSubDomains.", url))
    if "content-security-policy" not in headers:
        findings.append(_finding(
            "config_issue", "medium", "Missing Content-Security-Policy",
            "Add a CSP to constrain script/style/connect sources and mitigate XSS.", url))
    if headers.get("x-content-type-options", "").lower() != "nosniff":
        findings.append(_finding(
            "config_issue", "low", "Missing X-Content-Type-Options: nosniff",
            "Set X-Content-Type-Options: nosniff to stop MIME sniffing.", url))
    if "x-frame-options" not in headers and "frame-ancestors" not in headers.get("content-security-policy", ""):
        findings.append(_finding(
            "config_issue", "low", "No clickjacking protection (X-Frame-Options / frame-ancestors)",
            "Set X-Frame-Options: DENY or a CSP frame-ancestors directive.", url))
    for h in ("server", "x-powered-by"):
        if headers.get(h):
            findings.append(_finding(
                "config_issue", "info", f"Version/tech disclosure via {h} header",
                f"Suppress or genericize the {h} header to reduce fingerprinting.",
                url, evidence=f"{h}: {headers[h]}"))
    # cookies — assess each Set-Cookie separately so one secure cookie can't mask another;
    # report the cookie NAME only, never its value
    for raw_cookie in headers.get("_set_cookies", []):
        parts = [p.strip() for p in raw_cookie.split(";")]
        name = parts[0].split("=", 1)[0].strip()
        # attribute NAMES only (not the cookie name/value), so "insecuretoken=..." can't
        # be misread as having a Secure attribute
        attrs = {p.split("=", 1)[0].strip().lower() for p in parts[1:]}
        if "secure" not in attrs:
            findings.append(_finding("auth_issue", "high", f"Cookie '{name}' missing Secure flag",
                "Set Secure so the cookie is only sent over HTTPS.", url, evidence=f"cookie: {name}"))
        if "httponly" not in attrs:
            findings.append(_finding("auth_issue", "medium", f"Cookie '{name}' missing HttpOnly flag",
                "Set HttpOnly so the cookie isn't readable by JavaScript (XSS theft).", url, evidence=f"cookie: {name}"))
        if "samesite" not in attrs:
            findings.append(_finding("config_issue", "low", f"Cookie '{name}' missing SameSite",
                "Set SameSite=Lax or Strict to reduce CSRF exposure.", url, evidence=f"cookie: {name}"))


def check_cors(url, findings):
    """Actively probe CORS with a controlled Origin, since many servers only emit CORS
    headers when an Origin is present. Passive, non-mutating GET."""
    probe = "https://vibescan.invalid"
    status, headers, _ = _get(url, origin=probe)
    if status is None:
        return
    acao = headers.get("access-control-allow-origin", "")
    acac = headers.get("access-control-allow-credentials", "").lower()
    if acao == probe:
        sev = "high" if acac == "true" else "medium"
        findings.append(_finding("config_issue", sev, "CORS reflects an arbitrary Origin",
            "Echo only allowlisted origins; do not reflect the request Origin."
            + (" Never reflect an origin together with Allow-Credentials: true." if acac == "true" else ""),
            url, evidence="reflected test origin" + (" + credentials" if acac == "true" else "")))
    elif acao == "*" and acac == "true":
        findings.append(_finding("config_issue", "high", "CORS allows any origin with credentials",
            "Never combine Access-Control-Allow-Origin: * with Allow-Credentials: true.",
            url, evidence="ACAO: * + ACAC: true"))
    elif acao == "*":
        findings.append(_finding("config_issue", "medium", "Wildcard CORS (Access-Control-Allow-Origin: *)",
            "Restrict CORS to an explicit origin allowlist.", url))


def check_tls(url, findings):
    p = urlparse(url)
    if p.scheme != "https":
        return
    host, port = p.hostname, p.port or 443
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert()
        after = cert.get("notAfter")
        if after:
            exp = datetime.strptime(after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days = (exp - datetime.now(timezone.utc)).days
            if days < 0:
                findings.append(_finding("config_issue", "high", "TLS certificate expired",
                                         "Renew the certificate immediately.", url, evidence=f"expired {abs(days)}d ago"))
            elif days < 14:
                findings.append(_finding("config_issue", "medium", "TLS certificate expiring soon",
                                         "Renew before expiry.", url, evidence=f"{days}d left"))
    except ssl.SSLCertVerificationError as e:
        findings.append(_finding("config_issue", "high", "TLS certificate fails validation",
                                 "Fix the certificate chain/hostname mismatch.", url, evidence=str(e)[:120]))
    except Exception:
        pass


def _probe(u):
    """(status, final_url, body_sha, length) for a GET, or None if unreachable."""
    status, headers, resp = _get(u)
    if status is None:
        return None
    body = b""
    try:
        body = resp.read(65536) if resp else b""
    except Exception:
        pass
    return status, headers.get("_final_url", u), hashlib.sha256(body).hexdigest(), len(body)


def check_exposed_paths(base, findings):
    p = urlparse(base)
    root = f"{p.scheme}://{p.netloc}"
    host = p.netloc
    # Baseline: a path that should NOT exist. SPAs and custom 404s often 200 the app shell
    # for everything, so anything that matches this fallback is not a real exposure.
    baseline = _probe(root + "/vibescan-not-found-" + uuid.uuid4().hex[:12])
    for path in EXPOSED_PATHS:
        probe = _probe(root + path)
        if not probe:
            continue
        status, final_url, bhash, length = probe
        if status != 200:
            continue
        fp = urlparse(final_url)
        # redirected elsewhere (login/home, or another host) -> not proof of exposure
        if fp.netloc != host or fp.path.rstrip("/") != path.rstrip("/"):
            continue
        # indistinguishable from the generic fallback -> not the real file. Match on body
        # hash only; equal length alone is NOT sufficient (a real file can share a length).
        if baseline and status == baseline[0] and bhash == baseline[2]:
            continue
        sev = "critical" if path in ("/.env", "/.git/config", "/.aws/credentials") else "high"
        findings.append(_finding(
            "data_exposure", sev,
            f"Potentially exposed sensitive path: {path}",
            f"Block public access to {path}; it should never be web-served.",
            root + path, evidence=f"HTTP 200, {length}B, differs from fallback page",
            confidence="medium"))


def main():
    if len(sys.argv) < 2:
        print('{"findings":[]}')
        return
    url = sys.argv[1]
    authorized = "--authorized" in sys.argv[2:]
    if not authorized:
        print("ERROR: DAST refused — pass --authorized to confirm you own/are authorized to test this target.",
              file=sys.stderr)
        print('{"findings":[]}')
        sys.exit(2)

    findings = []
    status, headers, _ = _get(url)
    if status is None:
        print(json.dumps({"status": "failed", "targetReachable": False,
                          "error": f"could not reach {url}", "findings": []}))
        sys.exit(3)
    check_headers_and_cookies(url, headers, findings)
    check_cors(url, findings)
    check_tls(url, findings)
    check_exposed_paths(url, findings)
    print(json.dumps({"status": "success", "targetReachable": True, "findings": findings}))


if __name__ == "__main__":
    main()
