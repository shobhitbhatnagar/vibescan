#!/usr/bin/env python3
"""VibeScan passive DAST — inspect a LIVE web app over HTTP (non-destructive).

Checks security headers, TLS/HSTS, cookie flags, CORS, version disclosure, and a small
set of well-known exposed paths (.env, .git). GET/HEAD only — no fuzzing, no writes, no
destructive methods. Emits findings in VibeScan's schema to stdout as {"findings":[...]}.

AUTHORIZATION: DAST sends real requests to a running system. This tool refuses to run
unless --authorized is passed, which asserts you own or are explicitly authorized to test
the target. Never point it at a URL you don't control.

Usage: web_scan.py <url> --authorized
"""
import json
import socket
import ssl
import sys
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


def _get(url, method="GET"):
    req = urllib.request.Request(url, method=method, headers={"User-Agent": UA})
    ctx = ssl.create_default_context()
    try:
        resp = urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx)
        return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in (e.headers or {}).items()}, None
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
    # CORS
    acao = headers.get("access-control-allow-origin", "")
    acac = headers.get("access-control-allow-credentials", "").lower()
    if acao == "*" and acac == "true":
        findings.append(_finding(
            "config_issue", "high", "CORS allows any origin with credentials",
            "Never combine Access-Control-Allow-Origin: * with Allow-Credentials: true; echo an allowlisted origin.",
            url, evidence="ACAO: * + ACAC: true"))
    elif acao == "*":
        findings.append(_finding(
            "config_issue", "medium", "Wildcard CORS (Access-Control-Allow-Origin: *)",
            "Restrict CORS to an explicit origin allowlist.", url))
    # cookies
    setcookie = headers.get("set-cookie", "")
    if setcookie:
        low = setcookie.lower()
        if "secure" not in low:
            findings.append(_finding(
                "auth_issue", "high", "Session cookie missing Secure flag",
                "Set the Secure flag so cookies are only sent over HTTPS.", url))
        if "httponly" not in low:
            findings.append(_finding(
                "auth_issue", "medium", "Session cookie missing HttpOnly flag",
                "Set HttpOnly so cookies aren't readable by JavaScript (XSS theft).", url))
        if "samesite" not in low:
            findings.append(_finding(
                "config_issue", "low", "Session cookie missing SameSite attribute",
                "Set SameSite=Lax or Strict to reduce CSRF exposure.", url))


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


def check_exposed_paths(base, findings):
    p = urlparse(base)
    root = f"{p.scheme}://{p.netloc}"
    for path in EXPOSED_PATHS:
        status, headers, resp = _get(root + path)
        if status == 200:
            body = ""
            try:
                body = resp.read(256).decode("utf-8", "replace") if resp else ""
            except Exception:
                pass
            # crude sanity: many servers 200 a custom 404 page; flag only if it looks like the real thing
            looks_real = any(m in body for m in ("[core]", "ref:", "=", "AWS", "aws_")) or path.endswith("HEAD")
            sev = "critical" if path in ("/.env", "/.git/config", "/.aws/credentials") else "high"
            findings.append(_finding(
                "data_exposure", sev if looks_real else "medium",
                f"Potentially exposed sensitive path: {path}",
                f"Block public access to {path}; it should never be web-served.",
                root + path, evidence=body[:120],
                confidence="high" if looks_real else "low"))


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
        print(f"WARN: could not reach {url}", file=sys.stderr)
        print('{"findings":[]}')
        return
    check_headers_and_cookies(url, headers, findings)
    check_tls(url, findings)
    check_exposed_paths(url, findings)
    print(json.dumps({"findings": findings}))


if __name__ == "__main__":
    main()
