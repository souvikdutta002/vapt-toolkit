#!/usr/bin/env python3
"""
demo.py - Simulated VAPT demo on localhost
Run this to see the toolkit in action without a real target.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from modules.utils import print_banner, print_section
from modules.reporter import ReportGenerator

print_banner()

print("""
  This demo simulates a VAPT assessment for educational purposes.
  Replace 'localhost' and the URL with your authorized lab target.
""")

# Simulated findings (as if a scan was run on a test lab machine)
simulated_data = {
    "target": "192.168.1.100 (Lab VM - Authorized)",
    "open_ports": [21, 22, 80, 445, 3306, 8080],
    "banners": {
        21:   "220 vsftpd 2.3.4",
        22:   "SSH-2.0-OpenSSH_7.4",
        80:   "HTTP/1.1 200 OK Server: Apache/2.4.18",
        8080: "HTTP/1.1 200 OK Server: Apache Tomcat/8.5.5"
    },
    "vulnerabilities": [
        {
            "port": 21, "service": "FTP", "name": "Anonymous FTP Login",
            "severity": "HIGH", "cve": "CVE-1999-0497", "cvss": 7.5,
            "description": "FTP server allows anonymous login, exposing sensitive files.",
            "remediation": "Disable anonymous FTP access."
        },
        {
            "port": 445, "service": "SMB", "name": "SMB EternalBlue Risk",
            "severity": "CRITICAL", "cve": "CVE-2017-0144", "cvss": 9.3,
            "description": "SMB port exposed. EternalBlue targets this service (WannaCry).",
            "remediation": "Apply MS17-010 patch. Disable SMBv1."
        },
        {
            "port": 3306, "service": "MySQL", "name": "MySQL Externally Accessible",
            "severity": "HIGH", "cve": "CVE-2012-2122", "cvss": 7.6,
            "description": "MySQL is accessible from network, not just localhost.",
            "remediation": "Bind MySQL to 127.0.0.1 only."
        }
    ],
    "web_findings": [
        {
            "type": "Missing Security Header",
            "severity": "MEDIUM",
            "detail": "Header 'Content-Security-Policy' is not set.",
            "reference": "OWASP A05:2021 - Security Misconfiguration",
            "remediation": "Add Content-Security-Policy header to all responses."
        },
        {
            "type": "Missing Security Header",
            "severity": "MEDIUM",
            "detail": "Header 'X-Frame-Options' is not set. Site may be vulnerable to Clickjacking.",
            "reference": "OWASP A05:2021 - Security Misconfiguration",
            "remediation": "Add X-Frame-Options: DENY or SAMEORIGIN."
        },
        {
            "type": "Unencrypted HTTP Service",
            "severity": "MEDIUM",
            "detail": "HTTP (port 80) is active without enforced HTTPS redirect.",
            "reference": "CWE-319",
            "remediation": "Redirect all HTTP traffic to HTTPS."
        }
    ]
}

print_section("Generating Demo Report")
reporter = ReportGenerator(simulated_data, "reports/demo_report.txt", "txt")
reporter.generate()

# Also save JSON
reporter_json = ReportGenerator(simulated_data, "reports/demo_report.json", "json")
reporter_json.generate()

print("\n[✔] Demo complete!")
print("    TXT Report : reports/demo_report.txt")
print("    JSON Report: reports/demo_report.json")
print("\n  To run a real scan:")
print("    python vapt_toolkit.py --target <IP> --url <URL> --full")
