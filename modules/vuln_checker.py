"""
Vulnerability Checker Module
Checks for common vulnerabilities based on open ports and service detection.
Maps findings to CVE references and CVSS severity scores.
"""

import socket
from modules.utils import log_result


# Known vulnerable service signatures mapped to CVE data
VULNERABILITY_DB = {
    21: {
        "service": "FTP",
        "checks": [
            {
                "name": "Anonymous FTP Login",
                "severity": "HIGH",
                "cve": "CVE-1999-0497",
                "cvss": 7.5,
                "description": "FTP server allows anonymous login, potentially exposing sensitive files.",
                "remediation": "Disable anonymous FTP access. Enforce authentication."
            }
        ]
    },
    22: {
        "service": "SSH",
        "checks": [
            {
                "name": "SSH Version Detection",
                "severity": "INFO",
                "cve": "N/A",
                "cvss": 0.0,
                "description": "SSH service detected. Older versions (< OpenSSH 8.x) may have known vulnerabilities.",
                "remediation": "Ensure OpenSSH is updated to the latest stable version."
            }
        ]
    },
    23: {
        "service": "Telnet",
        "checks": [
            {
                "name": "Telnet Service Exposed",
                "severity": "CRITICAL",
                "cve": "CVE-2011-4862",
                "cvss": 9.3,
                "description": "Telnet transmits data in plaintext including credentials. Should not be exposed.",
                "remediation": "Disable Telnet. Replace with SSH for encrypted remote access."
            }
        ]
    },
    80: {
        "service": "HTTP",
        "checks": [
            {
                "name": "Unencrypted HTTP Service",
                "severity": "MEDIUM",
                "cve": "CWE-319",
                "cvss": 5.3,
                "description": "HTTP is unencrypted. Sensitive data transmitted over HTTP is vulnerable to interception.",
                "remediation": "Redirect HTTP to HTTPS. Use TLS 1.2 or higher."
            }
        ]
    },
    443: {
        "service": "HTTPS",
        "checks": [
            {
                "name": "HTTPS Detected",
                "severity": "INFO",
                "cve": "N/A",
                "cvss": 0.0,
                "description": "HTTPS is enabled. Verify TLS version and certificate validity.",
                "remediation": "Ensure TLS 1.2+ is enforced. Disable SSLv2, SSLv3, TLS 1.0."
            }
        ]
    },
    3306: {
        "service": "MySQL",
        "checks": [
            {
                "name": "MySQL Externally Accessible",
                "severity": "HIGH",
                "cve": "CVE-2012-2122",
                "cvss": 7.6,
                "description": "MySQL database port is exposed to the network. May allow unauthorized access.",
                "remediation": "Bind MySQL to localhost only. Use firewall rules to restrict access."
            }
        ]
    },
    3389: {
        "service": "RDP",
        "checks": [
            {
                "name": "RDP BlueKeep Risk",
                "severity": "CRITICAL",
                "cve": "CVE-2019-0708",
                "cvss": 9.8,
                "description": "RDP is exposed. BlueKeep vulnerability allows unauthenticated remote code execution on unpatched systems.",
                "remediation": "Apply MS19-0708 patch. Enable NLA. Restrict RDP access via VPN."
            }
        ]
    },
    445: {
        "service": "SMB",
        "checks": [
            {
                "name": "SMB EternalBlue Risk",
                "severity": "CRITICAL",
                "cve": "CVE-2017-0144",
                "cvss": 9.3,
                "description": "SMB port exposed. EternalBlue exploit used by WannaCry targets this service.",
                "remediation": "Apply MS17-010 patch. Disable SMBv1. Block port 445 on perimeter firewall."
            }
        ]
    },
    8080: {
        "service": "HTTP-Alternate",
        "checks": [
            {
                "name": "Alternate HTTP Port Open",
                "severity": "LOW",
                "cve": "CWE-16",
                "cvss": 3.1,
                "description": "An alternate HTTP port is exposed. May indicate dev/staging server or misconfiguration.",
                "remediation": "Verify this port is intentional. Apply proper access controls."
            }
        ]
    },
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_COLORS = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🔵",
    "INFO": "⚪"
}


class VulnerabilityChecker:
    def __init__(self, target: str, open_ports: list):
        self.target = target
        self.open_ports = open_ports
        self.findings = []

    def _check_anonymous_ftp(self):
        """Attempt anonymous FTP login to confirm vulnerability."""
        try:
            import ftplib
            ftp = ftplib.FTP(self.target, timeout=3)
            ftp.login("anonymous", "vapt@test.com")
            ftp.quit()
            return True
        except Exception:
            return False

    def run(self) -> list:
        print(f"[*] Running vulnerability checks against: {self.target}")
        print(f"[*] Analyzing {len(self.open_ports)} open port(s)...\n")

        ports_to_check = self.open_ports if self.open_ports else list(VULNERABILITY_DB.keys())

        for port in ports_to_check:
            if port in VULNERABILITY_DB:
                entry = VULNERABILITY_DB[port]
                service = entry["service"]

                # Special case: verify anonymous FTP
                if port == 21:
                    confirmed = self._check_anonymous_ftp()
                    if not confirmed:
                        continue  # Skip if not actually vulnerable

                for check in entry["checks"]:
                    icon = SEVERITY_COLORS.get(check["severity"], "⚪")
                    finding = {
                        "port": port,
                        "service": service,
                        **check
                    }
                    self.findings.append(finding)
                    print(f"  {icon} [{check['severity']}] Port {port} ({service}) - {check['name']}")
                    print(f"     CVE: {check['cve']} | CVSS: {check['cvss']}")
                    print(f"     {check['description']}")
                    print(f"     Fix: {check['remediation']}\n")
                    log_result(f"VULN [{check['severity']}] Port {port} - {check['name']} | {check['cve']}")

        # Sort by severity
        self.findings.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 99))

        summary = {s: sum(1 for f in self.findings if f["severity"] == s)
                   for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]}

        print(f"[✔] Vulnerability check complete.")
        print(f"    Summary → CRITICAL: {summary['CRITICAL']} | HIGH: {summary['HIGH']} | "
              f"MEDIUM: {summary['MEDIUM']} | LOW: {summary['LOW']} | INFO: {summary['INFO']}")

        return self.findings
