"""
Report Generator Module
Produces structured assessment reports in TXT or JSON format.
"""

import json
import os
from datetime import datetime


class ReportGenerator:
    def __init__(self, data: dict, output_path: str = "reports/report.txt", fmt: str = "txt"):
        self.data = data
        self.output_path = output_path
        self.fmt = fmt
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

    def _txt_report(self) -> str:
        lines = []
        border = "=" * 70
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        lines.append(border)
        lines.append("       VAPT TOOLKIT - ASSESSMENT REPORT")
        lines.append(border)
        lines.append(f"  Target   : {self.data.get('target', 'N/A')}")
        lines.append(f"  Date     : {now}")
        lines.append(f"  Tool     : VAPT Toolkit v1.0")
        lines.append(border)
        lines.append("")

        # Open Ports
        if "open_ports" in self.data:
            lines.append("[ PORT SCAN RESULTS ]")
            lines.append("-" * 40)
            open_ports = self.data["open_ports"]
            if open_ports:
                for p in open_ports:
                    try:
                        svc = __import__("socket").getservbyport(p)
                    except OSError:
                        svc = "unknown"
                    lines.append(f"  [OPEN] Port {p} - {svc}")
            else:
                lines.append("  No open ports found.")
            lines.append("")

        # Banners
        if "banners" in self.data:
            lines.append("[ SERVICE BANNERS ]")
            lines.append("-" * 40)
            for port, banner in self.data["banners"].items():
                lines.append(f"  Port {port}: {banner[:100]}")
            lines.append("")

        # Vulnerabilities
        if "vulnerabilities" in self.data:
            lines.append("[ VULNERABILITY ASSESSMENT ]")
            lines.append("-" * 40)
            vulns = self.data["vulnerabilities"]
            if vulns:
                for v in vulns:
                    lines.append(f"  [{v['severity']}] Port {v['port']} ({v['service']}) - {v['name']}")
                    lines.append(f"    CVE       : {v['cve']}")
                    lines.append(f"    CVSS      : {v['cvss']}")
                    lines.append(f"    Details   : {v['description']}")
                    lines.append(f"    Fix       : {v['remediation']}")
                    lines.append("")
            else:
                lines.append("  No vulnerabilities detected.")
            lines.append("")

        # Web Findings
        if "web_findings" in self.data:
            lines.append("[ WEB APPLICATION FINDINGS ]")
            lines.append("-" * 40)
            findings = self.data["web_findings"]
            if findings:
                for f in findings:
                    lines.append(f"  [{f['severity']}] {f['type']}")
                    lines.append(f"    Detail    : {f['detail']}")
                    lines.append(f"    Reference : {f['reference']}")
                    lines.append(f"    Fix       : {f['remediation']}")
                    lines.append("")
            else:
                lines.append("  No web vulnerabilities detected.")
            lines.append("")

        # Summary
        lines.append(border)
        lines.append("[ EXECUTIVE SUMMARY ]")
        lines.append("-" * 40)
        total_vulns = len(self.data.get("vulnerabilities", []))
        total_web = len(self.data.get("web_findings", []))
        total_ports = len(self.data.get("open_ports", []))
        lines.append(f"  Open Ports          : {total_ports}")
        lines.append(f"  Vulnerabilities     : {total_vulns}")
        lines.append(f"  Web App Findings    : {total_web}")
        lines.append(f"  Total Issues Found  : {total_vulns + total_web}")
        lines.append("")
        lines.append("  DISCLAIMER: This report is generated in a simulated/lab")
        lines.append("  environment for educational purposes only. Unauthorized")
        lines.append("  use against real systems is illegal.")
        lines.append(border)

        return "\n".join(lines)

    def _json_report(self) -> str:
        report = {
            "meta": {
                "tool": "VAPT Toolkit v1.0",
                "generated": datetime.now().isoformat(),
                "target": self.data.get("target", "N/A")
            },
            "results": self.data
        }
        return json.dumps(report, indent=4)

    def generate(self):
        if self.fmt == "json":
            content = self._json_report()
        else:
            content = self._txt_report()

        with open(self.output_path, "w") as f:
            f.write(content)

        print(content)
