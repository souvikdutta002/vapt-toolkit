#!/usr/bin/env python3
"""
VAPT Toolkit - Vulnerability Assessment and Penetration Testing Framework
Author: Souvik Dutta
"""

import sys
import os
import argparse
from modules.scanner import PortScanner
from modules.vuln_checker import VulnerabilityChecker
from modules.web_tester import WebAppTester
from modules.reporter import ReportGenerator
from modules.banner_grabber import BannerGrabber
from modules.utils import print_banner, print_section

def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="VAPT Toolkit - Vulnerability Assessment & Penetration Testing"
    )
    parser.add_argument("--target", "-t", help="Target IP or hostname")
    parser.add_argument("--url", "-u", help="Target URL for web application testing")
    parser.add_argument("--ports", "-p", default="1-1024", help="Port range (default: 1-1024)")
    parser.add_argument("--scan", action="store_true", help="Run port scan")
    parser.add_argument("--vuln", action="store_true", help="Run vulnerability check")
    parser.add_argument("--web", action="store_true", help="Run web application tests")
    parser.add_argument("--banner", action="store_true", help="Grab service banners")
    parser.add_argument("--full", action="store_true", help="Run full assessment")
    parser.add_argument("--report", "-r", default="reports/report.txt", help="Output report file")
    parser.add_argument("--output-format", choices=["txt", "json"], default="txt", help="Report format")

    args = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    report_data = {
        "target": args.target or args.url,
        "findings": []
    }

    # --- Port Scanning ---
    if args.scan or args.full:
        if not args.target:
            print("[!] --target is required for port scanning.")
        else:
            print_section("Port Scanning")
            scanner = PortScanner(args.target, args.ports)
            open_ports = scanner.run()
            report_data["open_ports"] = open_ports

    # --- Banner Grabbing ---
    if args.banner or args.full:
        if not args.target:
            print("[!] --target is required for banner grabbing.")
        else:
            print_section("Banner Grabbing")
            grabber = BannerGrabber(args.target)
            banners = grabber.run(report_data.get("open_ports", [21, 22, 80, 443, 8080]))
            report_data["banners"] = banners

    # --- Vulnerability Check ---
    if args.vuln or args.full:
        if not args.target:
            print("[!] --target is required for vulnerability check.")
        else:
            print_section("Vulnerability Assessment")
            checker = VulnerabilityChecker(args.target, report_data.get("open_ports", []))
            vulns = checker.run()
            report_data["vulnerabilities"] = vulns

    # --- Web Application Testing ---
    if args.web or args.full:
        if not args.url:
            print("[!] --url is required for web application testing.")
        else:
            print_section("Web Application Testing")
            tester = WebAppTester(args.url)
            web_findings = tester.run()
            report_data["web_findings"] = web_findings

    # --- Generate Report ---
    print_section("Generating Report")
    reporter = ReportGenerator(report_data, args.report, args.output_format)
    reporter.generate()

    print(f"\n[✔] Assessment complete. Report saved to: {args.report}\n")


if __name__ == "__main__":
    main()
