"""
Banner Grabber Module
Connects to open ports and retrieves service banners for fingerprinting.
"""

import socket
from modules.utils import log_result

# Protocol-specific probes
PROBES = {
    21:   b"",          # FTP sends banner automatically
    22:   b"",          # SSH sends banner automatically
    25:   b"",          # SMTP
    80:   b"HEAD / HTTP/1.1\r\nHost: target\r\n\r\n",
    443:  b"HEAD / HTTP/1.1\r\nHost: target\r\n\r\n",
    110:  b"",          # POP3
    143:  b"",          # IMAP
    3306: b"",          # MySQL
    3389: b"",          # RDP
    8080: b"HEAD / HTTP/1.1\r\nHost: target\r\n\r\n",
}


class BannerGrabber:
    def __init__(self, target: str, timeout: float = 3.0):
        self.target = target
        self.timeout = timeout
        self.results = {}

    def _grab(self, port: int) -> str:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, port))

            probe = PROBES.get(port, b"\r\n")
            if probe:
                sock.send(probe)

            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            sock.close()
            return banner if banner else "No banner received"
        except (socket.timeout, ConnectionRefusedError):
            return "No response"
        except Exception as e:
            return f"Error: {str(e)[:50]}"

    def run(self, ports: list) -> dict:
        print(f"[*] Grabbing banners from {self.target} on {len(ports)} port(s)...\n")
        for port in ports:
            banner = self._grab(port)
            self.results[port] = banner
            # Truncate for display
            display = banner[:80] + "..." if len(banner) > 80 else banner
            print(f"  Port {port:<6} → {display}")
            log_result(f"BANNER Port {port}: {banner[:120]}")

        print(f"\n[✔] Banner grabbing complete.")
        return self.results
