"""
Port Scanner Module
Scans a target host for open TCP ports using socket connections.
"""

import socket
import threading
from queue import Queue
from modules.utils import log_result


class PortScanner:
    def __init__(self, target: str, port_range: str = "1-1024", threads: int = 100, timeout: float = 0.5):
        self.target = target
        self.timeout = timeout
        self.threads = threads
        self.open_ports = []
        self.queue = Queue()
        self.lock = threading.Lock()

        # Parse port range
        try:
            start, end = map(int, port_range.split("-"))
            self.ports = range(start, end + 1)
        except ValueError:
            self.ports = [int(p) for p in port_range.split(",")]

    def _resolve_target(self) -> str:
        try:
            ip = socket.gethostbyname(self.target)
            print(f"[*] Resolved {self.target} → {ip}")
            return ip
        except socket.gaierror:
            print(f"[!] Could not resolve host: {self.target}")
            return self.target

    def _scan_port(self, ip: str, port: int):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except OSError:
                    service = "unknown"
                with self.lock:
                    self.open_ports.append(port)
                    print(f"  [OPEN] Port {port:<6} | Service: {service}")
                    log_result(f"OPEN PORT: {port} ({service})")
            sock.close()
        except (socket.error, OSError):
            pass

    def _worker(self, ip: str):
        while not self.queue.empty():
            port = self.queue.get()
            self._scan_port(ip, port)
            self.queue.task_done()

    def run(self) -> list:
        ip = self._resolve_target()
        print(f"[*] Scanning {ip} | Ports: {min(self.ports)}-{max(self.ports)} | Threads: {self.threads}")

        for port in self.ports:
            self.queue.put(port)

        threads = []
        for _ in range(min(self.threads, len(self.ports))):
            t = threading.Thread(target=self._worker, args=(ip,))
            t.daemon = True
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        print(f"\n[✔] Scan complete. Found {len(self.open_ports)} open port(s): {sorted(self.open_ports)}")
        return sorted(self.open_ports)
