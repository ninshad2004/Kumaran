#!/usr/bin/env python3
"""
scanner.py — Threaded port scanner with banner grabbing
"""

import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

# ─── Common port → service name map ─────────────────────────────────────────────
PORT_SERVICE_MAP = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP",
    88: "KERBEROS", 110: "POP3", 111: "RPCBIND", 119: "NNTP",
    123: "NTP", 135: "MSRPC", 137: "NETBIOS", 138: "NETBIOS",
    139: "NETBIOS-SSN", 143: "IMAP", 161: "SNMP", 162: "SNMP-TRAP",
    179: "BGP", 194: "IRC", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 500: "ISAKMP", 512: "REXEC", 513: "RLOGIN",
    514: "SYSLOG", 515: "PRINTER", 520: "RIP", 587: "SMTP-SUBMISSION",
    631: "CUPS-IPP", 636: "LDAPS", 873: "RSYNC", 902: "VMWARE",
    989: "FTPS-DATA", 990: "FTPS", 993: "IMAPS", 995: "POP3S",
    1080: "SOCKS", 1194: "OPENVPN", 1433: "MSSQL", 1434: "MSSQL-UDP",
    1521: "ORACLE-DB", 1723: "PPTP", 1883: "MQTT", 2049: "NFS",
    2121: "FTP-ALT", 2181: "ZOOKEEPER", 2375: "DOCKER", 2376: "DOCKER-TLS",
    2483: "ORACLE-DB", 3000: "DEV-SERVER", 3306: "MYSQL", 3389: "RDP",
    3690: "SVN", 4000: "REMOTEANYTHING", 4369: "ERLANG-EPMD",
    5000: "FLASK-DEV", 5432: "POSTGRESQL", 5672: "RABBITMQ",
    5900: "VNC", 5984: "COUCHDB", 6379: "REDIS", 6443: "K8S-API",
    7001: "WEBLOGIC", 8000: "HTTP-ALT", 8008: "HTTP-ALT2",
    8080: "HTTP-PROXY", 8443: "HTTPS-ALT", 8888: "JUPYTER",
    9000: "PORTAINER", 9090: "PROMETHEUS", 9200: "ELASTICSEARCH",
    9300: "ELASTICSEARCH-TRANSPORT", 10250: "KUBELET",
    11211: "MEMCACHED", 15672: "RABBITMQ-MGMT", 27017: "MONGODB",
    27018: "MONGODB", 50070: "HADOOP", 61616: "ACTIVEMQ",
}


def grab_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    """Attempt to grab a service banner from an open port."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            # Send generic HTTP probe for web ports, else just read
            if port in (80, 8080, 8000, 8008, 8888, 3000, 5000):
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
            elif port in (21, 22, 25, 110, 143, 220, 443):
                pass  # services send banner on connect
            else:
                s.sendall(b"\r\n")
            banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
            # Return just the first meaningful line
            for line in banner.splitlines():
                line = line.strip()
                if line:
                    return line[:80]
    except Exception:
        pass
    return ""


def scan_port(ip: str, port: int, timeout: float, verbose: bool):
    """
    Try to connect to a single port.
    Returns (port, service, banner) if open, else None.
    """
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            service = PORT_SERVICE_MAP.get(port, "UNKNOWN")
            banner  = grab_banner(ip, port, timeout=min(timeout + 1, 3.0))
            if verbose:
                print(f"  \033[92m[OPEN]\033[0m  {port:<6}  {service:<20}  {banner[:40] if banner else ''}")
            return (port, service, banner)
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def scan_target(ip: str, port_list: list, threads: int = 150,
                timeout: float = 1.0, verbose: bool = False) -> list:
    """
    Scan all ports in port_list using a thread pool.
    Returns list of (port, service, banner) tuples for open ports.
    """
    results = []
    lock = threading.Lock()

    if verbose:
        print(f"\033[96m[*] Scanning {len(port_list)} ports on {ip} …\033[0m\n")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(scan_port, ip, port, timeout, verbose): port
            for port in port_list
        }
        for future in as_completed(futures):
            result = future.result()
            if result:
                with lock:
                    results.append(result)

    # Sort by port number before returning
    results.sort(key=lambda x: x[0])
    return results

