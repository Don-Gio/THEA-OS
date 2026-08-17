import socket
import re
from system.tools import check_installed_tools, run_cmd

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1433, 3306, 3389, 8080, 8443]

def scan_target(target_ip):
    """Scan hybride : utilise Nmap pro si disponible, sinon fallback sockets Python."""
    tools = check_installed_tools()
    results = []

    # MODE 1 : Utilisation de Nmap (Mode Professionnel)
    if tools["nmap"]:
        ports_str = ",".join(map(str, COMMON_PORTS))
        raw_output = run_cmd(["nmap", "-sV", "-p", ports_str, "--open", target_ip], timeout=45)
        if raw_output:
            for line in raw_output.splitlines():
                match = re.search(r"^(\d+)/(tcp|udp)\s+open\s+([\w\-\.]+)\s*(.*)", line)
                if match:
                    port = int(match.group(1))
                    service = match.group(3)
                    banner = match.group(4).strip() or service
                    results.append({
                        "port": port,
                        "state": "open",
                        "service": service,
                        "banner": banner,
                        "engine": "Nmap (Native Binary)"
                    })
            if results:
                return results

    # MODE 2 : Fallback Sockets Python (Mode Secours / Zero-dependency)
    for port in COMMON_PORTS:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.8)
            code = sock.connect_ex((target_ip, port))
            if code == 0:
                service = "http" if port in [80, 8080] else "https" if port in [443, 8443] else "unknown"
                banner = ""
                try:
                    if port in [80, 8080, 443]:
                        sock.sendall(b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                    banner = sock.recv(256).decode('utf-8', errors='ignore').strip().split("\r\n")[0]
                except Exception:
                    pass
                
                results.append({
                    "port": port,
                    "state": "open",
                    "service": service,
                    "banner": banner or f"Port {port} Ouvert",
                    "engine": "Python Socket (Fallback)"
                })
            sock.close()
        except Exception:
            pass

    return results