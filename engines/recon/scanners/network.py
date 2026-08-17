import socket
import concurrent.futures

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 139: "NetBIOS", 443: "HTTPS", 445: "SMB",
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt"
}

def scan_port(ip, port, timeout=1.0):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            res = s.connect_ex((ip, port))
            if res == 0:
                service = COMMON_PORTS.get(port, "Unknown")
                banner = ""
                try:
                    s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = s.recv(256).decode("utf-8", errors="ignore").strip().split("\n")[0]
                except Exception:
                    pass
                return {"port": port, "service": service, "state": "OPEN", "banner": banner}
    except Exception:
        pass
    return None

def scan_target(target_ip, ports=None, max_threads=20):
    if ports is None:
        ports = list(COMMON_PORTS.keys())
        
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = [executor.submit(scan_port, target_ip, p) for p in ports]
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if res:
                open_ports.append(res)
                
    return sorted(open_ports, key=lambda x: x["port"])