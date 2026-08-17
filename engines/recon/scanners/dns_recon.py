import socket

def resolve_target(target):
    info = {"target": target, "ip": None, "hostname": None, "aliases": []}
    try:
        ip = socket.gethostbyname(target)
        info["ip"] = ip
        try:
            host_info = socket.gethostbyaddr(ip)
            info["hostname"] = host_info[0]
            info["aliases"] = host_info[1]
        except Exception:
            info["hostname"] = "N/A"
    except Exception as e:
        info["error"] = str(e)
    return info