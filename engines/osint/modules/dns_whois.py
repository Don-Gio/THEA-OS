import socket
import urllib.request
import json

def get_dns_records(domain):
    """Recupere les adresses IP et les informations basiques de resolution."""
    results = {
        "ip_addresses": [],
        "hostnames": []
    }
    try:
        ip_list = socket.gethostbyname_ex(domain)
        results["hostnames"].append(ip_list[0])
        results["ip_addresses"] = ip_list[2]
    except Exception as e:
        results["error"] = str(e)
    return results

def get_ip_intel(ip_address):
    """Recupere les informations de geolocalisation et d'ASN pour une IP."""
    try:
        url = f"http://ip-api.com/json/{ip_address}?fields=status,country,countryCode,regionName,city,isp,org,as,query"
        req = urllib.request.Request(url, headers={'User-Agent': 'THEA-OS/1.0 OSINTEngine'})
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode())
            if data.get("status") == "success":
                return data
    except Exception:
        pass
    return {}