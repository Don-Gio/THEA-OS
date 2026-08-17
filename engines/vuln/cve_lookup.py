import urllib.request
import urllib.parse
import json
import ssl
import re

def parse_service_query(query):
    """Extrait la technologie et sa version pour cibler la recherche CVE."""
    query = query.strip()
    
    # Ignorer les reponses HTTP generiques sans nom de serveur
    if query.startswith("HTTP/") or query == "HTTP/1.1 200 OK":
        return None

    if "openssh" in query.lower():
        match = re.search(r'openssh[_\s]([0-9]+\.[0-9]+)', query, re.IGNORECASE)
        ver = match.group(1) if match else ""
        return f"OpenSSH {ver}".strip() if ver else "OpenSSH"
        
    elif "apache" in query.lower():
        match = re.search(r'apache[/\s]([0-9]+\.[0-9]+\.[0-9]+)', query, re.IGNORECASE)
        ver = match.group(1) if match else ""
        return f"Apache {ver}".strip() if ver else "Apache"
        
    elif "nginx" in query.lower():
        match = re.search(r'nginx[/\s]([0-9]+\.[0-9]+\.[0-9]+)', query, re.IGNORECASE)
        ver = match.group(1) if match else ""
        return f"Nginx {ver}".strip() if ver else "Nginx"
        
    return query

def fetch_cves_circl(keyword, max_results=5):
    """Interroge la base de donnees de vulnerabilites."""
    if not keyword:
        return []
        
    cves = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    encoded = urllib.parse.quote(keyword)
    url = f"https://cve.circl.lu/api/search/{encoded}"
    req = urllib.request.Request(url, headers={'User-Agent': 'THEA-OS/1.0 VulnEngine'})

    try:
        with urllib.request.urlopen(req, timeout=6, context=ctx) as response:
            if response.getcode() == 200:
                raw = response.read().decode('utf-8', errors='ignore')
                data = json.loads(raw)
                results = data if isinstance(data, list) else data.get("results", [])
                for item in results[:max_results]:
                    cve_id = item.get("id", "CVE-Unknown")
                    cvss = item.get("cvss", "N/A")
                    summary = item.get("summary", "Pas de description disponible.")
                    cves.append({
                        "id": cve_id,
                        "cvss": str(cvss),
                        "summary": summary[:90] + "..." if len(summary) > 90 else summary
                    })
    except Exception:
        pass
    return cves