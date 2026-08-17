import urllib.request
import json

def fetch_crtsh_subdomains(domain):
    """Recherche les sous-domaines publics enregistrÃ©s via crt.sh (Certificate Transparency)."""
    subdomains = set()
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'THEA-OS/1.0 OSINTEngine'})
        with urllib.request.urlopen(req, timeout=8) as response:
            data = json.loads(response.read().decode())
            for item in data:
                name = item.get("name_value", "")
                for sub in name.split("\n"):
                    sub = sub.strip()
                    if sub and not sub.startswith("*.") and domain in sub:
                        subdomains.add(sub)
    except Exception:
        pass

    return sorted(list(subdomains))