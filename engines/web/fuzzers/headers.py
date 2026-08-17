import urllib.request
import ssl

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "X-XSS-Protection",
    "Referrer-Policy"
]

def analyze_headers(target_url):
    results = {
        "server": "Inconnu",
        "powered_by": "Inconnu",
        "present_security_headers": [],
        "missing_security_headers": [],
        "status_code": None
    }
    
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(target_url, headers={'User-Agent': 'THEA-OS/1.0 WebEngine'})

    try:
        with urllib.request.urlopen(req, timeout=5, context=ctx) as response:
            results["status_code"] = response.getcode()
            headers = response.info()

            results["server"] = headers.get("Server", "Non revele")
            results["powered_by"] = headers.get("X-Powered-By", "Non revele")

            for sec_h in SECURITY_HEADERS:
                if sec_h in headers:
                    results["present_security_headers"].append(sec_h)
                else:
                    results["missing_security_headers"].append(sec_h)

    except Exception as e:
        results["error"] = str(e)

    return results