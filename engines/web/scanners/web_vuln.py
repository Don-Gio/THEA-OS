import urllib.request
import ssl
import re
from system.tools import check_installed_tools, run_cmd

def run_nikto_scan(target_url, timeout=40):
    """Execute un scan Nikto en mode natif Pro avec fallback Python."""
    tools = check_installed_tools()
    results = []

    # MODE 1 : Nikto Pro
    if tools["nikto"]:
        cmd = ["nikto", "-h", target_url, "-maxtime", f"{timeout}s", "-ask", "no"]
        raw_out = run_cmd(cmd, timeout=timeout + 10)
        if raw_out:
            for line in raw_out.splitlines():
                if line.startswith("+ "):
                    results.append({
                        "type": "Nikto Vuln",
                        "finding": line[2:].strip(),
                        "engine": "Nikto (Native Binary)"
                    })
            if results:
                return results

    # MODE 2 : Fallback Python (En-tÃªtes de sÃ©curitÃ© Web)
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(target_url, headers={'User-Agent': 'THEA-OS/1.0 WebEngine'})
        with urllib.request.urlopen(req, timeout=8, context=ctx) as resp:
            headers = dict(resp.headers)
            sec_headers = ["X-Frame-Options", "X-Content-Type-Options", "Strict-Transport-Security", "Content-Security-Policy"]
            for sh in sec_headers:
                if sh.lower() not in [h.lower() for h in headers.keys()]:
                    results.append({
                        "type": "Header Manquant",
                        "finding": f"En-tete de securite absent : {sh}",
                        "engine": "Python HTTP (Fallback)"
                    })
    except Exception:
        pass

    return results

def run_sqlmap_scan(target_url, timeout=30):
    """Execute un audit d'injection SQL via Sqlmap Pro ou fuzzer Python."""
    tools = check_installed_tools()
    results = []

    # MODE 1 : Sqlmap Pro (Batch automatique)
    if tools["sqlmap"]:
        cmd = ["sqlmap", "-u", target_url, "--batch", "--random-agent", "--level=1", "--risk=1", "--timeout=10"]
        raw_out = run_cmd(cmd, timeout=timeout + 10)
        if raw_out:
            if "is vulnerable" in raw_out or "injectable" in raw_out:
                results.append({
                    "type": "SQL Injection",
                    "finding": "Critique : Parametre injectable detecte par Sqlmap !",
                    "engine": "Sqlmap (Native Binary)"
                })
            for line in raw_out.splitlines():
                if any(k in line for k in ["Parameter:", "Type:", "Title:"]):
                    results.append({
                        "type": "SQLi Detail",
                        "finding": line.strip(),
                        "engine": "Sqlmap (Native Binary)"
                    })
            if results:
                return results

    # MODE 2 : Fallback Python (Detection d'erreurs SQL directes)
    try:
        test_url = target_url + ("?" if "?" not in target_url else "&") + "id=1'"
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(test_url, headers={'User-Agent': 'THEA-OS/1.0 WebEngine'})
        with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
            body = resp.read().decode('utf-8', errors='ignore')
            sql_errors = ["you have an error in your sql syntax", "unclosed quotation mark", "mysql_fetch", "pg_query", "sqlite3"]
            for err in sql_errors:
                if err in body.lower():
                    results.append({
                        "type": "Potentielle SQLi",
                        "finding": f"Erreur SQL generee par le fuzzer : '{err}'",
                        "engine": "Python Fuzzer (Fallback)"
                    })
    except Exception:
        pass

    return results