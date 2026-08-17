import shutil
import subprocess

def check_installed_tools():
    """Verifie la presence des outils pros sur le systeme host."""
    tools = {
        "nmap": shutil.which("nmap") is not None,
        "searchsploit": shutil.which("searchsploit") is not None,
        "nikto": shutil.which("nikto") is not None,
        "sqlmap": shutil.which("sqlmap") is not None,
        "curl": shutil.which("curl") is not None
    }
    return tools

def run_cmd(cmd, timeout=30):
    """Execute une commande systeme et retourne le resultat brut."""
    try:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
        return res.stdout if res.returncode == 0 else None
    except Exception:
        return None