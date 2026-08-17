import urllib.request
import ssl
import concurrent.futures

DEFAULT_WORDLIST = [
    "admin", "login", "dashboard", "api", "v1", "v2", "robots.txt",
    ".env", ".git/HEAD", "config.json", "config.php", "phpmyadmin",
    "backup.sql", "swagger-ui.html", "sitemap.xml", "server-status"
]

def check_path(base_url, path, ctx, timeout=3.0):
    url = f"{base_url.rstrip('/')}/{path}"
    req = urllib.request.Request(url, headers={'User-Agent': 'THEA-OS/1.0 WebEngine'})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as response:
            code = response.getcode()
            length = len(response.read())
            if code in [200, 201, 204, 301, 302, 403]:
                return {"path": f"/{path}", "status": code, "length": length}
    except urllib.error.HTTPError as e:
        if e.code in [301, 302, 403]:
            return {"path": f"/{path}", "status": e.code, "length": 0}
    except Exception:
        pass
    return None

def fuzz_directories(target_url, wordlist=None, max_threads=15):
    if wordlist is None:
        wordlist = DEFAULT_WORDLIST

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    found_paths = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = [executor.submit(check_path, target_url, path, ctx) for path in wordlist]
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if res:
                found_paths.append(res)

    return sorted(found_paths, key=lambda x: x["status"])