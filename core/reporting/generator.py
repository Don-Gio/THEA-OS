import json
import os
from datetime import datetime

REPORTS_DIR = "/opt/thea/reports"

def ensure_dirs():
    os.makedirs(f"{REPORTS_DIR}/json", exist_ok=True)
    os.makedirs(f"{REPORTS_DIR}/html", exist_ok=True)

def generate_report(engine_name, target, data):
    """Genere des rapports JSON et HTML a partir des donnees d'un moteur."""
    ensure_dirs()
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    date_human = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    clean_target = str(target).replace("/", "_").replace(":", "_")
    base_name = f"{engine_name}_{clean_target}_{timestamp_str}"

    json_path = os.path.join(REPORTS_DIR, "json", f"{base_name}.json")
    html_path = os.path.join(REPORTS_DIR, "html", f"{base_name}.html")

    # 1. Export JSON
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)

    # 2. Export HTML Dashboard
    html_content = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>THEA-OS Report - {engine_name.upper()}</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, sans-serif; background-color: #0f172a; color: #f8fafc; margin: 0; padding: 30px; }}
        .header {{ background-color: #1e293b; padding: 20px; border-radius: 10px; border-left: 6px solid #38bdf8; margin-bottom: 25px; }}
        h1 {{ margin: 0 0 10px 0; color: #38bdf8; font-size: 24px; }}
        .meta {{ color: #94a3b8; font-size: 14px; display: flex; gap: 20px; }}
        .card {{ background-color: #1e293b; padding: 20px; border-radius: 10px; margin-bottom: 20px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.3); }}
        h2 {{ color: #f43f5e; margin-top: 0; font-size: 18px; border-bottom: 1px solid #334155; padding-bottom: 8px; }}
        pre {{ background-color: #020617; padding: 15px; border-radius: 6px; overflow-x: auto; color: #38bdf8; font-family: 'Consolas', monospace; font-size: 13px; }}
        .footer {{ text-align: center; margin-top: 40px; color: #64748b; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>THEA-OS â€” Rapport d'Audit Intelligence</h1>
        <div class="meta">
            <span><strong>Moteur :</strong> {engine_name.upper()}</span>
            <span><strong>Cible :</strong> {target}</span>
            <span><strong>Date :</strong> {date_human}</span>
        </div>
    </div>

    <div class="card">
        <h2>Resultats de l'Analyse</h2>
        <pre>{json.dumps(data, indent=4, ensure_ascii=False)}</pre>
    </div>

    <div class="footer">
        GÃ©nÃ©rÃ© automatiquement par THEA-OS Framework.
    </div>
</body>
</html>"""

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    return json_path, html_path

def list_reports():
    """Liste l'ensemble des rapports disponibles."""
    ensure_dirs()
    json_files = os.listdir(f"{REPORTS_DIR}/json")
    html_files = os.listdir(f"{REPORTS_DIR}/html")
    return {
        "json": sorted(json_files, reverse=True),
        "html": sorted(html_files, reverse=True)
    }