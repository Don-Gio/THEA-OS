import time
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from .scanners.web_vuln import run_nikto_scan, run_sqlmap_scan

console = Console()

class WebEngine:
    def __init__(self, target):
        self.target = target.strip()
        if not self.target.startswith("http://") and not self.target.startswith("https://"):
            self.target = "http://" + self.target

    def run_full_scan(self):
        start_time = time.time()

        console.print(Panel(
            f"[bold cyan]Cible Audit Web Hybride :[/bold cyan] [bold yellow]{self.target}[/bold yellow]",
            title="[bold red]THEA-OS - ENGINE WEB (PRO HYBRID)[/bold red]",
            subtitle="[dim]Application Vulnerabilities & SQL Injection Audit[/dim]",
            expand=False
        ))

        # 1. Audit Nikto
        console.print("\n  [bold cyan][+][/bold cyan] Lancement du scan applicatif (Nikto / Headers)...")
        with console.status("[bold green]Analyse des failles web en cours...", spinner="dots"):
            nikto_res = run_nikto_scan(self.target)

        t_nikto = Table(title="[bold gold1]VULNERABILITES APPLICATIVES WEB[/bold gold1]", border_style="bright_blue")
        t_nikto.add_column("TYPE", style="bold red", width=20)
        t_nikto.add_column("DETAILS / CONSTATATIONS", style="white")
        t_nikto.add_column("MOTEUR", style="bold yellow", width=22)

        if nikto_res:
            for item in nikto_res[:8]:
                t_nikto.add_row(item["type"], item["finding"], item["engine"])
            console.print(t_nikto)
        else:
            console.print("    [bold green][V] Aucune vulnÃ©rabilitÃ© applicative majeure relevÃ©e.[/bold green]")

        # 2. Audit Sqlmap
        console.print("\n  [bold cyan][+][/bold cyan] Test de vulnÃ©rabilitÃ© aux injections SQL (Sqlmap / Fuzzer)...")
        with console.status("[bold green]Recherche de failles d'injection SQL...", spinner="bouncingBar"):
            sql_res = run_sqlmap_scan(self.target)

        t_sql = Table(title="[bold gold1]TESTS D'INJECTION SQL (SQLi)[/bold gold1]", border_style="bright_blue")
        t_sql.add_column("TYPE", style="bold red", width=20)
        t_sql.add_column("RESULTAT / INJECTION", style="white")
        t_sql.add_column("MOTEUR", style="bold yellow", width=22)

        if sql_res:
            for item in sql_res[:8]:
                t_sql.add_row(item["type"], item["finding"], item["engine"])
            console.print(t_sql)
        else:
            console.print("    [bold green][V] Aucune injection SQL dÃ©tectÃ©e sur l'URL ciblÃ©e.[/bold green]")

        duration = round(time.time() - start_time, 2)
        console.print(f"\n[bold green][+] Audit Web terminÃ© en {duration}s.[/bold green]\n")

        return {
            "target": self.target,
            "nikto_results": nikto_res,
            "sqlmap_results": sql_res,
            "duration_sec": duration
        }