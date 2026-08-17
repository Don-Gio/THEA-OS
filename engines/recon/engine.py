import time
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from .scanners.dns_recon import resolve_target
from .scanners.network import scan_target

console = Console()

class ReconEngine:
    def __init__(self, target):
        self.target = target

    def run_full_recon(self):
        start_time = time.time()
        
        # En-tete
        console.print(Panel(
            f"[bold cyan]Cible :[/bold cyan] [bold yellow]{self.target}[/bold yellow]",
            title="[bold red]THEA-OS - ENGINE RECON[/bold red]",
            subtitle="[dim]Vulnerability & Reconnaissance Framework[/dim]",
            expand=False
        ))

        # 1. Resolution DNS
        with console.status("[bold green]Resolution DNS et IP...", spinner="dots"):
            dns_data = resolve_target(self.target)

        if not dns_data.get("ip"):
            console.print(f"[bold red][!] Impossible de resoudre l'hote {self.target}[/bold red]")
            return None

        console.print(f"  [bold green][+][/bold green] [bold white]Adresse IP  :[/bold white] {dns_data['ip']}")
        console.print(f"  [bold green][+][/bold green] [bold white]Hote DNS    :[/bold white] {dns_data['hostname']}\n")

        # 2. Port Scan & Banner Grabbing
        with console.status("[bold cyan]Balayage des services et bannieres...", spinner="bouncingBar"):
            open_services = scan_target(dns_data["ip"])

        duration = round(time.time() - start_time, 2)

        # 3. Tableau de resultats
        table = Table(
            title=f"\n[bold gold1]RAPPORT DE RECONNAISSANCE ({duration}s)[/bold gold1]",
            header_style="bold magenta",
            border_style="bright_blue"
        )
        table.add_column("PORT", style="cyan", justify="right")
        table.add_column("SERVICE", style="green", justify="center")
        table.add_column("BANNIERE / INFORMATIONS", style="white")

        if open_services:
            for s in open_services:
                banner_text = s["banner"][:45] if s["banner"] else "[dim]Aucune banniere[/dim]"
                table.add_row(str(s["port"]), s["service"], banner_text)
            console.print(table)
        else:
            console.print("[bold yellow][!] Aucun port usuel ouvert detecte.[/bold yellow]")

        return {
            "target": self.target,
            "ip": dns_data["ip"],
            "hostname": dns_data["hostname"],
            "open_ports_count": len(open_services),
            "services": open_services,
            "scan_duration_sec": duration
        }