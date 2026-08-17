import time
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from .modules.dns_whois import get_dns_records, get_ip_intel
from .modules.subdomains import fetch_crtsh_subdomains

console = Console()

class OSINTEngine:
    def __init__(self, target):
        # Nettoyage du nom de domaine
        target = target.replace("http://", "").replace("https://", "").split("/")[0]
        self.target = target

    def run_full_scan(self):
        start_time = time.time()

        console.print(Panel(
            f"[bold cyan]Cible OSINT :[/bold cyan] [bold yellow]{self.target}[/bold yellow]",
            title="[bold red]THEA-OS - ENGINE OSINT & RECON[/bold red]",
            subtitle="[dim]Passive Intelligence & Asset Discovery[/dim]",
            expand=False
        ))

        # 1. RÃ©solution DNS
        with console.status("[bold green]Collecte des enregistrements DNS & IP...", spinner="dots"):
            dns_info = get_dns_records(self.target)

        if "error" in dns_info:
            console.print(f"[bold red][!] Resolution impossible pour {self.target} : {dns_info['error']}[/bold red]")
            return None

        ips = dns_info.get("ip_addresses", [])
        console.print(f"  [bold green][+][/bold green] [bold white]IP associees :[/bold white] {', '.join(ips)}")

        # 2. IP Intelligence (Sur la premiÃ¨re IP)
        if ips:
            primary_ip = ips[0]
            with console.status(f"[bold green]Recherche d'informations ASN/GeoIP sur {primary_ip}...", spinner="dots"):
                intel = get_ip_intel(primary_ip)

            if intel:
                console.print(f"  [bold green][+][/bold green] [bold white]Localisation :[/bold white] {intel.get('city')}, {intel.get('country')}")
                console.print(f"  [bold green][+][/bold green] [bold white]ISP / FAI    :[/bold white] {intel.get('isp')}")
                console.print(f"  [bold green][+][/bold green] [bold white]ASN          :[/bold white] {intel.get('as')}\n")

        # 3. Enumeration des sous-domaines via Certificate Transparency
        with console.status("[bold cyan]Enumeration des sous-domaines (crt.sh)...", spinner="bouncingBar"):
            subs = fetch_crtsh_subdomains(self.target)

        duration = round(time.time() - start_time, 2)

        # Affichage du tableau de sous-domaines
        table = Table(
            title=f"\n[bold gold1]SOUS-DOMAINES DECOUVERTS ({len(subs)}) - [{duration}s][/bold gold1]",
            header_style="bold magenta",
            border_style="bright_blue"
        )
        table.add_column("NÂ°", style="dim", width=4)
        table.add_column("SOUS-DOMAINE", style="cyan")

        if subs:
            for idx, sub in enumerate(subs[:15], 1): # LimitÃ© aux 15 premiers affichÃ©s
                table.add_row(str(idx), sub)
            console.print(table)
            if len(subs) > 15:
                console.print(f"[dim]... et {len(subs) - 15} autres sous-domaines caches.[/dim]")
        else:
            console.print("[bold yellow][!] Aucun sous-domaine public trouve.[/bold yellow]")

        return {
            "target": self.target,
            "dns": dns_info,
            "subdomains": subs,
            "scan_duration_sec": duration
        }