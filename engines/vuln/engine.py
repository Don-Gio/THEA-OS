import time
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from .cve_lookup import parse_service_query, fetch_cves_circl
from recon.scanners.network import scan_target
from recon.scanners.dns_recon import resolve_target

console = Console()

class VulnEngine:
    def __init__(self, target):
        self.target = target.strip()

    def run_full_scan(self):
        start_time = time.time()

        console.print(Panel(
            f"[bold cyan]Cible Audit CVE :[/bold cyan] [bold yellow]{self.target}[/bold yellow]",
            title="[bold red]THEA-OS - ENGINE VULN & CVE[/bold red]",
            subtitle="[dim]Automated Vulnerability & CVE Intelligence[/dim]",
            expand=False
        ))

        targets_to_audit = []

        # Verification : hote/IP ou recherche directe ?
        if "." in self.target and " " not in self.target:
            with console.status("[bold green]Analyse des services actifs sur la cible...", spinner="dots"):
                dns_data = resolve_target(self.target)
                ip = dns_data.get("ip")
                if ip:
                    open_ports = scan_target(ip)
                    for p in open_ports:
                        if p.get("banner"):
                            targets_to_audit.append((p["service"], p["banner"]))
                        else:
                            targets_to_audit.append((p["service"], f"{p['service']} port {p['port']}"))

        if not targets_to_audit:
            targets_to_audit.append(("Custom Query", self.target))

        total_cves_found = 0

        for service_name, banner in targets_to_audit:
            query_keyword = parse_service_query(banner)
            console.print(f"\n  [bold cyan][+][/bold cyan] Audit de la banniere : [bold white]{banner}[/bold white]")
            
            with console.status(f"[bold green]Recherche CVE pour '{query_keyword}'...", spinner="bouncingBar"):
                cves = fetch_cves_circl(query_keyword)

            table = Table(
                title=f"[bold gold1]VULNERABILITES & CVEs ({service_name})[/bold gold1]",
                header_style="bold magenta",
                border_style="bright_blue"
            )
            table.add_column("CVE ID", style="bold red", width=16)
            table.add_column("CVSS", style="bold yellow", justify="center", width=8)
            table.add_column("DESCRIPTION / RESUME", style="white")

            if cves:
                total_cves_found += len(cves)
                for c in cves:
                    cvss_val = c['cvss']
                    try:
                        score = float(cvss_val)
                        if score >= 7.0:
                            cvss_style = "bold red"
                        elif score >= 4.0:
                            cvss_style = "bold yellow"
                        else:
                            cvss_style = "bold green"
                    except ValueError:
                        cvss_style = "white"

                    table.add_row(c['id'], f"[{cvss_style}]{cvss_val}[/{cvss_style}]", c['summary'])
                console.print(table)
            else:
                console.print("    [bold yellow][!] Aucune CVE connue n'a ete retournee pour cette banniere.[/bold yellow]")

        duration = round(time.time() - start_time, 2)
        console.print(f"\n[bold green][+] Audit de vulnerabilites termine en {duration}s. Total CVEs identifiees : {total_cves_found}[/bold green]\n")

        return {
            "target": self.target,
            "total_cves": total_cves_found,
            "scan_duration_sec": duration
        }