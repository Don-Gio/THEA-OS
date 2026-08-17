import time
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from .fuzzers.headers import analyze_headers
from .fuzzers.dir_fuzz import fuzz_directories

console = Console()

class WebEngine:
    def __init__(self, target):
        if not target.startswith("http://") and not target.startswith("https://"):
            self.target = "http://" + target
        else:
            self.target = target

    def run_full_scan(self):
        start_time = time.time()

        console.print(Panel(
            f"[bold cyan]Cible Web :[/bold cyan] [bold yellow]{self.target}[/bold yellow]",
            title="[bold red]THEA-OS - ENGINE WEB & FUZZING[/bold red]",
            subtitle="[dim]Web Audit & Path Discovery[/dim]",
            expand=False
        ))

        # 1. Analyse des en-tetes
        with console.status("[bold green]Analyse des en-tetes & Stack Tech...", spinner="dots"):
            header_res = analyze_headers(self.target)

        if "error" in header_res:
            console.print(f"[bold red][!] Echec de connexion : {header_res['error']}[/bold red]")
            return None

        console.print(f"  [bold green][+][/bold green] [bold white]Serveur HTTP :[/bold white] {header_res['server']}")
        console.print(f"  [bold green][+][/bold green] [bold white]Techno       :[/bold white] {header_res['powered_by']}")
        console.print(f"  [bold green][+][/bold green] [bold white]En-tetes Securite Presents  :[/bold white] {len(header_res['present_security_headers'])}")
        console.print(f"  [bold yellow][!][/bold yellow] [bold white]En-tetes Securite Manquants :[/bold white] {len(header_res['missing_security_headers'])}\n")

        # 2. Fuzzing de rÃ©pertoires
        with console.status("[bold cyan]Fuzzing des chemins & repertoires caches...", spinner="bouncingBar"):
            discovered_paths = fuzz_directories(self.target)

        duration = round(time.time() - start_time, 2)

        # 3. Affichage des rÃ©sultats
        table = Table(
            title=f"\n[bold gold1]DECOUVERTES FUZZING ({duration}s)[/bold gold1]",
            header_style="bold magenta",
            border_style="bright_blue"
        )
        table.add_column("CHEMIN", style="cyan")
        table.add_column("CODE HTTP", style="bold green", justify="center")
        table.add_column("TAILLE (octets)", style="white", justify="right")

        if discovered_paths:
            for p in discovered_paths:
                status_style = "bold green" if p["status"] == 200 else "bold yellow"
                table.add_row(p["path"], f"[{status_style}]{p['status']}[/{status_style}]", str(p["length"]))
            console.print(table)
        else:
            console.print("[bold yellow][!] Aucun dossier ou fichier sensible detecte.[/bold yellow]")

        return {
            "target": self.target,
            "headers": header_res,
            "paths": discovered_paths,
            "scan_duration_sec": duration
        }