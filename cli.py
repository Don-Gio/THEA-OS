import typer
from rich.console import Console

app = typer.Typer(help="THEA-OS - Central Security & Intelligence Framework")
engine_app = typer.Typer(help="Gestion et execution des moteurs THEA")
app.add_typer(engine_app, name="engine")

console = Console()

@engine_app.command("run")
def run_engine(engine_name: str, target: str):
    """Execute un moteur specifique (network, web, osint)."""
    engine_name = engine_name.lower().strip()
    
    if engine_name == "network":
        from engines.network.engine import NetworkEngine
        eng = NetworkEngine(target)
        eng.run_full_scan()

    elif engine_name == "web":
        from engines.web.engine import WebEngine
        eng = WebEngine(target)
        eng.run_full_scan()

    elif engine_name == "osint":
        from engines.osint.engine import OSINTEngine
        eng = OSINTEngine(target)
        eng.run_full_scan()

    else:
        console.print(f"[bold red][!] Moteur inconnu : '{engine_name}'[/bold red]")
        console.print("[yellow]Moteurs disponibles : network, web, osint[/yellow]")

if __name__ == "__main__":
    app()