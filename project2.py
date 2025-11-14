import time
import os
import subprocess
from rich.console import Console
from rich.table import Table

console = Console()

# Header
console.print("="*70, style="bold cyan")
console.print("        Python Network Firewall", style="bold green")
console.print("          Designed by Vidhyashalini R S", style="italic yellow")
console.print("="*70, style="bold cyan")
console.print("\nMonitoring live network packets...")
console.print("Press Ctrl + C to stop.\n", style="bold red")

def get_connections():
    """
    Uses Windows 'netstat -ano' to fetch live TCP/UDP connections.
    Safe and works without admin.
    """
    result = subprocess.run("netstat -ano", capture_output=True, text=True, shell=True)
    return result.stdout.splitlines()

while True:
    try:
        table = Table(title="Live Network Packet Monitor", style="bold magenta")
        table.add_column("Time")
        table.add_column("Status")
        table.add_column("Protocol")
        table.add_column("Source -> Destination")

        lines = get_connections()
        now = time.strftime("%H:%M:%S")

        found = False

        for line in lines:
            if "TCP" in line or "UDP" in line:
                parts = line.split()
                if len(parts) < 5:
                    continue

                proto = parts[0]
                src = parts[1]
                dst = parts[2]

                # Decide SAFE / UNSAFE / SUSPICIOUS
                if "127.0.0.1" in src or "127.0.0.1" in dst:
                    status = "[green]SAFE[/green]"
                elif ":443" in dst or ":80" in dst:
                    status = "[yellow]SUSPICIOUS[/yellow]"
                else:
                    status = "[red]UNSAFE[/red]"

                table.add_row(now, status, proto, f"{src} -> {dst}")
                found = True

        if not found:
            table.add_row(now, "[green]SAFE[/green]", "None", "No active connections")

        console.print(table)
        time.sleep(1)

    except KeyboardInterrupt:
        console.print("\n[bold red]Stopped by user.[/bold red]")
        break
