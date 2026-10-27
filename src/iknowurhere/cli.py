"""Command line interface for IknoWurHeRe."""

from __future__ import annotations

import argparse
import asyncio
import csv
import json
import sys
from dataclasses import asdict
from pathlib import Path

from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.text import Text

from .scanner import Device, ScanResult, scan, validate_network

LOGO = r""" _____ _                     _ _ _ _      _    _         _____
|_   _| |                   | | | | |    | |  | |       |  __ \
  | | | | ___ __   ___  __ _| | | | |    | |  | |_ __   | |__) |
  | | | |/ / '_ \ / _ \/ _` | | | | |    | |  | | '__|  |  _  /
 _| |_|   <| | | | (_) | (_| |_|_|_|_|    \ \_/ /| |    | | \ \\
|_____|_|\_|_| |_|\___/ \__, (_|_|_|_)     \___/ |_|    |_|  \_\
                         __/ |
                        |___/"""


def _table(devices: list[Device], network: str) -> Table:
    table = Table(title=f"IknoWurHeRe  •  {network}", header_style="bold cyan", border_style="blue")
    table.add_column("Status", justify="center")
    table.add_column("IP address", style="bold")
    table.add_column("MAC address")
    table.add_column("Hostname")
    table.add_column("Discovered by", style="magenta")
    for device in devices:
        table.add_row(Text("● Online", style="green"), device.ip, device.mac or "—",
                      device.hostname or "—", device.source)
    return table


def write_report(devices: list[Device], path: Path) -> None:
    """Write a JSON or CSV inventory report."""
    rows = [asdict(device) for device in devices]
    if path.suffix.lower() == ".csv":
        with path.open("w", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(file, fieldnames=["ip", "mac", "hostname", "source", "status"])
            writer.writeheader()
            writer.writerows(rows)
    elif path.suffix.lower() == ".json":
        path.write_text(json.dumps(rows, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    else:
        raise ValueError("Report filename must end in .json or .csv")


async def _run(args: argparse.Namespace, console: Console) -> int:
    try:
        network = validate_network(args.network)
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        return 2

    console.print(f"[bold cyan]{LOGO}[/bold cyan]\n")
    console.print(f"Scanning [bold]{network}[/bold] using ICMP ping and active ARP…")
    with Live(Text("Preparing scan…", style="cyan"), console=console, refresh_per_second=8, transient=False) as live:
        try:
            result: ScanResult = await scan(str(network), concurrency=args.concurrency, timeout=args.timeout)
        except (RuntimeError, OSError, ValueError) as exc:
            console.print(f"[red]Scan failed:[/red] {exc}")
            return 1
        live.update(_table(result.devices, str(network)))

    if result.warning:
        console.print(f"[yellow]ARP notice:[/yellow] {result.warning}")
        console.print("Continuing with ping results; rerun with the required permissions for full ARP discovery.")
    console.print(f"\n[bold]{len(result.devices)}[/bold] device(s) discovered.")
    if args.output:
        try:
            write_report(result.devices, Path(args.output))
        except (OSError, ValueError) as exc:
            console.print(f"[red]Could not write report:[/red] {exc}")
            return 1
        console.print(f"Report saved to [green]{args.output}[/green]")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="IknoWurHeRe", description="Discover devices on an authorized private local IPv4 network."
    )
    parser.add_argument("network", help="Authorized private CIDR, e.g. 192.168.8.0/24")
    parser.add_argument("-o", "--output", help="Save report as .json or .csv")
    parser.add_argument("--timeout", type=float, default=0.8, help="Per-host timeout in seconds (default: 0.8)")
    parser.add_argument("--concurrency", type=int, default=64, help="Maximum simultaneous pings (default: 64)")
    parser.add_argument("--no-animation", action="store_true", help="Use a static display")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    if args.timeout <= 0 or args.concurrency < 1 or args.concurrency > 256:
        parser.error("--timeout must be positive and --concurrency must be between 1 and 256")
    try:
        code = asyncio.run(_run(args, Console()))
    except KeyboardInterrupt:
        Console().print("\n[yellow]Scan cancelled.[/yellow]")
        code = 130
    sys.exit(code)


if __name__ == "__main__":
    main()
