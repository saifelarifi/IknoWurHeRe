"""Typer command suite for IknoWurHeRe."""

from __future__ import annotations

import asyncio
import csv
import ipaddress
import json
import secrets
import time
from dataclasses import asdict
from pathlib import Path
from queue import Empty
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from .database import Alert, DeviceRecord, DeviceStore, default_database_path
from .monitor import PassiveMonitor, available_interfaces, current_gateway, passive_capture_permission, persist_passive_event
from .scanner import Device, validate_interface, validate_network
from .service import RecordedScan, scan_and_record

app = typer.Typer(no_args_is_help=True, help="Defensive local network inventory and change monitoring.")
console = Console()
LOGO = r""" _____ _                     _ _ _ _      _    _         _____
|_   _| |                   | | | | |    | |  | |       |  __ \
  | | | | ___ __   ___  __ _| | | | |    | |  | |_ __   | |__) |
  | | | |/ / '_ \ / _ \/ _` | | | | |    | |  | | '__|  |  _  /
 _| |_|   <| | | | (_) | (_| |_|_|_|_|    \ \_/ /| |    | | \\
|_____|_|\_|_| |_|\___/ \__, (_|_|_|_)     \___/ |_|    |_|  \_\
                         __/ |
                        |___/"""


def _devices_table(devices: list[Device] | list[DeviceRecord], *, history: bool = False) -> Table:
    table = Table(title="IknoWurHeRe • Device inventory", header_style="bold cyan", border_style="blue")
    table.add_column("Status", justify="center")
    table.add_column("IP", style="bold")
    table.add_column("MAC")
    table.add_column("Vendor")
    table.add_column("Hostname")
    table.add_column("Source", style="magenta")
    if history:
        table.add_column("Network scope")
        table.add_column("First seen")
        table.add_column("Last seen")
    for device in devices:
        device_status = getattr(device, "status", "online")
        status_color = "green" if device_status in {"online", "recent"} else "yellow" if device_status == "stale" else "dim"
        table.add_row(
            Text(f"● {device_status.title()}", style=status_color), device.ip, device.mac or "—", device.vendor or "—",
            device.hostname or "—", device.source,
            *([device.scope, device.first_seen, device.last_seen] if history else []),
        )
    return table


def _alert_table(alerts: list[Alert]) -> Table:
    table = Table(title="Defensive alerts", header_style="bold yellow", border_style="yellow")
    table.add_column("When")
    table.add_column("Type", style="bold")
    table.add_column("Confidence", justify="right")
    table.add_column("Address")
    table.add_column("Reason", max_width=72)
    for alert in alerts:
        table.add_row(alert.observed_at, alert.event_type, f"{alert.confidence:.0%}", alert.ip or "network", alert.reason)
    return table


def _print_summary(summary: RecordedScan) -> None:
    console.print(_devices_table(summary.devices))
    console.print(f"[bold]{len(summary.devices)}[/bold] device(s) recorded.")
    if summary.gateway:
        console.print(f"Gateway: [cyan]{summary.gateway}[/cyan]   DNS: [cyan]{', '.join(summary.dns_servers) or 'unknown'}[/cyan]")
    if summary.warning:
        console.print(f"[yellow]Discovery notice:[/yellow] {summary.warning}")
    if summary.alerts:
        console.print(_alert_table(summary.alerts))


def _parse_csv_set(value: Optional[str]) -> set[str] | None:
    if not value:
        return None
    return {item.strip() for item in value.split(",") if item.strip()}


def _validated_subnet(value: str) -> str:
    try:
        return str(validate_network(value))
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc


def write_report(devices: list[Device] | list[DeviceRecord], path: Path) -> None:
    """Write a current or historical device report as JSON or CSV."""
    rows = [asdict(device) for device in devices]
    if path.suffix.lower() == ".csv":
        fields = list(rows[0]) if rows else ["ip", "mac", "hostname", "source", "status", "vendor"]
        with path.open("w", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(file, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)
    elif path.suffix.lower() == ".json":
        path.write_text(json.dumps(rows, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    else:
        raise ValueError("Report filename must end in .json or .csv")


def write_alert_report(alerts: list[Alert], path: Path) -> None:
    rows = [asdict(alert) for alert in alerts]
    if path.suffix.lower() == ".csv":
        fields = list(rows[0]) if rows else ["event_type", "reason", "confidence", "ip", "previous_mac", "current_mac", "observed_at", "previous_value", "current_value", "scope"]
        with path.open("w", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(file, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)
    elif path.suffix.lower() == ".json":
        path.write_text(json.dumps(rows, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    else:
        raise ValueError("Report filename must end in .json or .csv")


def write_state_report(states: list[dict], path: Path) -> None:
    rows = states
    if path.suffix.lower() == ".csv":
        fields = list(rows[0]) if rows else ["scope", "key", "value", "observed_at"]
        with path.open("w", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(file, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)
    elif path.suffix.lower() == ".json":
        path.write_text(json.dumps(rows, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    else:
        raise ValueError("Report filename must end in .json or .csv")


@app.command("scan")
def scan_command(
    network: str = typer.Argument(..., help="Authorized private IPv4 CIDR, e.g. 192.168.8.0/24"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Save current scan as .json or .csv"),
    database: Path = typer.Option(default_database_path(), "--database", help="SQLite history database"),
    timeout: float = typer.Option(0.8, min=0.1, max=10.0, help="Per-host ping timeout in seconds"),
    concurrency: int = typer.Option(64, min=1, max=256, help="Maximum concurrent ping requests"),
    interface: Optional[str] = typer.Option(None, help="Interface for active ARP discovery"),
    trusted_gateway: Optional[str] = typer.Option(None, help="Expected gateway IPv4 address"),
    trusted_dns: Optional[str] = typer.Option(None, help="Comma-separated expected DNS addresses"),
) -> None:
    """Run one authorized scan and save device/network history."""
    subnet = _validated_subnet(network)
    try:
        interface = validate_interface(interface)
    except ValueError as exc:
        raise typer.BadParameter(str(exc), param_hint="--interface") from exc
    console.print(f"[bold cyan]{LOGO}[/bold cyan]\nScanning {subnet}…")
    try:
        with DeviceStore(database) as store:
            summary = asyncio.run(scan_and_record(
                subnet, store, timeout=timeout, concurrency=concurrency, interface=interface,
                trusted_gateway=_parse_csv_set(trusted_gateway), trusted_dns=_parse_csv_set(trusted_dns),
            ))
            _print_summary(summary)
            if output:
                write_report(summary.devices, output)
                console.print(f"Report saved: [green]{output}[/green]")
    except (RuntimeError, OSError, ValueError) as exc:
        console.print(f"[red]Scan failed:[/red] {exc}")
        raise typer.Exit(1) from exc


@app.command("devices")
def devices_command(
    database: Path = typer.Option(default_database_path(), "--database", help="SQLite history database"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Export historical devices as .json or .csv"),
) -> None:
    """List previously observed devices and first/last seen times."""
    with DeviceStore(database) as store:
        devices = store.list_devices()
        console.print(_devices_table(devices, history=True))
        if output:
            write_report(devices, output)
            console.print(f"Historical device report saved: [green]{output}[/green]")


@app.command("alerts")
def alerts_command(
    database: Path = typer.Option(default_database_path(), "--database", help="SQLite history database"),
    limit: int = typer.Option(100, min=1, max=5000, help="Maximum number of alerts"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Export alert history as .json or .csv"),
) -> None:
    """Show saved network-change and defensive alerts."""
    with DeviceStore(database) as store:
        alerts = store.list_alerts(limit=limit)
        console.print(_alert_table(alerts))
        if output:
            write_alert_report(alerts, output)
            console.print(f"Alert report saved: [green]{output}[/green]")


@app.command("interfaces")
def interfaces_command() -> None:
    """List interfaces available for passive observation."""
    table = Table(title="Network interfaces", header_style="bold cyan")
    table.add_column("Interface")
    table.add_column("Default route")
    from .monitor import current_interface

    default = current_interface()
    interfaces = available_interfaces()
    for interface in interfaces:
        table.add_row(interface, "●" if interface == default else "")
    if not interfaces:
        console.print("[yellow]No capture interfaces found. Check Scapy/Npcap installation.[/yellow]")
    else:
        console.print(table)


async def _watch(
    network: str, database: Path, interval: int, interface: Optional[str], trusted_dhcp: set[str] | None,
    trusted_gateway: set[str] | None, trusted_dns: set[str] | None,
) -> None:
    monitor = PassiveMonitor(interface)
    capture_warning = monitor.start()
    with DeviceStore(database) as store:
        console.print(f"Watching {network} every {interval}s. Press Ctrl+C to stop.")
        if interface:
            console.print(f"Passive ARP/DHCP interface: {interface}")
        if capture_warning:
            console.print(f"[yellow]Passive capture unavailable:[/yellow] {capture_warning}")
        try:
            while True:
                summary = await scan_and_record(
                    network, store, interface=interface,
                    trusted_gateway=trusted_gateway, trusted_dns=trusted_dns
                )
                _print_summary(summary)
                deadline = time.monotonic() + interval
                while time.monotonic() < deadline:
                    try:
                        event = monitor.events.get(timeout=min(1.0, max(0.1, deadline - time.monotonic())))
                    except Empty:
                        continue
                    if event.kind == "error":
                        console.print(f"[yellow]Passive monitor:[/yellow] {event.value}")
                        continue
                    alerts = persist_passive_event(
                        store, event, scope=network, gateway_ip=current_gateway(), trusted_dhcp=trusted_dhcp
                    )
                    if alerts:
                        console.print(_alert_table(alerts))
        except KeyboardInterrupt:
            console.print("\n[yellow]Watch stopped.[/yellow]")
        finally:
            monitor.stop()


@app.command("watch")
def watch_command(
    network: str = typer.Argument(..., help="Authorized private IPv4 CIDR"),
    database: Path = typer.Option(default_database_path(), "--database", help="SQLite history database"),
    interval: int = typer.Option(60, min=5, max=86400, help="Seconds between active inventory scans"),
    interface: Optional[str] = typer.Option(None, help="Interface for passive ARP/DHCP observation"),
    trusted_dhcp: Optional[str] = typer.Option(None, help="Comma-separated approved DHCP server IPs"),
    trusted_gateway: Optional[str] = typer.Option(None, help="Expected gateway IPv4 address"),
    trusted_dns: Optional[str] = typer.Option(None, help="Comma-separated expected DNS addresses"),
) -> None:
    """Continuously scan and passively observe ARP/DHCP metadata."""
    subnet = _validated_subnet(network)
    try:
        interface = validate_interface(interface)
    except ValueError as exc:
        raise typer.BadParameter(str(exc), param_hint="--interface") from exc
    try:
        asyncio.run(_watch(subnet, database, interval, interface, _parse_csv_set(trusted_dhcp),
                           _parse_csv_set(trusted_gateway), _parse_csv_set(trusted_dns)))
    except KeyboardInterrupt:
        console.print("\n[yellow]Watch stopped.[/yellow]")
    except (RuntimeError, OSError, ValueError) as exc:
        console.print(f"[red]Watch failed:[/red] {exc}")
        raise typer.Exit(1) from exc


@app.command("web")
def web_command(
    network: str = typer.Argument(..., help="Authorized private IPv4 CIDR"),
    database: Path = typer.Option(default_database_path(), "--database", help="SQLite history database"),
    host: str = typer.Option("0.0.0.0", help="Bind address; 0.0.0.0 allows LAN clients"),
    port: int = typer.Option(8787, min=1, max=65535),
    interval: int = typer.Option(60, min=5, max=86400, help="Seconds between scans"),
    interface: Optional[str] = typer.Option(None, help="Interface for passive ARP/DHCP observation"),
    traffic: bool = typer.Option(False, "--traffic", help="Opt in to packet-header byte counters by observed IP"),
    token: Optional[str] = typer.Option(None, help="Dashboard API token; generated automatically when omitted"),
    ssl_certfile: Optional[Path] = typer.Option(None, help="TLS certificate for non-loopback binds"),
    ssl_keyfile: Optional[Path] = typer.Option(None, help="TLS private key for non-loopback binds"),
    trusted_dhcp: Optional[str] = typer.Option(None, help="Comma-separated approved DHCP server IPs"),
    trusted_gateway: Optional[str] = typer.Option(None, help="Expected gateway IPv4 address"),
    trusted_dns: Optional[str] = typer.Option(None, help="Comma-separated expected DNS addresses"),
) -> None:
    """Serve the local web dashboard and update it with continuous monitoring."""
    subnet = _validated_subnet(network)
    try:
        interface = validate_interface(interface)
    except ValueError as exc:
        raise typer.BadParameter(str(exc), param_hint="--interface") from exc
    if interval < 5:
        raise typer.BadParameter("interval must be at least 5 seconds")
    if bool(ssl_certfile) != bool(ssl_keyfile):
        raise typer.BadParameter("provide both --ssl-certfile and --ssl-keyfile")
    if not token:
        token = secrets.token_urlsafe(32)
    if token and len(token) < 24:
        raise typer.BadParameter("dashboard token must be at least 24 characters")

    try:
        import uvicorn
        from .dashboard import create_dashboard_app
    except ImportError as exc:
        raise typer.BadParameter("Web dashboard dependencies missing. Reinstall with: pip install -e '.[dev]'") from exc

    if ssl_certfile and ssl_keyfile:
        certificate, private_key = ssl_certfile, ssl_keyfile
        generated = False
        certificate_names = {host}
    else:
        from .tls import ensure_dashboard_certificate, local_certificate_names

        certificate_names = local_certificate_names(interface)
        if host not in {"0.0.0.0", "::"}:
            certificate_names.add(host)
        tls_directory = default_database_path().parent / "tls"
        certificate, private_key, generated = ensure_dashboard_certificate(tls_directory, certificate_names)
    urls: set[str] = set()
    if host in {"0.0.0.0", "::"}:
        urls.add(f"https://127.0.0.1:{port}")
        for name in certificate_names:
            try:
                address = ipaddress.ip_address(name)
            except ValueError:
                continue
            if address.is_private and not address.is_loopback and not address.is_link_local:
                urls.add(f"https://[{name}]:{port}" if address.version == 6 else f"https://{name}:{port}")
    else:
        urls.add(f"https://[{host}]:{port}" if ":" in host else f"https://{host}:{port}")
    console.print("Dashboard addresses:")
    for url in sorted(urls):
        console.print(f"  [bold cyan]{url}[/bold cyan]")
    if generated:
        console.print(f"Self-signed TLS certificate created: [dim]{certificate}[/dim]")
        console.print("[yellow]Browsers may warn that this certificate is untrusted. HTTPS encrypts the connection; trusting the certificate requires a one-time manual trust step.[/yellow]")
    if host not in {"127.0.0.1", "localhost", "::1"}:
        console.print("[yellow]LAN access is enabled. Keep the token private and restrict the port with your firewall.[/yellow]")
    if token:
        console.print(f"Dashboard token (keep private): [bold yellow]{token}[/bold yellow]")
    permitted, capture_message = passive_capture_permission()
    if not permitted:
        console.print(f"[yellow]Passive ARP/DHCP monitoring unavailable:[/yellow] {capture_message}")
        console.print("The web dashboard and periodic inventory scans will continue.")
    if traffic:
        console.print("Traffic counters enabled: observed IPv4 headers only; visibility depends on the network interface/AP.")
    store = DeviceStore(database)
    dashboard = create_dashboard_app(
        subnet, store, interval=interval, interface=interface,
        trusted_dhcp=_parse_csv_set(trusted_dhcp), trusted_gateway=_parse_csv_set(trusted_gateway),
        trusted_dns=_parse_csv_set(trusted_dns), api_token=token, traffic_enabled=traffic,
    )
    try:
        uvicorn.run(
            dashboard, host=host, port=port, access_log=False,
            ssl_certfile=str(certificate),
            ssl_keyfile=str(private_key),
        )
    except KeyboardInterrupt:
        console.print("\n[yellow]Dashboard stopped.[/yellow]")


@app.command("export")
def export_command(
    output: Path = typer.Argument(..., help="Destination .json or .csv path"),
    kind: str = typer.Option("devices", "--kind", help="History type: devices, alerts, or network-state"),
    database: Path = typer.Option(default_database_path(), "--database", help="SQLite history database"),
    limit: int = typer.Option(1000, min=1, max=50000, help="Alert export row limit"),
) -> None:
    """Export historical device or alert records."""
    kind = kind.lower()
    if kind not in {"devices", "alerts", "network-state"}:
        raise typer.BadParameter("kind must be 'devices', 'alerts', or 'network-state'")
    with DeviceStore(database) as store:
        if kind == "devices":
            write_report(store.list_devices(), output)
        elif kind == "alerts":
            write_alert_report(store.list_alerts(limit=limit), output)
        else:
            states = [asdict(item) for item in store.list_network_state()]
            write_state_report(states, output)
    console.print(f"Exported {kind} history to [green]{output}[/green]")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
