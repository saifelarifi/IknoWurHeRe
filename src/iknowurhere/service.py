"""Application services that join discovery, network state, and persistence."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from dataclasses import dataclass

from .database import Alert, DeviceStore
from .monitor import current_dns_servers, current_gateway
from .scanner import Device, ScanResult, scan, validate_network

COMMON_TCP_PORTS = (21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 5432, 8080, 8443)


@dataclass(frozen=True, slots=True)
class RecordedScan:
    devices: list[Device]
    alerts: list[Alert]
    warning: str | None
    gateway: str | None
    dns_servers: list[str]


async def scan_and_record(
    network: str,
    store: DeviceStore,
    *,
    concurrency: int = 64,
    timeout: float = 0.8,
    interface: str | None = None,
    trusted_gateway: set[str] | None = None,
    trusted_dns: set[str] | None = None,
) -> RecordedScan:
    """Run an authorized subnet scan, update inventory, and compare local config."""
    result: ScanResult = await scan(
        network, concurrency=concurrency, timeout=timeout, interface=interface
    )
    gateway = current_gateway()
    dns_servers = current_dns_servers()
    alerts: list[Alert] = []

    for device in result.devices:
        alerts.extend(store.observe_device(device, gateway_ip=gateway, scope=network))
    if gateway:
        alerts.extend(store.observe_network_state(
            "gateway", gateway, scope=network, expected=trusted_gateway
        ))
    if dns_servers:
        alerts.extend(store.observe_network_state(
            "dns", dns_servers, scope=network, expected=trusted_dns
        ))
    return RecordedScan(result.devices, alerts, result.warning, gateway, dns_servers)


async def quick_port_scan(network: str, address: str, *, timeout: float = 0.5) -> list[dict[str, int | str]]:
    """Check fixed common TCP ports on one discovered host without sending payloads."""
    subnet = validate_network(network)
    target = ipaddress.ip_address(address)
    if not isinstance(subnet, ipaddress.IPv4Network) or not isinstance(target, ipaddress.IPv4Address):
        raise ValueError("Quick port scan supports IPv4 hosts only")
    if target not in subnet or target not in subnet.hosts():
        raise ValueError("Target must be a usable host address inside the monitored network")

    semaphore = asyncio.Semaphore(6)

    async def probe(port: int) -> dict[str, int | str] | None:
        async with semaphore:
            writer = None
            try:
                _reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(str(target), port), timeout=timeout
                )
                try:
                    service = socket.getservbyport(port, "tcp")
                except OSError:
                    service = "unknown"
                return {"port": port, "service": service, "state": "open"}
            except (TimeoutError, OSError):
                return None
            finally:
                if writer is not None:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except OSError:
                        pass

    results = await asyncio.gather(*(probe(port) for port in COMMON_TCP_PORTS))
    return [result for result in results if result is not None]
