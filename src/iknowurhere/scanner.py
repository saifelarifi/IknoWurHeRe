"""Bounded async discovery on an authorized private IPv4 subnet."""

from __future__ import annotations

import asyncio
import ipaddress
import platform
import re
import shutil
import socket
from dataclasses import dataclass

MAC_RE = re.compile(r"(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}")
PRIVATE_NETWORKS = tuple(map(ipaddress.ip_network, ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")))


@dataclass(frozen=True, slots=True)
class Device:
    ip: str
    mac: str | None
    hostname: str | None
    source: str
    status: str = "online"


@dataclass(frozen=True, slots=True)
class ScanResult:
    devices: list[Device]
    warning: str | None = None


def validate_network(value: str, max_hosts: int = 256) -> ipaddress.IPv4Network:
    """Accept RFC 1918 IPv4 networks only, with a strict address-count limit."""
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise ValueError(f"Invalid network: {value}") from exc
    if not isinstance(network, ipaddress.IPv4Network):
        raise ValueError("Only IPv4 networks are supported")
    if not any(network.subnet_of(private) for private in PRIVATE_NETWORKS):
        raise ValueError("Only RFC 1918 private IPv4 networks are allowed")
    if network.num_addresses > max_hosts:
        raise ValueError(f"Network is too large ({network.num_addresses} addresses); limit is {max_hosts}")
    return network


async def _ping(ip: str, semaphore: asyncio.Semaphore, timeout: float) -> bool:
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(max(1, int(timeout * 1000))), ip]
    elif system == "darwin":
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout * 1000))), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout))), ip]
    async with semaphore:
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL
            )
            return await asyncio.wait_for(proc.wait(), timeout=timeout + 1) == 0
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return False


def _arp_sweep_sync(network: str, timeout: float) -> dict[str, str]:
    """Send layer-2 ARP requests with Scapy. Requires raw-socket privileges."""
    try:
        from scapy.all import ARP, Ether, srp
        from scapy.error import Scapy_Exception
    except ImportError as exc:
        raise RuntimeError("Scapy is missing. Reinstall IknoWurHeRe with its project dependencies.") from exc
    try:
        answered, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network), timeout=timeout, retry=0, verbose=0)
    except (OSError, PermissionError, Scapy_Exception) as exc:
        raise RuntimeError(
            "Active ARP needs permission to use raw network sockets. On Linux, run with sudo or grant the "
            "Python interpreter CAP_NET_RAW; on Windows use an elevated terminal and install Npcap."
        ) from exc
    return {str(received.psrc): str(received.hwsrc).lower() for _, received in answered}


async def _arp_sweep(network: str, timeout: float) -> dict[str, str]:
    return await asyncio.to_thread(_arp_sweep_sync, network, timeout)


async def _neighbor_table() -> dict[str, str]:
    """Read cached neighbors as a fallback MAC source for ping responders."""
    system = platform.system().lower()
    commands = [["arp", "-a"]] if system in {"windows", "darwin"} else [["ip", "neigh", "show"], ["arp", "-an"]]
    for cmd in commands:
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
            )
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=3)
            found: dict[str, str] = {}
            for line in out.decode(errors="replace").splitlines():
                ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
                mac_match = MAC_RE.search(line)
                if ip_match and mac_match:
                    found[ip_match.group()] = mac_match.group().replace("-", ":").lower()
            if found:
                return found
        except (OSError, asyncio.TimeoutError):
            continue
    return {}


async def _hostname(ip: str) -> str | None:
    try:
        return (await asyncio.wait_for(asyncio.to_thread(socket.gethostbyaddr, ip), 1))[0]
    except (OSError, asyncio.TimeoutError):
        return None


async def scan(network: str, *, concurrency: int = 64, timeout: float = 0.8) -> ScanResult:
    """Discover hosts with ICMP and active ARP; no ports are scanned.

    Use only on a network you own or are authorized to inventory. Active ARP
    may require elevated privileges; ping discovery remains available as fallback.
    """
    subnet = validate_network(network)
    if shutil.which("ping") is None:
        raise RuntimeError("The system 'ping' command was not found. Install ping (iputils on Linux) and try again.")

    semaphore = asyncio.Semaphore(concurrency)
    hosts = [str(ip) for ip in subnet.hosts()]
    ping_results = await asyncio.gather(*(_ping(ip, semaphore, timeout) for ip in hosts))
    ping_active = {ip for ip, is_up in zip(hosts, ping_results) if is_up}

    warning = None
    try:
        arp_neighbors = await _arp_sweep(str(subnet), timeout)
    except RuntimeError as exc:
        arp_neighbors = {}
        warning = str(exc)
    cached_neighbors = await _neighbor_table()
    found_ips = ping_active | set(arp_neighbors)
    names = await asyncio.gather(*(_hostname(ip) for ip in found_ips))
    devices = []
    for ip, hostname in zip(found_ips, names):
        source = "PING+ARP" if ip in ping_active and ip in arp_neighbors else "PING" if ip in ping_active else "ARP"
        devices.append(Device(ip, arp_neighbors.get(ip) or cached_neighbors.get(ip), hostname, source))
    devices.sort(key=lambda device: ipaddress.ip_address(device.ip))
    return ScanResult(devices, warning)
