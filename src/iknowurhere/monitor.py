"""Passive metadata-only monitoring helpers for ARP and DHCP observations."""

from __future__ import annotations

import queue
import os
import platform
import socket
import sys
import threading
from dataclasses import dataclass

from .database import Alert, DeviceStore
from .scanner import Device


@dataclass(frozen=True, slots=True)
class PassiveEvent:
    kind: str
    ip: str | None = None
    mac: str | None = None
    value: str | None = None


def passive_capture_permission() -> tuple[bool, str | None]:
    """Check whether this process can open a passive packet-capture socket."""
    system = platform.system()
    if system == "Windows":
        try:
            import ctypes

            if ctypes.windll.shell32.IsUserAnAdmin():
                return True, None
        except (AttributeError, OSError):
            pass
        return False, "Passive ARP/DHCP capture needs an Administrator terminal and Npcap."

    if sys.platform.startswith("linux"):
        try:
            probe = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
            probe.close()
            return True, None
        except (AttributeError, OSError):
            return False, (
                "Passive ARP/DHCP capture is unavailable without CAP_NET_RAW. Run the command with sudo "
                "or grant CAP_NET_RAW to the Python interpreter. Inventory scans will continue."
            )

    if sys.platform == "darwin":
        if getattr(os, "geteuid", lambda: 1)() == 0 or any(
            os.access(f"/dev/bpf{index}", os.R_OK | os.W_OK) for index in range(256)
        ):
            return True, None
        return False, "Passive capture needs permission to open /dev/bpf devices; run with approved capture access. Inventory scans will continue."

    if getattr(os, "geteuid", lambda: 1)() == 0:
        return True, None
    return False, "Passive packet capture needs elevated capture permissions. Inventory scans will continue."


def current_interface() -> str | None:
    """Return the OS-selected default-route interface when Scapy can identify it."""
    try:
        from scapy.all import conf

        interface, _source, _gateway = conf.route.route("0.0.0.0")
        return str(interface) if interface else None
    except Exception:
        return None


def available_interfaces() -> list[str]:
    """Return interface names visible to Scapy, or an empty list if unavailable."""
    try:
        from scapy.all import get_if_list

        return sorted(set(get_if_list()))
    except Exception:
        return []


def current_gateway() -> str | None:
    """Read the OS route table through Scapy's cross-platform route adapter."""
    try:
        from scapy.all import conf

        _interface, _source, gateway = conf.route.route("0.0.0.0")
        return gateway if gateway not in (None, "0.0.0.0") else None
    except Exception:
        return None


def current_dns_servers() -> list[str]:
    """Read configured resolvers from the platform adapter, without querying them."""
    try:
        from scapy.all import conf

        return sorted({str(address) for address in conf.nameservers if address})
    except Exception:
        return []


def _decode_packet(packet) -> PassiveEvent | None:
    """Extract only ARP identity or DHCP server metadata; never retain payloads."""
    try:
        from scapy.layers.dhcp import BOOTP, DHCP
        from scapy.layers.l2 import ARP
        from scapy.layers.inet import UDP
    except ImportError:
        return None

    if packet.haslayer(ARP):
        arp = packet[ARP]
        # ARP replies contain an asserted IP-to-MAC mapping; requests are not
        # treated as proof that the sender owns the queried IP.
        if int(arp.op) == 2 and arp.psrc and arp.psrc != "0.0.0.0":
            return PassiveEvent("arp", ip=str(arp.psrc), mac=str(arp.hwsrc).lower())

    if packet.haslayer(UDP) and packet.haslayer(BOOTP) and packet.haslayer(DHCP):
        options = packet[DHCP].options
        message_type = next((option[1] for option in options if isinstance(option, tuple) and option[0] == "message-type"), None)
        server_id = next((option[1] for option in options if isinstance(option, tuple) and option[0] == "server_id"), None)
        # DHCP Offer (2) is an observation only; the tool does not transmit DHCP.
        if message_type in (2, "offer", b"\x02") and server_id:
            return PassiveEvent("dhcp", value=str(server_id))
    return None


class PassiveMonitor:
    """Queue passive ARP/DHCP observations from one selected interface."""

    def __init__(self, interface: str | None = None, *, traffic_enabled: bool = False) -> None:
        self.interface = interface or current_interface()
        self.traffic_enabled = traffic_enabled
        self._traffic_lock = threading.Lock()
        self._traffic: dict[str, dict[str, int]] = {}
        self.events: queue.Queue[PassiveEvent] = queue.Queue()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> str | None:
        if self._thread and self._thread.is_alive():
            return None
        permitted, message = passive_capture_permission()
        if not permitted:
            return message
        self._stop.clear()
        self._thread = threading.Thread(target=self._capture, name="iknowurhere-passive-monitor", daemon=True)
        self._thread.start()
        return None

    def _capture(self) -> None:
        try:
            from scapy.all import sniff
        except Exception as exc:
            self.events.put(PassiveEvent(
                "error",
                value=("Scapy packet capture could not initialize. Check Scapy/Npcap/libpcap and capture permissions: "
                       f"{exc}"),
            ))
            return
        try:
            while not self._stop.is_set():
                sniff(
                    iface=self.interface,
                    filter=("arp or (udp and (port 67 or port 68)) or ip" if self.traffic_enabled
                            else "arp or (udp and (port 67 or port 68))"),
                    prn=self._on_packet,
                    store=False,
                    timeout=1,
                )
        except Exception as exc:
            self._stop.set()
            self.events.put(PassiveEvent(
                "error",
                value=("Passive capture could not start. Check interface selection, capture permissions, "
                       f"and Npcap/libpcap availability: {exc}"),
            ))

    def _on_packet(self, packet) -> None:
        event = _decode_packet(packet)
        if event:
            self.events.put(event)
        if self.traffic_enabled:
            try:
                from scapy.layers.inet import IP

                if packet.haslayer(IP):
                    ip_packet = packet[IP]
                    size = int(ip_packet.len or len(packet))
                    with self._traffic_lock:
                        if ip_packet.src:
                            counters = self._traffic.setdefault(str(ip_packet.src), {"source_bytes": 0, "destination_bytes": 0})
                            counters["source_bytes"] += size
                        if ip_packet.dst:
                            counters = self._traffic.setdefault(str(ip_packet.dst), {"source_bytes": 0, "destination_bytes": 0})
                            counters["destination_bytes"] += size
            except Exception:
                # Traffic accounting is optional and must never disrupt ARP/DHCP monitoring.
                return

    def traffic_snapshot(self) -> dict[str, dict[str, int]]:
        """Return in-memory IP/byte counters; packet payloads are never retained."""
        with self._traffic_lock:
            return {address: counters.copy() for address, counters in self._traffic.items()}

    def stop(self, timeout: float = 2.0) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=timeout)


def persist_passive_event(
    store: DeviceStore,
    event: PassiveEvent,
    *,
    scope: str,
    gateway_ip: str | None,
    trusted_dhcp: set[str] | None = None,
) -> list[Alert]:
    """Persist one passive observation and return any resulting alerts."""
    if event.kind == "arp" and event.ip and event.mac:
        return store.observe_device(
            Device(event.ip, event.mac, None, "PASSIVE_ARP"),
            gateway_ip=gateway_ip,
            scope=scope,
        )
    if event.kind == "dhcp" and event.value:
        return store.observe_network_state(
            "dhcp", event.value, scope=scope, expected=trusted_dhcp
        )
    return []
