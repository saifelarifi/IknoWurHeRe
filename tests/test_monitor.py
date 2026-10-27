import sys
from types import ModuleType, SimpleNamespace

import pytest

from iknowurhere.monitor import PassiveEvent, PassiveMonitor, _decode_packet, persist_passive_event
from iknowurhere.database import DeviceStore


@pytest.fixture
def fake_scapy(monkeypatch):
    scapy = ModuleType("scapy")
    scapy.__path__ = []
    layers = ModuleType("scapy.layers")
    layers.__path__ = []
    l2 = ModuleType("scapy.layers.l2")
    inet = ModuleType("scapy.layers.inet")
    dhcp = ModuleType("scapy.layers.dhcp")
    l2.ARP = type("ARP", (), {})
    inet.UDP = type("UDP", (), {})
    inet.IP = type("IP", (), {})
    dhcp.BOOTP = type("BOOTP", (), {})
    dhcp.DHCP = type("DHCP", (), {})
    for name, module in {
        "scapy": scapy,
        "scapy.layers": layers,
        "scapy.layers.l2": l2,
        "scapy.layers.inet": inet,
        "scapy.layers.dhcp": dhcp,
    }.items():
        monkeypatch.setitem(sys.modules, name, module)
    return SimpleNamespace(ARP=l2.ARP, UDP=inet.UDP, IP=inet.IP, BOOTP=dhcp.BOOTP, DHCP=dhcp.DHCP)


class FakePacket:
    def __init__(self, layers):
        self.layers = layers

    def haslayer(self, layer_type):
        return layer_type in self.layers

    def __getitem__(self, layer_type):
        return self.layers[layer_type]


def test_monitor_skips_capture_when_permissions_are_missing(monkeypatch):
    import iknowurhere.monitor as monitor_module

    monkeypatch.setattr(monitor_module, "passive_capture_permission", lambda: (False, "need CAP_NET_RAW"))
    monitor = PassiveMonitor("mock0")
    assert monitor.start() == "need CAP_NET_RAW"
    assert monitor._thread is None


def test_passive_arp_reply_is_reduced_to_identity_metadata(fake_scapy):
    packet = FakePacket({fake_scapy.ARP: SimpleNamespace(
        op=2, psrc="192.168.8.44", hwsrc="aa:bb:cc:dd:ee:44", pdst="192.168.8.1"
    )})
    event = _decode_packet(packet)
    assert event == PassiveEvent("arp", ip="192.168.8.44", mac="aa:bb:cc:dd:ee:44")


def test_passive_dhcp_offer_reports_server_address_only(fake_scapy):
    packet = FakePacket({
        fake_scapy.UDP: SimpleNamespace(),
        fake_scapy.BOOTP: SimpleNamespace(),
        fake_scapy.DHCP: SimpleNamespace(options=[
            ("message-type", "offer"), ("server_id", "192.168.8.1"), "end"
        ]),
    })
    assert _decode_packet(packet) == PassiveEvent("dhcp", value="192.168.8.1")


def test_optional_traffic_monitor_keeps_only_ip_byte_counters(fake_scapy):
    monitor = PassiveMonitor("mock0", traffic_enabled=True)
    packet = FakePacket({fake_scapy.IP: SimpleNamespace(
        src="192.168.8.7", dst="192.168.8.1", len=128
    )})
    monitor._on_packet(packet)
    assert monitor.traffic_snapshot() == {
        "192.168.8.7": {"source_bytes": 128, "destination_bytes": 0},
        "192.168.8.1": {"source_bytes": 0, "destination_bytes": 128},
    }


def test_persist_passive_arp_observation():
    with DeviceStore(":memory:") as store:
        alerts = persist_passive_event(
            store,
            PassiveEvent("arp", ip="192.168.8.4", mac="aa:bb:cc:dd:ee:04"),
            scope="192.168.8.0/24",
            gateway_ip="192.168.8.1",
        )
        assert alerts[0].event_type == "new_device"
        assert store.list_devices()[0].source == "PASSIVE_ARP"


def test_persist_unapproved_dhcp_offer():
    with DeviceStore(":memory:") as store:
        alerts = persist_passive_event(
            store,
            PassiveEvent("dhcp", value="192.168.8.99"),
            scope="192.168.8.0/24",
            gateway_ip="192.168.8.1",
            trusted_dhcp={"192.168.8.1"},
        )
        assert alerts[0].event_type == "unexpected_dhcp_server"
