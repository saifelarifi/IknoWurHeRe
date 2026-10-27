import ipaddress
import json

import pytest

from iknowurhere.cli import write_report
from iknowurhere.scanner import Device, ScanResult, scan, validate_network


@pytest.mark.parametrize("value", ["192.168.8.0/24", "10.0.0.7/30", "172.16.0.0/28"])
def test_validate_private_ipv4(value):
    assert isinstance(validate_network(value), ipaddress.IPv4Network)


@pytest.mark.parametrize("value", ["8.8.8.0/24", "192.168.0.0/16", "127.0.0.0/24", "169.254.0.0/24", "2001:db8::/64", "not-a-network"])
def test_validate_rejects_outside_scope(value):
    with pytest.raises(ValueError):
        validate_network(value)


def test_validate_rejects_large_range():
    with pytest.raises(ValueError, match="too large"):
        validate_network("10.0.0.0/16")


def test_report_json_contains_discovery_source(tmp_path):
    path = tmp_path / "devices.json"
    write_report([Device("192.168.8.1", "aa:bb:cc:dd:ee:ff", None, "ARP")], path)
    assert json.loads(path.read_text())[0]["source"] == "ARP"


def test_report_csv_contains_discovery_source(tmp_path):
    path = tmp_path / "devices.csv"
    write_report([Device("192.168.8.1", None, "router", "PING")], path)
    assert "PING" in path.read_text()


def test_report_rejects_unknown_extension(tmp_path):
    with pytest.raises(ValueError, match=".json or .csv"):
        write_report([], tmp_path / "devices.txt")


@pytest.mark.asyncio
async def test_scan_merges_ping_and_arp_results(monkeypatch):
    async def fake_ping(ip, semaphore, timeout):
        return ip.endswith(".1")

    async def fake_arp(network, timeout):
        return {"192.168.1.1": "aa:bb:cc:dd:ee:01", "192.168.1.2": "aa:bb:cc:dd:ee:02"}

    async def fake_neighbors():
        return {}

    async def fake_hostname(ip):
        return None

    monkeypatch.setattr("iknowurhere.scanner.shutil.which", lambda _: "/usr/bin/ping")
    monkeypatch.setattr("iknowurhere.scanner._ping", fake_ping)
    monkeypatch.setattr("iknowurhere.scanner._arp_sweep", fake_arp)
    monkeypatch.setattr("iknowurhere.scanner._neighbor_table", fake_neighbors)
    monkeypatch.setattr("iknowurhere.scanner._hostname", fake_hostname)
    result = await scan("192.168.1.0/30")
    assert [(d.ip, d.source) for d in result.devices] == [
        ("192.168.1.1", "PING+ARP"),
        ("192.168.1.2", "ARP"),
    ]
    assert result.devices[1].mac == "aa:bb:cc:dd:ee:02"


@pytest.mark.asyncio
async def test_scan_continues_with_ping_when_arp_not_permitted(monkeypatch):
    async def fake_ping(ip, semaphore, timeout):
        return ip.endswith(".1")

    async def fail_arp(network, timeout):
        raise RuntimeError("permission required")

    async def fake_neighbors():
        return {}

    async def fake_hostname(ip):
        return None

    monkeypatch.setattr("iknowurhere.scanner.shutil.which", lambda _: "/usr/bin/ping")
    monkeypatch.setattr("iknowurhere.scanner._ping", fake_ping)
    monkeypatch.setattr("iknowurhere.scanner._arp_sweep", fail_arp)
    monkeypatch.setattr("iknowurhere.scanner._neighbor_table", fake_neighbors)
    monkeypatch.setattr("iknowurhere.scanner._hostname", fake_hostname)
    result = await scan("192.168.1.0/30")
    assert result.warning == "permission required"
    assert result.devices[0].source == "PING"
