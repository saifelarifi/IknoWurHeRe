import asyncio

import httpx
from dataclasses import dataclass

from iknowurhere.dashboard import create_dashboard_app
from iknowurhere.database import DeviceStore
from iknowurhere.scanner import Device
import iknowurhere.dashboard as dashboard


def test_dashboard_is_read_only_and_api_requires_token():
    store = DeviceStore(":memory:")
    store.observe_device(
        Device("192.168.8.4", "aa:bb:cc:dd:ee:04", "laptop", "PING"),
        scope="192.168.8.0/24",
    )
    app = create_dashboard_app(
        "192.168.8.0/24", store, api_token="t" * 32,
        background_scan=False, background_monitor=False,
    )

    async def make_requests():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            assert (await client.get("/")).status_code == 200
            assert (await client.get("/api/devices")).status_code == 401
            response = await client.get("/api/devices", headers={"X-API-Key": "t" * 32})
            assert response.status_code == 200
            assert response.json()[0]["ip"] == "192.168.8.4"

    try:
        asyncio.run(make_requests())
    finally:
        store.close()


def test_scan_now_requires_token_and_runs_scan(monkeypatch):
    store = DeviceStore(":memory:")
    app = create_dashboard_app(
        "192.168.8.0/24", store, api_token="t" * 32,
        background_scan=False, background_monitor=False,
    )

    @dataclass
    class Summary:
        devices: list
        alerts: list
        warning: str | None = None

    async def fake_scan(*args, **kwargs):
        return Summary([], [])

    monkeypatch.setattr(dashboard, "scan_and_record", fake_scan)

    async def make_requests():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            assert (await client.post("/api/scan")).status_code == 401
            response = await client.post("/api/scan", headers={"X-API-Key": "t" * 32})
            assert response.status_code == 200
            assert response.json()["ok"] is True
            assert response.json()["device_count"] == 0

    try:
        asyncio.run(make_requests())
    finally:
        store.close()


def test_scan_failure_is_visible_in_dashboard_state(monkeypatch):
    store = DeviceStore(":memory:")
    app = create_dashboard_app(
        "192.168.8.0/24", store, api_token="t" * 32,
        background_scan=False, background_monitor=False,
    )

    async def fail_scan(*args, **kwargs):
        raise RuntimeError("ping unavailable; ARP permission denied")

    monkeypatch.setattr(dashboard, "scan_and_record", fail_scan)

    async def make_requests():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            headers = {"X-API-Key": "t" * 32}
            response = await client.post("/api/scan", headers=headers)
            assert response.status_code == 503
            overview = await client.get("/api/overview", headers=headers)
            assert overview.json()["last_scan_status"] == "error"
            assert "ARP permission denied" in overview.json()["last_scan_error"]

    try:
        asyncio.run(make_requests())
    finally:
        store.close()


def test_dashboard_ack_port_scan_and_html_export_are_protected(monkeypatch):
    store = DeviceStore(":memory:")
    network = "192.168.8.0/24"
    store.observe_device(Device("192.168.8.7", "aa:bb:cc:dd:ee:07", "host", "PING"), scope=network)
    store.observe_network_state("gateway", "192.168.8.1", scope=network)
    store.observe_network_state("gateway", "192.168.8.254", scope=network)
    alert = store.list_alerts(scope=network)[0]
    app = create_dashboard_app(network, store, api_token="t" * 32, background_scan=False, background_monitor=False)

    async def fake_ports(network, address):
        return [{"port": 443, "service": "https", "state": "open"}]

    monkeypatch.setattr(dashboard, "quick_port_scan", fake_ports)

    async def make_requests():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            assert (await client.post("/api/devices/192.168.8.7/ports")).status_code == 401
            headers = {"X-API-Key": "t" * 32}
            ports = await client.post("/api/devices/192.168.8.7/ports", headers=headers)
            assert ports.json()["open_ports"][0]["port"] == 443
            ack = await client.post(f"/api/alerts/{alert.alert_id}/ack", headers=headers)
            assert ack.status_code == 200
            report = await client.get("/api/export/html", headers=headers)
            assert report.status_code == 200
            assert "192.168.8.7" in report.text
            assert "Acknowledged" in report.text

    try:
        asyncio.run(make_requests())
    finally:
        store.close()
