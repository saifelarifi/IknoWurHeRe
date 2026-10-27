import json

from typer.testing import CliRunner

from iknowurhere.cli import app
from iknowurhere.database import DeviceStore
from iknowurhere.scanner import Device
from typer.testing import CliRunner


def test_devices_command_reads_history(tmp_path):
    database = tmp_path / "history.sqlite3"
    with DeviceStore(database) as store:
        store.observe_device(
            Device("192.168.8.4", "aa:bb:cc:dd:ee:04", "laptop", "ARP", vendor="Example"),
            scope="192.168.8.0/24",
        )
    result = CliRunner().invoke(app, ["devices", "--database", str(database)])
    assert result.exit_code == 0
    assert "Device inventory" in result.output
    assert "Vendor" in result.output


def test_export_network_state_json(tmp_path):
    database = tmp_path / "history.sqlite3"
    output = tmp_path / "state.json"
    with DeviceStore(database) as store:
        store.observe_network_state("gateway", "192.168.8.1", scope="192.168.8.0/24")
    result = CliRunner().invoke(
        app, ["export", str(output), "--kind", "network-state", "--database", str(database)]
    )
    assert result.exit_code == 0
    assert json.loads(output.read_text())[0]["key"] == "gateway"


def test_web_generates_tls_token_and_binds_lan(monkeypatch, tmp_path):
    import uvicorn
    import iknowurhere.cli as cli
    import iknowurhere.tls as tls

    db = tmp_path / "history.sqlite3"
    monkeypatch.setattr(cli, "default_database_path", lambda: db)
    monkeypatch.setattr(tls, "local_certificate_names", lambda interface=None: {
        "localhost", "127.0.0.1", "192.168.8.102"
    })
    monkeypatch.setattr(cli, "passive_capture_permission", lambda: (False, "CAP_NET_RAW unavailable"))
    captured = {}

    def fake_run(asgi_app, **kwargs):
        captured.update(kwargs)
        asgi_app.state.store.close()

    monkeypatch.setattr(uvicorn, "run", fake_run)
    result = CliRunner().invoke(app, [
        "web", "192.168.8.0/24", "--database", str(db), "--host", "0.0.0.0", "--port", "8787"
    ])
    assert result.exit_code == 0, result.output
    assert captured["host"] == "0.0.0.0"
    assert captured["port"] == 8787
    assert captured["ssl_certfile"].endswith("dashboard-cert.pem")
    assert captured["ssl_keyfile"].endswith("dashboard-key.pem")
    assert "https://192.168.8.102:8787" in result.output
    assert "Dashboard token" in result.output
    assert "periodic inventory scans will continue" in result.output
