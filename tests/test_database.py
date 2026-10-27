import sqlite3
from datetime import datetime, timezone

from iknowurhere.database import DeviceStore
from iknowurhere.scanner import Device


def test_gateway_mac_change_is_recorded_as_alert():
    gateway_ip = "192.168.8.1"
    original_mac = "aa:bb:cc:dd:ee:01"
    replacement_mac = "aa:bb:cc:dd:ee:99"

    with DeviceStore(":memory:") as store:
        baseline_alerts = store.observe_device(
            Device(gateway_ip, original_mac, "router", "ARP"),
            gateway_ip=gateway_ip,
            observed_at="2026-10-27T10:00:00+00:00",
        )
        change_alerts = store.observe_device(
            Device(gateway_ip, replacement_mac, "router", "ARP"),
            gateway_ip=gateway_ip,
            observed_at="2026-10-27T10:05:00+00:00",
        )

        assert not any(alert.event_type == "gateway_mac_changed" for alert in baseline_alerts)
        alert = next(alert for alert in change_alerts if alert.event_type == "gateway_mac_changed")
        assert alert.ip == gateway_ip
        assert alert.previous_mac == original_mac
        assert alert.current_mac == replacement_mac
        assert alert.confidence == 0.98
        assert "legitimate network change" in alert.reason

        persisted_alert = next(
            alert for alert in store.list_alerts() if alert.event_type == "gateway_mac_changed"
        )
        assert persisted_alert == alert


def test_device_history_preserves_first_seen_and_updates_last_seen():
    device = Device("192.168.8.42", "00:11:22:33:44:55", "laptop", "PING+ARP")

    with DeviceStore(":memory:") as store:
        store.observe_device(device, observed_at="2026-10-27T10:00:00+00:00")
        store.observe_device(device, observed_at="2026-10-27T10:10:00+00:00")

        [record] = store.list_devices()
        assert record.first_seen == "2026-10-27T10:00:00+00:00"
        assert record.last_seen == "2026-10-27T10:10:00+00:00"


def test_network_state_change_and_allowlist_alerts():
    with DeviceStore(":memory:") as store:
        assert store.observe_network_state("gateway", "192.168.8.1", scope="192.168.8.0/24") == []
        assert store.observe_network_state(
            "dns", ["1.1.1.1", "8.8.8.8"], scope="192.168.8.0/24", expected={"1.1.1.1", "8.8.8.8"}
        ) == []

        gateway_alerts = store.observe_network_state(
            "gateway", "192.168.8.254", scope="192.168.8.0/24"
        )
        dhcp_alerts = store.observe_network_state(
            "dhcp", "192.168.8.99", scope="192.168.8.0/24", expected={"192.168.8.1"}
        )

        assert gateway_alerts[0].event_type == "gateway_ip_changed"
        assert gateway_alerts[0].previous_value == '"192.168.8.1"'
        assert dhcp_alerts[0].event_type == "unexpected_dhcp_server"
        assert "allowlist" in dhcp_alerts[0].reason


def test_device_history_is_isolated_by_network_scope():
    device = Device("192.168.8.2", "aa:bb:cc:dd:ee:02", None, "ARP")
    with DeviceStore(":memory:") as store:
        store.observe_device(device, scope="192.168.8.0/24")
        store.observe_device(device, scope="10.0.0.0/24")
        assert len(store.list_devices(scope="192.168.8.0/24")) == 1
        assert len(store.list_devices(scope="10.0.0.0/24")) == 1
        assert len(store.list_devices()) == 2


def test_history_freshness_label_is_not_a_reachability_claim():
    with DeviceStore(":memory:") as store:
        store.observe_device(
            Device("192.168.8.7", "aa:bb:cc:dd:ee:07", None, "ARP"),
            observed_at=datetime.now(timezone.utc),
        )
        store.observe_device(
            Device("192.168.8.8", "aa:bb:cc:dd:ee:08", None, "ARP"),
            observed_at="2000-01-01T00:00:00+00:00",
        )
        statuses = {record.ip: record.status for record in store.list_devices()}
        assert statuses["192.168.8.7"] == "recent"
        assert statuses["192.168.8.8"] == "stale"


def test_alert_acknowledgement_is_persisted_and_idempotent():
    with DeviceStore(":memory:") as store:
        store.observe_network_state("gateway", "192.168.8.1", scope="192.168.8.0/24")
        store.observe_network_state("gateway", "192.168.8.254", scope="192.168.8.0/24")
        [alert] = store.list_alerts(scope="192.168.8.0/24")
        assert alert.alert_id is not None
        assert alert.acknowledged_at is None
        assert store.acknowledge_alert(alert.alert_id, scope=alert.scope)
        assert not store.acknowledge_alert(alert.alert_id, scope=alert.scope)
        [saved] = store.list_alerts(scope=alert.scope)
        assert saved.acknowledged_at is not None


def test_migrates_legacy_v01_device_and_alert_tables(tmp_path):
    path = tmp_path / "legacy.sqlite3"
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE devices (
            ip TEXT NOT NULL, mac TEXT NOT NULL DEFAULT '', hostname TEXT, source TEXT NOT NULL,
            first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, PRIMARY KEY(ip, mac)
        );
        CREATE TABLE alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT, event_type TEXT NOT NULL, reason TEXT NOT NULL,
            confidence REAL NOT NULL, ip TEXT NOT NULL, previous_mac TEXT, current_mac TEXT,
            observed_at TEXT NOT NULL
        );
        INSERT INTO devices VALUES ('192.168.8.5', 'aa:bb:cc:dd:ee:05', 'host', 'ARP', 't1', 't2');
        """
    )
    connection.close()

    with DeviceStore(path) as store:
        [record] = store.list_devices()
        assert record.ip == "192.168.8.5"
        assert record.first_seen == "t1"
        store.observe_device(Device("192.168.8.5", "aa:bb:cc:dd:ee:05", "host", "ARP"))
        assert store.list_alerts() == []
