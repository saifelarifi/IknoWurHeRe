"""SQLite-backed device history and defensive network-change alerts.

The confidence score describes confidence in the observed change, not certainty
that the change is malicious. Router replacement, DHCP, and MAC randomization can
all produce legitimate changes.
"""

from __future__ import annotations

import sqlite3
import json
import os
import platform
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .scanner import Device


@dataclass(frozen=True, slots=True)
class Alert:
    event_type: str
    reason: str
    confidence: float
    ip: str
    previous_mac: str | None
    current_mac: str | None
    observed_at: str
    previous_value: str | None = None
    current_value: str | None = None
    scope: str = "default"
    alert_id: int | None = field(default=None, compare=False)
    acknowledged_at: str | None = field(default=None, compare=False)


@dataclass(frozen=True, slots=True)
class DeviceRecord:
    ip: str
    mac: str | None
    hostname: str | None
    source: str
    first_seen: str
    last_seen: str
    vendor: str | None = None
    scope: str = "default"
    status: str = "unknown"


@dataclass(frozen=True, slots=True)
class NetworkState:
    scope: str
    key: str
    value: str
    observed_at: str


def default_database_path() -> Path:
    """Return the platform-standard per-user data location."""
    system = platform.system()
    if system == "Windows":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData/Local"))
        return base / "IknoWurHeRe" / "history.sqlite3"
    if system == "Darwin":
        return Path.home() / "Library" / "Application Support" / "IknoWurHeRe" / "history.sqlite3"
    base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share"))
    return base / "iknowurhere" / "history.sqlite3"


class DeviceStore:
    """Persist device sightings and gateway identity changes in SQLite."""

    def __init__(self, database: str | Path | None = None) -> None:
        self._lock = threading.RLock()
        using_default = database is None
        if database is None:
            database = default_database_path()
        raw_path = str(database)
        if raw_path != ":memory:":
            path = Path(raw_path).expanduser()
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            if using_default and os.name != "nt":
                path.parent.chmod(0o700)
            raw_path = str(path)

        self._connection = sqlite3.connect(raw_path, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA busy_timeout = 5000")
        self._create_schema()
        if raw_path != ":memory:" and os.name != "nt":
            Path(raw_path).chmod(0o600)

    def _create_schema(self) -> None:
        with self._connection:
            self._connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS device_history (
                    scope TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    mac TEXT NOT NULL DEFAULT '',
                    hostname TEXT,
                    source TEXT NOT NULL,
                    vendor TEXT,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    PRIMARY KEY (scope, ip, mac)
                );
                CREATE INDEX IF NOT EXISTS idx_device_history_last_seen ON device_history(last_seen DESC);

                CREATE TABLE IF NOT EXISTS gateway_state (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    ip TEXT NOT NULL,
                    mac TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS gateway_state_by_scope (
                    scope TEXT PRIMARY KEY,
                    ip TEXT NOT NULL,
                    mac TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    confidence REAL NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
                    ip TEXT NOT NULL,
                    previous_mac TEXT,
                    current_mac TEXT,
                    previous_value TEXT,
                    current_value TEXT,
                    observed_at TEXT NOT NULL,
                    scope TEXT NOT NULL DEFAULT 'default'
                );
                CREATE INDEX IF NOT EXISTS idx_alerts_observed_at ON alerts(observed_at DESC);
                CREATE TABLE IF NOT EXISTS network_state (
                    scope TEXT NOT NULL,
                    key TEXT NOT NULL,
                    value TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    PRIMARY KEY (scope, key)
                );
                PRAGMA user_version = 3;
                """
            )
            # Add columns when opening databases created by v0.1.0.
            self._ensure_column("alerts", "previous_value", "TEXT")
            self._ensure_column("alerts", "current_value", "TEXT")
            self._ensure_column("alerts", "scope", "TEXT NOT NULL DEFAULT 'default'")
            self._ensure_column("alerts", "acknowledged_at", "TEXT")
            existing_tables = {row["name"] for row in self._connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )}
            if "devices" in existing_tables:
                old_columns = {row["name"] for row in self._connection.execute("PRAGMA table_info(devices)")}
                vendor_column = "vendor" if "vendor" in old_columns else "NULL"
                self._connection.execute(
                    f"""INSERT OR IGNORE INTO device_history(scope, ip, mac, hostname, source, vendor, first_seen, last_seen)
                        SELECT 'default', ip, mac, hostname, source, {vendor_column}, first_seen, last_seen FROM devices"""
                )

    def _ensure_column(self, table: str, column: str, definition: str) -> None:
        columns = {row["name"] for row in self._connection.execute(f"PRAGMA table_info({table})")}
        if column not in columns:
            self._connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    @staticmethod
    def _timestamp(value: str | datetime | None) -> str:
        if value is None:
            return datetime.now(timezone.utc).isoformat(timespec="microseconds")
        if isinstance(value, datetime):
            if value.tzinfo is None:
                value = value.replace(tzinfo=timezone.utc)
            return value.astimezone(timezone.utc).isoformat(timespec="microseconds")
        return value

    @staticmethod
    def _normalize_mac(mac: str | None) -> str:
        return mac.strip().lower().replace("-", ":") if mac else ""

    @staticmethod
    def _public_mac(mac: str | None) -> str | None:
        return mac or None

    @staticmethod
    def _seen_status(timestamp: str) -> str:
        try:
            seen = datetime.fromisoformat(timestamp)
            if seen.tzinfo is None:
                seen = seen.replace(tzinfo=timezone.utc)
            age = datetime.now(timezone.utc) - seen.astimezone(timezone.utc)
            return "recent" if age.total_seconds() <= 300 else "stale"
        except (ValueError, TypeError):
            return "unknown"

    def observe_device(
        self,
        device: Device,
        *,
        gateway_ip: str | None = None,
        scope: str = "default",
        observed_at: str | datetime | None = None,
    ) -> list[Alert]:
        """Store one sighting and return any newly detected change alerts.

        The first gateway sighting establishes a baseline. A later MAC change
        creates a high-confidence *change* alert, not a verdict that an attack
        occurred. The caller supplies gateway_ip from trusted local routing data.
        """
        timestamp = self._timestamp(observed_at)
        mac = self._normalize_mac(device.mac)
        alerts: list[Alert] = []

        with self._lock, self._connection:
            same_device = self._connection.execute(
                "SELECT first_seen FROM device_history WHERE scope = ? AND ip = ? AND mac = ?",
                (scope, device.ip, mac),
            ).fetchone()
            previous_device = self._connection.execute(
                "SELECT mac, last_seen FROM device_history WHERE scope = ? AND ip = ? AND mac <> '' AND mac <> ? "
                "ORDER BY last_seen DESC LIMIT 1",
                (scope, device.ip, mac),
            ).fetchone()
            any_for_ip = self._connection.execute(
                "SELECT 1 FROM device_history WHERE scope = ? AND ip = ? LIMIT 1", (scope, device.ip)
            ).fetchone()

            self._connection.execute(
                """INSERT INTO device_history (scope, ip, mac, hostname, source, vendor, first_seen, last_seen)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(scope, ip, mac) DO UPDATE SET
                     hostname = COALESCE(excluded.hostname, device_history.hostname),
                     source = excluded.source,
                     vendor = COALESCE(excluded.vendor, device_history.vendor),
                     last_seen = excluded.last_seen""",
                (scope, device.ip, mac, device.hostname, device.source, device.vendor, timestamp, timestamp),
            )

            if not same_device and not any_for_ip:
                alerts.append(Alert(
                    event_type="new_device",
                    reason=f"A previously unseen device was observed at {device.ip}.",
                    confidence=0.80,
                    ip=device.ip,
                    previous_mac=None,
                    current_mac=self._public_mac(mac),
                    observed_at=timestamp,
                    scope=scope,
                ))

            if device.ip == gateway_ip and mac:
                gateway = self._connection.execute(
                    "SELECT ip, mac, first_seen FROM gateway_state_by_scope WHERE scope = ?", (scope,)
                ).fetchone()
                if gateway is None:
                    legacy_gateway = self._connection.execute(
                        "SELECT ip, mac, first_seen, last_seen FROM gateway_state WHERE singleton = 1"
                    ).fetchone()
                    # Preserve the v0.1 baseline when it belongs to this same gateway.
                    if legacy_gateway and legacy_gateway["ip"] == device.ip:
                        self._connection.execute(
                            """INSERT OR IGNORE INTO gateway_state_by_scope(scope, ip, mac, first_seen, last_seen)
                               VALUES (?, ?, ?, ?, ?)""",
                            (scope, legacy_gateway["ip"], legacy_gateway["mac"],
                             legacy_gateway["first_seen"], legacy_gateway["last_seen"]),
                        )
                        gateway = legacy_gateway
                if gateway is None:
                    self._connection.execute(
                        "INSERT INTO gateway_state_by_scope(scope, ip, mac, first_seen, last_seen) VALUES (?, ?, ?, ?, ?)",
                        (scope, device.ip, mac, timestamp, timestamp),
                    )
                else:
                    if gateway["ip"] != device.ip:
                        # The network-state observer records the IP change;
                        # this table tracks the paired gateway MAC baseline.
                        self._connection.execute(
                            "UPDATE gateway_state_by_scope SET ip = ?, mac = ?, first_seen = ?, last_seen = ? WHERE scope = ?",
                            (device.ip, mac, timestamp, timestamp, scope),
                        )
                    elif gateway["mac"] != mac:
                        alerts.append(Alert(
                            event_type="gateway_mac_changed",
                            reason=(
                                f"The MAC address for gateway {device.ip} changed from {gateway['mac']} to {mac}. "
                                "This may be a legitimate network change or an identity-spoofing indicator."
                            ),
                            confidence=0.98,
                            ip=device.ip,
                            previous_mac=gateway["mac"],
                            current_mac=mac,
                            observed_at=timestamp,
                            scope=scope,
                        ))
                        self._connection.execute(
                            "UPDATE gateway_state_by_scope SET mac = ?, last_seen = ? WHERE scope = ?",
                            (mac, timestamp, scope),
                        )
                    else:
                        self._connection.execute(
                            "UPDATE gateway_state_by_scope SET last_seen = ? WHERE scope = ?", (timestamp, scope)
                        )
            elif previous_device:
                alerts.append(Alert(
                    event_type="ip_mac_changed",
                    reason=(
                        f"IP {device.ip} was previously observed with MAC {previous_device['mac']} "
                        f"and is now observed with {mac}. This can indicate a duplicate IP or a legitimate change."
                    ),
                    confidence=0.85,
                    ip=device.ip,
                    previous_mac=previous_device["mac"],
                    current_mac=mac,
                    observed_at=timestamp,
                    scope=scope,
                ))

            self._connection.executemany(
                """INSERT INTO alerts(event_type, reason, confidence, ip, previous_mac, current_mac,
                                        previous_value, current_value, observed_at, scope)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                [
                    (a.event_type, a.reason, a.confidence, a.ip, a.previous_mac, a.current_mac,
                     a.previous_value, a.current_value, a.observed_at, a.scope)
                    for a in alerts
                ],
            )

        return alerts

    def list_devices(self, *, scope: str | None = None) -> list[DeviceRecord]:
        with self._lock:
            query = "SELECT ip, mac, hostname, source, first_seen, last_seen, vendor, scope FROM device_history"
            params: tuple[str, ...] = ()
            if scope is not None:
                query += " WHERE scope = ?"
                params = (scope,)
            query += " ORDER BY last_seen DESC, ip"
            rows = self._connection.execute(query, params).fetchall()
        return [
            DeviceRecord(row["ip"], self._public_mac(row["mac"]), row["hostname"], row["source"],
                         row["first_seen"], row["last_seen"], row["vendor"], row["scope"],
                         self._seen_status(row["last_seen"]))
            for row in rows
        ]

    def list_alerts(self, *, limit: int = 100, scope: str | None = None) -> list[Alert]:
        if limit < 1:
            raise ValueError("limit must be at least 1")
        with self._lock:
            query = """SELECT event_type, reason, confidence, ip, previous_mac, current_mac,
                              observed_at, previous_value, current_value, scope, id AS alert_id,
                              acknowledged_at FROM alerts"""
            params: tuple = ()
            if scope is not None:
                query += " WHERE scope = ?"
                params = (scope,)
            query += " ORDER BY id DESC LIMIT ?"
            rows = self._connection.execute(query, (*params, limit)).fetchall()
        return [Alert(**dict(row)) for row in rows]

    def acknowledge_alert(self, alert_id: int, *, scope: str) -> bool:
        """Mark one alert acknowledged without changing its event details."""
        timestamp = self._timestamp(None)
        with self._lock, self._connection:
            cursor = self._connection.execute(
                "UPDATE alerts SET acknowledged_at = ? "
                "WHERE id = ? AND scope = ? AND acknowledged_at IS NULL",
                (timestamp, alert_id, scope),
            )
            return cursor.rowcount == 1

    def observe_network_state(
        self,
        key: str,
        value: str | list[str],
        *,
        scope: str = "default",
        expected: set[str] | None = None,
        observed_at: str | datetime | None = None,
    ) -> list[Alert]:
        """Record a gateway/DNS/DHCP value and alert when it diverges.

        `expected` is an optional allowlist. Initial observations establish a
        baseline unless an allowlist was provided and the actual value is absent.
        """
        timestamp = self._timestamp(observed_at)
        normalized = sorted(set(value)) if isinstance(value, list) else value
        encoded = json.dumps(normalized, separators=(",", ":"), sort_keys=True)
        old_value: str | None = None
        alerts: list[Alert] = []
        with self._lock, self._connection:
            row = self._connection.execute(
                "SELECT value FROM network_state WHERE scope = ? AND key = ?", (scope, key)
            ).fetchone()
            if row:
                old_value = row["value"]
            mismatch = False
            if expected is not None:
                if isinstance(normalized, list):
                    mismatch = not set(normalized).issubset(expected)
                else:
                    mismatch = normalized not in expected
            changed = old_value is not None and old_value != encoded

            event_type = {
                "gateway": "gateway_ip_changed",
                "dns": "dns_changed",
                "dhcp": "unexpected_dhcp_server",
            }.get(key, f"{key}_changed")
            if changed or (mismatch and not old_value):
                old_display = json.loads(old_value) if old_value else None
                new_display = json.loads(encoded)
                reason = (
                    f"Observed {key} changed from {old_display!r} to {new_display!r}."
                    if changed else f"Observed {key} value {new_display!r} is not in the configured allowlist."
                )
                confidence = 0.95 if key == "gateway" else 0.90
                alerts.append(Alert(
                    event_type=event_type,
                    reason=reason,
                    confidence=confidence,
                    ip="",
                    previous_mac=None,
                    current_mac=None,
                    observed_at=timestamp,
                    previous_value=old_value,
                    current_value=encoded,
                    scope=scope,
                ))

            self._connection.execute(
                """INSERT INTO network_state(scope, key, value, observed_at) VALUES (?, ?, ?, ?)
                   ON CONFLICT(scope, key) DO UPDATE SET value = excluded.value, observed_at = excluded.observed_at""",
                (scope, key, encoded, timestamp),
            )
            self._connection.executemany(
                """INSERT INTO alerts(event_type, reason, confidence, ip, previous_mac, current_mac,
                                      previous_value, current_value, observed_at, scope)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                [(a.event_type, a.reason, a.confidence, a.ip, a.previous_mac, a.current_mac,
                  a.previous_value, a.current_value, a.observed_at, a.scope) for a in alerts],
            )
        return alerts

    def list_network_state(self, *, scope: str | None = None) -> list[NetworkState]:
        with self._lock:
            if scope is None:
                rows = self._connection.execute(
                    "SELECT scope, key, value, observed_at FROM network_state ORDER BY scope, key"
                ).fetchall()
            else:
                rows = self._connection.execute(
                    "SELECT scope, key, value, observed_at FROM network_state WHERE scope = ? ORDER BY key", (scope,)
                ).fetchall()
        return [NetworkState(row["scope"], row["key"], row["value"], row["observed_at"]) for row in rows]

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def __enter__(self) -> DeviceStore:
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()
