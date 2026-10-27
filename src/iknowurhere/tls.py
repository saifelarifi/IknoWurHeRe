"""Generate and persist a local self-signed HTTPS certificate for the dashboard."""

from __future__ import annotations

import ipaddress
import os
import socket
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def local_certificate_names(interface: str | None = None) -> set[str]:
    """Find local IPs and hostnames that clients may use to reach this server."""
    names = {"localhost", "127.0.0.1", "::1", socket.gethostname(), socket.getfqdn()}
    try:
        _hostname, _aliases, addresses = socket.gethostbyname_ex(socket.gethostname())
        names.update(address for address in addresses if address and address != "0.0.0.0")
    except OSError:
        pass

    try:
        from scapy.all import conf, get_if_addr, get_if_list

        interfaces = [interface] if interface else get_if_list()
        for name in interfaces:
            if not name:
                continue
            address = get_if_addr(name)
            if address and address != "0.0.0.0":
                names.add(address)
        if not interface:
            _iface, source, _gateway = conf.route.route("0.0.0.0")
            if source and source != "0.0.0.0":
                names.add(source)
    except Exception:
        pass
    return names


def _san_entries(names: set[str]) -> x509.SubjectAlternativeName:
    entries: list[x509.GeneralName] = []
    for name in sorted(names):
        try:
            entries.append(x509.IPAddress(ipaddress.ip_address(name)))
        except ValueError:
            if name:
                entries.append(x509.DNSName(name))
    return x509.SubjectAlternativeName(entries)


def _read_existing(cert_path: Path, key_path: Path):
    try:
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        return cert, key
    except (OSError, ValueError, TypeError):
        return None, None


def _certificate_is_reusable(cert_path: Path, key_path: Path, names: set[str]) -> bool:
    cert, key = _read_existing(cert_path, key_path)
    if cert is None or key is None:
        return False
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        existing = {str(item.value) for item in san}
        public_matches = cert.public_key().public_numbers() == key.public_key().public_numbers()
        expiry = cert.not_valid_after_utc > datetime.now(timezone.utc) + timedelta(days=7)
        return public_matches and expiry and names.issubset(existing)
    except (x509.ExtensionNotFound, ValueError, TypeError):
        return False


def ensure_dashboard_certificate(directory: str | Path, names: set[str]) -> tuple[Path, Path, bool]:
    """Return certificate/key paths and whether they were generated this run."""
    cert_dir = Path(directory).expanduser()
    cert_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name != "nt":
        cert_dir.chmod(0o700)
    cert_path = cert_dir / "dashboard-cert.pem"
    key_path = cert_dir / "dashboard-key.pem"
    if _certificate_is_reusable(cert_path, key_path, names):
        return cert_path, key_path, False

    key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "IknoWurHeRe Local Dashboard"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "IknoWurHeRe"),
    ])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(_san_entries(names), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_tmp = cert_path.with_suffix(".pem.tmp")
    key_tmp = key_path.with_suffix(".pem.tmp")
    cert_tmp.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_tmp.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    if os.name != "nt":
        cert_tmp.chmod(0o644)
        key_tmp.chmod(0o600)
    cert_tmp.replace(cert_path)
    key_tmp.replace(key_path)
    return cert_path, key_path, True
