import os

from cryptography import x509

from iknowurhere.tls import ensure_dashboard_certificate


def test_dashboard_certificate_is_generated_securely_and_reused(tmp_path):
    names = {"localhost", "127.0.0.1", "192.168.8.102"}
    cert_path, key_path, generated = ensure_dashboard_certificate(tmp_path / "tls", names)
    assert generated is True
    assert cert_path.is_file() and key_path.is_file()
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert "192.168.8.102" in {str(item.value) for item in san}

    again_cert, again_key, generated_again = ensure_dashboard_certificate(tmp_path / "tls", names)
    assert (again_cert, again_key) == (cert_path, key_path)
    assert generated_again is False
    if os.name != "nt":
        assert key_path.stat().st_mode & 0o777 == 0o600
