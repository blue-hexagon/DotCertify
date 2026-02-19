from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import serialization


class X509Loader:
    @staticmethod
    def load_cert(path: Path | str) -> x509.Certificate:
        return x509.load_pem_x509_certificate(Path(path).read_bytes())

    @staticmethod
    def load_csr(path: Path | str) -> x509.CertificateSigningRequest:
        return x509.load_pem_x509_csr(Path(path).read_bytes())

    @staticmethod
    def load_key(path: Path | str, password: Optional[bytes] = None):
        return serialization.load_pem_private_key(
            Path(path).read_bytes(),
            password=password
        )
