from pathlib import Path
from datetime import datetime, UTC
from typing import Optional

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding


class Validator:

    # -------------------------
    # LOADERS
    # -------------------------

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

    # -------------------------
    # VALIDITY WINDOW
    # -------------------------

    @staticmethod
    def check_valid_time(cert: x509.Certificate) -> None:
        now = datetime.now(UTC)

        if now < cert.not_valid_before_utc:
            raise ValueError("Certificate not yet valid")

        if now > cert.not_valid_after_utc:
            raise ValueError("Certificate expired")

    # -------------------------
    # SUBJECT / CN
    # -------------------------

    @staticmethod
    def get_common_name(cert: x509.Certificate) -> str:
        return cert.subject.get_attributes_for_oid(
            NameOID.COMMON_NAME
        )[0].value

    @staticmethod
    def assert_cn(cert: x509.Certificate, expected: str) -> None:
        cn = Validator.get_common_name(cert)

        if cn != expected:
            raise ValueError(f"CN mismatch: {cn} != {expected}")

    # -------------------------
    # KEY ↔ CERT MATCH
    # -------------------------

    @staticmethod
    def assert_key_matches_cert(key, cert: x509.Certificate) -> None:
        if key.public_key().public_numbers() != cert.public_key().public_numbers():
            raise ValueError("Private key does not match certificate")

    # -------------------------
    # CSR SIGNATURE VALID
    # -------------------------

    @staticmethod
    def assert_csr_signature_valid(csr: x509.CertificateSigningRequest) -> None:
        csr.public_key().verify(
            csr.signature,
            csr.tbs_certrequest_bytes,
            padding.PKCS1v15(),
            csr.signature_hash_algorithm,
        )

    # -------------------------
    # CERT SIGNED BY CA
    # -------------------------

    @staticmethod
    def assert_signed_by(cert: x509.Certificate, ca_cert: x509.Certificate) -> None:

        ca_cert.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm
        )

    # -------------------------
    # EXTENSION CHECKS
    # -------------------------

    @staticmethod
    def assert_is_ca(cert: x509.Certificate) -> None:
        ext = cert.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value

        if not ext.ca:
            raise ValueError("Certificate is not a CA")

    @staticmethod
    def assert_not_ca(cert: x509.Certificate) -> None:
        ext = cert.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value

        if ext.ca:
            raise ValueError("Certificate must not be a CA")

    # -------------------------
    # QUICK FULL CHECK
    # -------------------------

    @staticmethod
    def validate_endpoint_cert(
        cert_path,
        ca_path,
        key_path=None,
        key_password=None,
        expected_cn=None
    ):

        cert = Validator.load_cert(cert_path)
        ca = Validator.load_cert(ca_path)

        Validator.check_valid_time(cert)
        Validator.assert_signed_by(cert, ca)
        Validator.assert_not_ca(cert)

        if expected_cn:
            Validator.assert_cn(cert, expected_cn)

        if key_path:
            key = Validator.load_key(key_path, key_password)
            Validator.assert_key_matches_cert(key, cert)

        return True
