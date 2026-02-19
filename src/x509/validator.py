from datetime import datetime, UTC

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import padding

from src.x509.loader import X509Loader


class X509Validator:

    @staticmethod
    def check_valid_time(cert: x509.Certificate) -> None:
        now = datetime.now(UTC)

        if now < cert.not_valid_before_utc:
            raise ValueError("Certificate not yet valid")

        if now > cert.not_valid_after_utc:
            raise ValueError("Certificate expired")

    # SUBJECT / CN
    @staticmethod
    def get_common_name(cert: x509.Certificate) -> str:
        return cert.subject.get_attributes_for_oid(
            NameOID.COMMON_NAME
        )[0].value

    @staticmethod
    def assert_cn(cert: x509.Certificate, expected: str) -> None:
        cn = X509Validator.get_common_name(cert)

        if cn != expected:
            raise ValueError(f"CN mismatch: {cn} != {expected}")

    @staticmethod
    def assert_key_matches_cert(key, cert: x509.Certificate) -> None:
        """ KEY ↔ CERT MATCH """
        if key.public_key().public_numbers() != cert.public_key().public_numbers():
            raise ValueError("Private key does not match certificate")

    @staticmethod
    def assert_csr_signature_valid(csr: x509.CertificateSigningRequest) -> None:
        csr.public_key().verify(
            csr.signature,
            csr.tbs_certrequest_bytes,
            padding.PKCS1v15(),
            csr.signature_hash_algorithm,
        )

    # CERT SIGNED BY CA
    @staticmethod
    def cert_assert_signed_by_ca(cert: x509.Certificate, ca_cert: x509.Certificate) -> None:

        ca_cert.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm
        )

    # EXTENSION CHECKS
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

    # QUICK FULL CHECK
    @staticmethod
    def validate_endpoint_cert(
            cert_path,
            ca_path,
            key_path=None,
            key_password=None,
            expected_cn=None
    ):

        cert = X509Loader.load_cert(cert_path)
        ca = X509Loader.load_cert(ca_path)

        X509Validator.check_valid_time(cert)
        X509Validator.cert_assert_signed_by_ca(cert, ca)
        X509Validator.assert_not_ca(cert)

        if expected_cn:
            X509Validator.assert_cn(cert, expected_cn)

        if key_path:
            key = X509Loader.load_key(key_path, key_password)
            X509Validator.assert_key_matches_cert(key, cert)

        return True
