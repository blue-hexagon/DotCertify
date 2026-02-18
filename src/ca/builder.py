from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta, UTC

from src.ca.ca_tpl import X509CaTemplate
from src.csr.csr_tpl import X509CsrTemplate


class CaBuilder:
    def __init__(self, ca_config: X509CaTemplate):
        self.ca_config = ca_config
        self.ca_key = None

    def create_key(self):
        self.ca_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096
        )
        return self

    def create_ca(self):
        self.ca_config.key_fp.write_bytes(
            self.ca_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.BestAvailableEncryption(self.ca_config.secret)
            )
        )

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, self.ca_config.dn.country),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.ca_config.dn.organization),
            x509.NameAttribute(NameOID.COMMON_NAME, self.ca_config.dn.common_name),
        ])

        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self.ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(UTC) - timedelta(minutes=5))
            .not_valid_after(datetime.now(UTC) + timedelta(days=3650))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True
            )
            .add_extension(
                x509.KeyUsage(
                    key_cert_sign=True,
                    crl_sign=True,
                    digital_signature=False,
                    key_encipherment=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True
            )
            .sign(self.ca_key, hashes.SHA256())
        )

        self.ca_config.cert_fp.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
        return self

    def sign_csr(self, csr_config: X509CsrTemplate):
        csr = x509.load_pem_x509_csr(csr_config.csr_fp.read_bytes())

        ca_key = serialization.load_pem_private_key(
            self.ca_config.key_fp.read_bytes(),
            password=self.ca_config.secret
        )

        ca_cert = x509.load_pem_x509_certificate(
            self.ca_config.cert_fp.read_bytes()
        )

        cert = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(ca_cert.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=self.ca_config.ca_days_lifetime))
            # copy CSR extensions if present
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    key_cert_sign=False,
                    crl_sign=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True
            )
            .sign(ca_key, hashes.SHA256())
        )

        csr_config.cert_fp.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
