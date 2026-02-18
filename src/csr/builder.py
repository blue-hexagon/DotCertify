from typing import Optional, List

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from src.csr.csr_tpl import X509CsrTemplate


class CsrBuilder:
    def __init__(self, csr_config: X509CsrTemplate | List[X509CsrTemplate] = None, print_csr=False):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.csr: Optional[x509.CertificateSigningRequest] = None
        if csr_config:
            if isinstance(csr_config, list):
                for csrtlp in csr_config:
                    self.process_csr(csrtlp, print_csr)
            else:
                self.process_csr(csr_config, print_csr)

    def write_key(self, csr_config: X509CsrTemplate) -> None:
        if csr_config.secret:
            enc = serialization.BestAvailableEncryption(csr_config.secret)
        else:
            enc = serialization.NoEncryption()

        csr_config.key_fp.write_bytes(
            self.key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=enc,
            )
        )

    @staticmethod
    def create_csr(csr_config: X509CsrTemplate) -> x509.CertificateSigningRequestBuilder:
        return (
            x509.CertificateSigningRequestBuilder()
            .subject_name(
                x509.Name([
                    x509.NameAttribute(NameOID.COUNTRY_NAME, csr_config.dn.country),
                    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, csr_config.dn.state),
                    x509.NameAttribute(NameOID.LOCALITY_NAME, csr_config.dn.locality),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, csr_config.dn.organization),
                    x509.NameAttribute(NameOID.COMMON_NAME, csr_config.dn.common_name),
                ])
            )
        )

    def sign(self, csr_builder: x509.CertificateSigningRequestBuilder) -> None:
        self.csr = csr_builder.sign(self.key, hashes.SHA256())

    def write_csr(self, csr_config: X509CsrTemplate) -> None:
        if self.csr is None:
            raise RuntimeError("CSR not created/signed yet.")
        csr_config.csr_fp.write_bytes(self.csr.public_bytes(serialization.Encoding.PEM))

    def print_csr(self, with_instruction: bool = False) -> None:
        if self.csr is None:
            raise RuntimeError("CSR not created/signed yet.")
        if with_instruction:
            print("\n*** COPY THIS CSR BELOW || KOPIER DENNE CSR NEDENUNDER ***\n")
        print(self.csr.public_bytes(serialization.Encoding.PEM).decode("utf-8"))

    def process_csr(self, csr_config, print_csr=False):
        self.write_key(csr_config)
        self.create_csr(csr_config)
        self.sign(self.create_csr(csr_config))
        self.write_csr(csr_config)
        if print_csr:
            self.print_csr(with_instruction=True)
