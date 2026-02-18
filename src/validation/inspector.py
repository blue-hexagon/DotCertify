from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization


class Inspector:

    # -------------------------
    # LOAD
    # -------------------------

    @staticmethod
    def load_cert(path):
        return x509.load_pem_x509_certificate(Path(path).read_bytes())

    @staticmethod
    def load_csr(path):
        return x509.load_pem_x509_csr(Path(path).read_bytes())

    @staticmethod
    def load_key(path, password=None):
        return serialization.load_pem_private_key(
            Path(path).read_bytes(),
            password=password
        )

    # -------------------------
    # CERT INSPECT
    # -------------------------

    @staticmethod
    def inspect_cert(cert: x509.Certificate):

        print("\n=== CERTIFICATE ===")

        print("Subject:", cert.subject.rfc4514_string())
        print("Issuer :", cert.issuer.rfc4514_string())

        print("Serial :", hex(cert.serial_number))

        print("Valid from:", cert.not_valid_before_utc)
        print("Valid to  :", cert.not_valid_after_utc)

        print("Signature hash:", cert.signature_hash_algorithm.name)

        print("Fingerprint SHA256:",
              cert.fingerprint(hashes.SHA256()).hex())

        pub = cert.public_key()
        print("Public key type:", pub.__class__.__name__)

        if hasattr(pub, "key_size"):
            print("Key size:", pub.key_size)

        Inspector._inspect_extensions(cert)

    # -------------------------
    # CSR INSPECT
    # -------------------------

    @staticmethod
    def inspect_csr(csr: x509.CertificateSigningRequest):

        print("\n=== CSR ===")

        print("Subject:", csr.subject.rfc4514_string())
        print("Signature hash:", csr.signature_hash_algorithm.name)

        pub = csr.public_key()
        print("Public key type:", pub.__class__.__name__)

        if hasattr(pub, "key_size"):
            print("Key size:", pub.key_size)

        for ext in csr.extensions:
            print("CSR Extension:", ext.oid._name, ext.value)

    # -------------------------
    # KEY INSPECT
    # -------------------------

    @staticmethod
    def inspect_key(key):

        print("\n=== PRIVATE KEY ===")

        print("Type:", key.__class__.__name__)

        if hasattr(key, "key_size"):
            print("Key size:", key.key_size)

        pub = key.public_key()

        print("Public numbers hash:",
              hash(pub.public_bytes(
                  serialization.Encoding.DER,
                  serialization.PublicFormat.SubjectPublicKeyInfo
              )))

    # -------------------------
    # EXTENSIONS
    # -------------------------

    @staticmethod
    def _inspect_extensions(cert):

        print("\n--- Extensions ---")

        for ext in cert.extensions:

            print(f"\n{ext.oid._name}:")

            val = ext.value

            if isinstance(val, x509.BasicConstraints):
                print("  CA:", val.ca)
                print("  Path length:", val.path_length)

            elif isinstance(val, x509.KeyUsage):
                print(" ", val)

            elif isinstance(val, x509.ExtendedKeyUsage):
                print(" ", [oid._name for oid in val])

            elif isinstance(val, x509.SubjectAlternativeName):
                print(" ", val.get_values_for_type(x509.DNSName))
                print(" ", val.get_values_for_type(x509.IPAddress))

            else:
                print(" ", val)
