from src.ca.builder import CaBuilder
from src.ca.ca_tpl import X509CaTemplate
from src.csr.builder import CsrBuilder
from src.csr.csr_tpl import X509CsrTemplate

from src.validation.inspector import Inspector
from src.validation.validator import Validator
from src.x509_template import X509DN

if __name__ == '__main__':
    # Create CSRs
    # Takes either a list of X509CsrTemplate or a single X509CsrTemplate
    # Remove the static_password from sec_secret_from_prompt to prompt for it..
    CsrBuilder([
        csr1 := X509CsrTemplate(
            output_directory="./client1",
            key_fp="endpoint.key",
            csr_fp="endpoint.csr",
            cert_fp="endpoint.crt",
            dn=X509DN(
                country="DK",
                organization="Org-Name",
                locality="Copenhagen",
                state="Hovedstaden",
            )
        ).sec_secret_from_prompt(static_secret="1234!Pass!"),
        csr2 := X509CsrTemplate(
            output_directory="./client2",
            key_fp="endpoint.key",
            csr_fp="endpoint.csr",
            cert_fp="endpoint.crt",
            dn=X509DN(
                country="DK",
                organization="Org-Name",
                locality="Copenhagen",
                state="Hovedstaden",
            )
        ).sec_secret_from_prompt(static_secret="Pass1234!")])

    # Create the CA
    ca = CaBuilder(
        X509CaTemplate(
            output_directory="./ca",
            key_fp="ca.key",
            cert_fp="ca.crt",
            ca_days_lifetime=365,
            dn=X509DN(
                country="DK",
                organization="Org-Name",
                locality="Copenhagen",
                state="Hovedstaden",
                common_name="Org-Name Root CA"
            )
        ).sec_secret_from_prompt(static_secret="SuperSecretPassword1234!")
    ).create_key().create_ca()

    # Sign the CSRs
    ca.sign_csr(csr_config=csr1)
    ca.sign_csr(csr_config=csr2)

    # Inspect a certificate
    cert = Inspector.load_cert("./client1/endpoint.crt")
    Inspector.inspect_cert(cert)

    # Inspect a CSR
    csr = Inspector.load_csr("./client2/endpoint.csr")
    Inspector.inspect_csr(csr)

    # Various validation
    try:
        key = Inspector.load_key("./client1/endpoint.key", b"Kode1234!")
        Inspector.inspect_key(key)
    except ValueError as e:
        print(f"\n{e}")

    try:
        Validator.validate_endpoint_cert(
            cert_path="./client1/endpoint.crt",
            ca_path="./ca/ca.crt",
            key_path="./client1/endpoint.key",
            key_password=b"Kode1234!",
            expected_cn="B8:1E:A4:33:70:40"
        )
    except ValueError as e:
        print(f"\n{e}")

    csr = Validator.load_csr("./client2/endpoint.csr")
    Validator.assert_csr_signature_valid(csr)
