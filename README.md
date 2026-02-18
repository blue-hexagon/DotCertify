# DotCertify

DotCertify is a small Python toy project for experimenting with X.509 certificates, CSRs, and simple CA signing using the `cryptography` library.

It’s developed as a small playground for learning and testing certificate flows — not a production PKI toolkit.

## What it currently does

- Generate RSA private keys
- Create CSRs from simple DN templates
- Create a local CA cert
- Sign CSRs with the CA
- Validate cert signatures and fields
- Inspect certs / CSRs in readable form

## Example Usage
```python
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

```
## Requirements

- Python 3.11+

### Installation

```bash
git clone <repo-url>
cd DotCertify
python -m venv venv
pip install cryptography

# Windows
./venv/Scripts/activate

# macOS / Linux
source venv/bin/activate

python ./main.py
```