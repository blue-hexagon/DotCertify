from dataclasses import dataclass

from pathlib import Path

from src.x509.base_tpl import X509Template


@dataclass(kw_only=True)
class X509CaTemplate(X509Template):
    cert_fp: Path | str
    ca_days_lifetime: int

    def __post_init__(self) -> None:
        super().__post_init__()
        self.cert_fp = self.output_directory / Path(self.cert_fp)
