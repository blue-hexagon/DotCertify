from dataclasses import dataclass
from typing import Optional

import uuid
from pathlib import Path

from src.x509_template import X509Template


@dataclass(kw_only=True)
class X509CsrTemplate(X509Template):
    csr_fp: Path | str
    cert_fp: Path | str
    endpoint_mac: Optional[str] = None

    def __post_init__(self) -> None:
        super().__post_init__()
        self.csr_fp = Path(self.output_directory / Path(self.csr_fp))
        self.cert_fp = Path(self.output_directory / Path(self.cert_fp))

        if not isinstance(self.dn.common_name, str):
            """ MAC addr as default CN """
            self.dn.common_name = self.get_device_mac()

    @staticmethod
    def get_device_mac() -> str:
        return ":".join(
            f"{(uuid.getnode() >> ele) & 0xff:02X}"
            for ele in range(40, -1, -8)
        )
