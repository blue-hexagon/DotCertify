import getpass

from pathlib import Path

from dataclasses import dataclass


@dataclass
class X509DN:
    country: str = "DK"
    organization: str = "University of Copenhagen"
    locality: str = "Copenhagen"
    state: str = "DK"
    common_name: str | None = None


@dataclass(kw_only=True)
class X509Template(X509DN):
    output_directory: Path | str
    key_fp: Path | str
    secret: bytes | None = None
    dn: X509DN

    def __post_init__(self) -> None:
        self.output_directory = Path(self.output_directory)
        self.output_directory.mkdir(parents=True, exist_ok=True)

        self.key_fp = self.output_directory / Path(self.key_fp)

    def set_secret(self, s: str) -> None:
        self.secret = s.encode("utf-8")

    def sec_secret_from_prompt(self, static_secret: str = None):
        """ static_secret must only be used for tests! """
        if static_secret:
            self.set_secret(static_secret)
        else:
            self.set_secret(getpass.getpass("Indtast kodeord (tom = ingen kryptering): "))
        return self
