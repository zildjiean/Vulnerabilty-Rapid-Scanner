from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from pathlib import Path


def _load_or_create_secret(path: Path) -> str:
    if path.exists():
        return path.read_text().strip()
    key = secrets.token_urlsafe(48)
    path.write_text(key)
    path.chmod(0o600)
    return key


@dataclass
class Settings:
    data_dir: Path
    nmap_bin: str = "nmap"
    nuclei_bin: str = "nuclei"
    secret_key: str = ""
    https: bool = False
    nuclei_templates_dir: Path | None = None
    custom_templates_dir: Path | None = None

    def __post_init__(self) -> None:
        self.data_dir = Path(self.data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        if self.nuclei_templates_dir is None:
            self.nuclei_templates_dir = self.data_dir / "nuclei-templates"
        self.nuclei_templates_dir = Path(self.nuclei_templates_dir)
        if self.custom_templates_dir is None:
            self.custom_templates_dir = self.data_dir / "custom-templates"
        self.custom_templates_dir = Path(self.custom_templates_dir)
        self.custom_templates_dir.mkdir(parents=True, exist_ok=True)
        (self.data_dir / "jobs").mkdir(parents=True, exist_ok=True)
        if not self.secret_key:
            self.secret_key = _load_or_create_secret(self.data_dir / "secret_key")

    @property
    def db_url(self) -> str:
        return f"sqlite:///{self.data_dir / 'scanner.db'}"

    @property
    def jobs_dir(self) -> Path:
        return self.data_dir / "jobs"


def settings_from_env() -> Settings:
    def opt_path(name: str) -> Path | None:
        v = os.environ.get(name)
        return Path(v) if v else None

    return Settings(
        data_dir=Path(os.environ.get("DATA_DIR", "/data")),
        nmap_bin=os.environ.get("NMAP_BIN", "nmap"),
        nuclei_bin=os.environ.get("NUCLEI_BIN", "nuclei"),
        secret_key=os.environ.get("SECRET_KEY", ""),
        https=os.environ.get("HTTPS", "0") == "1",
        nuclei_templates_dir=opt_path("NUCLEI_TEMPLATES_DIR"),
        custom_templates_dir=opt_path("CUSTOM_TEMPLATES_DIR"),
    )
