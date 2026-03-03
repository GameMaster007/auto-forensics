from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from pathlib import Path

from .security import SecurityPolicy


def _default_data_dir() -> Path:
    base = os.getenv("AUTO_FORENSICS_HOME")
    if base:
        return Path(base).expanduser().resolve()
    return (Path.home() / ".auto_forensics").resolve()


def _parse_csv_env(name: str, default: str) -> list[str]:
    value = os.getenv(name, default)
    return [item.strip() for item in value.split(",") if item.strip()]


def _parse_path_list_env(name: str, default: str) -> list[Path]:
    return [Path(p).expanduser().resolve() for p in _parse_csv_env(name, default)]


def _hash_api_key(raw: str | None) -> str | None:
    if not raw:
        return None
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _parse_optional_path_env(name: str) -> Path | None:
    value = os.getenv(name)
    if not value:
        return None
    return Path(value).expanduser().resolve()


@dataclass(slots=True)
class AppConfig:
    data_dir: Path
    cases_dir: Path
    db_path: Path
    host: str
    port: int
    production: bool
    api_key_hash: str | None
    allowed_origins: list[str]
    trusted_hosts: list[str]
    allowed_ingest_roots: list[Path]
    rate_limit_per_minute: int
    llama_endpoint: str
    llama_model: str
    security_policy: SecurityPolicy
    plugin_dirs: list[Path] = field(default_factory=list)
    rules_dir: Path | None = None
    sigma_rules_dir: Path | None = None
    attack_stix_path: Path | None = None
    database_url: str | None = None
    openai_compatible_endpoint: str | None = None
    openai_api_key: str | None = None
    virustotal_api_key: str | None = None
    malwarebazaar_api_key: str | None = None
    abuseipdb_api_key: str | None = None
    enable_whois_lookup: bool = False
    enrichment_cache_ttl_minutes: int = 24 * 60
    enrichment_http_retries: int = 2
    enrichment_backoff_base_seconds: float = 0.75
    enrichment_backoff_max_seconds: float = 8.0
    db_pool_size: int = 5
    db_max_overflow: int = 10
    db_pool_timeout_seconds: int = 30
    db_pool_recycle_seconds: int = 1800
    job_retention_days: int = 30
    watch_dir: Path | None = None
    watch_interval: int = 30
    auto_extract: bool = True

    def __post_init__(self) -> None:
        self.plugin_dirs = [p.expanduser().resolve() for p in self.plugin_dirs] if self.plugin_dirs else []
        if not self.plugin_dirs:
            self.plugin_dirs = [(self.data_dir / "plugins").resolve()]

        if self.rules_dir is None:
            self.rules_dir = (self.data_dir / "rules").resolve()
        else:
            self.rules_dir = self.rules_dir.expanduser().resolve()

        if self.attack_stix_path is None:
            self.attack_stix_path = (self.data_dir / "attack" / "enterprise-attack.json").resolve()
        else:
            self.attack_stix_path = self.attack_stix_path.expanduser().resolve()

        if self.sigma_rules_dir is None:
            base_rules = self.rules_dir if self.rules_dir is not None else (self.data_dir / "rules")
            self.sigma_rules_dir = (base_rules / "sigma").resolve()
        else:
            self.sigma_rules_dir = self.sigma_rules_dir.expanduser().resolve()

    @classmethod
    def from_env(cls) -> "AppConfig":
        data_dir = _default_data_dir()
        cases_dir = data_dir / "cases"
        db_path = data_dir / "app.db"
        production = os.getenv("AUTO_FORENSICS_ENV", "dev").lower() == "prod"
        return cls(
            data_dir=data_dir,
            cases_dir=cases_dir,
            db_path=db_path,
            host=os.getenv("AUTO_FORENSICS_HOST", "127.0.0.1"),
            port=int(os.getenv("AUTO_FORENSICS_PORT", "8765")),
            production=production,
            api_key_hash=_hash_api_key(os.getenv("AUTO_FORENSICS_API_KEY")),
            allowed_origins=_parse_csv_env("AUTO_FORENSICS_ALLOWED_ORIGINS", ""),
            trusted_hosts=_parse_csv_env("AUTO_FORENSICS_TRUSTED_HOSTS", "127.0.0.1,localhost"),
            allowed_ingest_roots=_parse_path_list_env(
                "AUTO_FORENSICS_ALLOWED_INGEST_ROOTS",
                str(Path.home()),
            ),
            rate_limit_per_minute=int(os.getenv("AUTO_FORENSICS_RATE_LIMIT_PER_MINUTE", "240")),
            llama_endpoint=os.getenv("AUTO_FORENSICS_LLAMA_ENDPOINT", "http://localhost:11434"),
            llama_model=os.getenv("AUTO_FORENSICS_LLAMA_MODEL", "llama3.1:8b"),
            security_policy=SecurityPolicy(
                max_file_size_bytes=int(
                    os.getenv("AUTO_FORENSICS_MAX_FILE_SIZE_BYTES", str(100 * 1024 * 1024))
                ),
                max_total_files=int(os.getenv("AUTO_FORENSICS_MAX_TOTAL_FILES", "200000")),
                max_text_bytes=int(
                    os.getenv("AUTO_FORENSICS_MAX_TEXT_BYTES", str(4 * 1024 * 1024))
                ),
                follow_symlinks=os.getenv("AUTO_FORENSICS_FOLLOW_SYMLINKS", "false").lower()
                == "true",
            ),
            plugin_dirs=_parse_path_list_env(
                "AUTO_FORENSICS_PLUGIN_DIRS",
                str(data_dir / "plugins"),
            ),
            rules_dir=_parse_optional_path_env("AUTO_FORENSICS_RULES_DIR") or (data_dir / "rules"),
            sigma_rules_dir=_parse_optional_path_env("AUTO_FORENSICS_SIGMA_RULES_DIR")
            or (data_dir / "rules" / "sigma"),
            attack_stix_path=_parse_optional_path_env("AUTO_FORENSICS_ATTACK_STIX_PATH")
            or (data_dir / "attack" / "enterprise-attack.json"),
            database_url=os.getenv("AUTO_FORENSICS_DATABASE_URL"),
            openai_compatible_endpoint=os.getenv("AUTO_FORENSICS_OPENAI_ENDPOINT"),
            openai_api_key=os.getenv("AUTO_FORENSICS_OPENAI_API_KEY"),
            virustotal_api_key=os.getenv("AUTO_FORENSICS_VIRUSTOTAL_API_KEY"),
            malwarebazaar_api_key=os.getenv("AUTO_FORENSICS_MALWAREBAZAAR_API_KEY"),
            abuseipdb_api_key=os.getenv("AUTO_FORENSICS_ABUSEIPDB_API_KEY"),
            enable_whois_lookup=os.getenv("AUTO_FORENSICS_ENABLE_WHOIS", "false").lower() == "true",
            enrichment_cache_ttl_minutes=int(
                os.getenv("AUTO_FORENSICS_ENRICHMENT_CACHE_TTL_MINUTES", str(24 * 60))
            ),
            enrichment_http_retries=int(os.getenv("AUTO_FORENSICS_ENRICHMENT_HTTP_RETRIES", "2")),
            enrichment_backoff_base_seconds=float(
                os.getenv("AUTO_FORENSICS_ENRICHMENT_BACKOFF_BASE_SECONDS", "0.75")
            ),
            enrichment_backoff_max_seconds=float(
                os.getenv("AUTO_FORENSICS_ENRICHMENT_BACKOFF_MAX_SECONDS", "8.0")
            ),
            db_pool_size=int(os.getenv("AUTO_FORENSICS_DB_POOL_SIZE", "5")),
            db_max_overflow=int(os.getenv("AUTO_FORENSICS_DB_MAX_OVERFLOW", "10")),
            db_pool_timeout_seconds=int(os.getenv("AUTO_FORENSICS_DB_POOL_TIMEOUT_SECONDS", "30")),
            db_pool_recycle_seconds=int(os.getenv("AUTO_FORENSICS_DB_POOL_RECYCLE_SECONDS", "1800")),
            job_retention_days=int(os.getenv("AUTO_FORENSICS_JOB_RETENTION_DAYS", "30")),
            watch_dir=_parse_optional_path_env("AUTO_FORENSICS_WATCH_DIR"),
            watch_interval=int(os.getenv("AUTO_FORENSICS_WATCH_INTERVAL", "30")),
            auto_extract=os.getenv("AUTO_FORENSICS_AUTO_EXTRACT", "true").lower() == "true",
        )

    def ensure_dirs(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.cases_dir.mkdir(parents=True, exist_ok=True)
        for plugin_dir in self.plugin_dirs:
            plugin_dir.mkdir(parents=True, exist_ok=True)
        if self.rules_dir:
            self.rules_dir.mkdir(parents=True, exist_ok=True)
        if self.sigma_rules_dir:
            self.sigma_rules_dir.mkdir(parents=True, exist_ok=True)
        if self.attack_stix_path:
            self.attack_stix_path.parent.mkdir(parents=True, exist_ok=True)
        if self.watch_dir:
            self.watch_dir.mkdir(parents=True, exist_ok=True)
