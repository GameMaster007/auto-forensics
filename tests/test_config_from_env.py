from __future__ import annotations

from auto_forensics.config import AppConfig


def test_from_env_invalid_numbers_fall_back_to_defaults(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setenv("AUTO_FORENSICS_HOME", str(tmp_path))
    monkeypatch.setenv("AUTO_FORENSICS_PORT", "not-a-port")
    monkeypatch.setenv(
        "AUTO_FORENSICS_RATE_LIMIT_PER_MINUTE",
        "bad-rate",
    )
    monkeypatch.setenv("AUTO_FORENSICS_MAX_FILE_SIZE_BYTES", "oops")
    monkeypatch.setenv(
        "AUTO_FORENSICS_ENRICHMENT_BACKOFF_BASE_SECONDS",
        "oops-float",
    )
    monkeypatch.setenv("AUTO_FORENSICS_DB_POOL_SIZE", "bad-size")
    monkeypatch.setenv("AUTO_FORENSICS_WATCH_INTERVAL", "bad-interval")

    config = AppConfig.from_env()

    assert config.port == 8765
    assert config.rate_limit_per_minute == 240
    assert config.security_policy.max_file_size_bytes == 100 * 1024 * 1024
    assert config.enrichment_backoff_base_seconds == 0.75
    assert config.db_pool_size == 5
    assert config.watch_interval == 30


def test_from_env_bool_parsing_supports_common_truthy_falsey_values(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setenv("AUTO_FORENSICS_HOME", str(tmp_path))
    monkeypatch.setenv("AUTO_FORENSICS_FOLLOW_SYMLINKS", "yes")
    monkeypatch.setenv("AUTO_FORENSICS_ENABLE_WHOIS", "1")
    monkeypatch.setenv("AUTO_FORENSICS_AUTO_EXTRACT", "off")

    config = AppConfig.from_env()

    assert config.security_policy.follow_symlinks is True
    assert config.enable_whois_lookup is True
    assert config.auto_extract is False


def test_from_env_invalid_bool_uses_default(monkeypatch, tmp_path):
    monkeypatch.setenv("AUTO_FORENSICS_HOME", str(tmp_path))
    monkeypatch.setenv("AUTO_FORENSICS_AUTO_EXTRACT", "not-a-bool")

    config = AppConfig.from_env()

    assert config.auto_extract is True
