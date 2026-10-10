"""Runtime configuration, read from environment variables only. No secrets are hardcoded."""
from __future__ import annotations

import os
from dataclasses import dataclass, field


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def _bool(name: str, default: bool) -> bool:
    v = os.environ.get(name)
    return default if v is None else v.strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class Settings:
    db_path: str = field(default_factory=lambda: os.environ.get("SENTINEL_DB_PATH", "data/sentinel.db"))
    api_token: str | None = field(default_factory=lambda: os.environ.get("SENTINEL_API_TOKEN") or None)
    max_upload_bytes: int = field(default_factory=lambda: _int("SENTINEL_MAX_UPLOAD_MB", 25) * 1024 * 1024)
    max_events_per_upload: int = field(default_factory=lambda: _int("SENTINEL_MAX_EVENTS_PER_UPLOAD", 200_000))
    max_line_bytes: int = 64 * 1024
    max_raw_chars: int = 8192
    # LLM
    llm_provider: str = field(default_factory=lambda: os.environ.get("SENTINEL_LLM_PROVIDER", "none").lower())
    llm_model: str | None = field(default_factory=lambda: os.environ.get("SENTINEL_LLM_MODEL") or None)
    llm_api_key: str | None = field(default_factory=lambda: os.environ.get("SENTINEL_LLM_API_KEY") or None)
    llm_base_url: str | None = field(default_factory=lambda: os.environ.get("SENTINEL_LLM_BASE_URL") or None)
    llm_timeout: float = field(default_factory=lambda: float(os.environ.get("SENTINEL_LLM_TIMEOUT", "60")))
    agent_max_steps: int = field(default_factory=lambda: _int("SENTINEL_AGENT_MAX_STEPS", 8))
    agent_deadline: float = field(default_factory=lambda: float(os.environ.get("SENTINEL_AGENT_DEADLINE", "240")))
    # Wazuh (indexer-based)
    wazuh_url: str | None = field(default_factory=lambda: os.environ.get("SENTINEL_WAZUH_INDEXER_URL") or None)
    wazuh_user: str | None = field(default_factory=lambda: os.environ.get("SENTINEL_WAZUH_USER") or None)
    wazuh_password: str | None = field(default_factory=lambda: os.environ.get("SENTINEL_WAZUH_PASSWORD") or None)
    wazuh_verify_tls: bool = field(default_factory=lambda: _bool("SENTINEL_WAZUH_VERIFY_TLS", True))
    wazuh_ca_bundle: str | None = field(default_factory=lambda: os.environ.get("SENTINEL_WAZUH_CA_BUNDLE") or None)
    wazuh_index: str = field(default_factory=lambda: os.environ.get("SENTINEL_WAZUH_INDEX", "wazuh-alerts-*"))
    wazuh_poll_seconds: int = field(default_factory=lambda: _int("SENTINEL_WAZUH_POLL_SECONDS", 0))
    wazuh_live_window: int = field(default_factory=lambda: _int("SENTINEL_WAZUH_LIVE_WINDOW_SECONDS", 900))
    wazuh_max_per_poll: int = field(default_factory=lambda: _int("SENTINEL_WAZUH_MAX_PER_POLL", 5000))
    # Threat intelligence (optional, off unless a key is set)
    abuseipdb_key: str | None = field(default_factory=lambda: os.environ.get("SENTINEL_ABUSEIPDB_KEY") or None)
    # Detection thresholds JSON file (optional)
    detection_config: str | None = field(default_factory=lambda: os.environ.get("SENTINEL_DETECTION_CONFIG") or None)


def get_settings() -> Settings:
    return Settings()
