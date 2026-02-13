"""Pydantic settings for NetSentinel configuration."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


_DEFAULT_PORTS = [22, 80, 443, 445, 548, 8080, 62078, 5353]


def _load_yaml_config() -> dict[str, Any]:
    """Load config from ~/.netsentinel/config.yaml, falling back to project config.yaml."""
    user_cfg = Path.home() / ".netsentinel" / "config.yaml"
    if user_cfg.exists():
        with open(user_cfg) as f:
            return yaml.safe_load(f) or {}
    project_cfg = Path(__file__).parent.parent / "config.yaml"
    if project_cfg.exists():
        with open(project_cfg) as f:
            return yaml.safe_load(f) or {}
    return {}


class Settings(BaseSettings):
    """NetSentinel application settings.

    Priority (highest → lowest): environment variables → config.yaml → defaults.
    """

    model_config = SettingsConfigDict(
        env_prefix="NETSENTINEL_",
        env_nested_delimiter="__",
    )

    # Network
    interface: str | None = None
    subnet: str | None = None
    scan_interval: int = 30
    scan_timeout: int = 3
    max_concurrent_fingerprint: int = 20
    quick_scan_ports: list[int] = Field(default_factory=lambda: list(_DEFAULT_PORTS))

    # API
    api_host: str = "127.0.0.1"
    api_port: int = 8555

    # Logging
    log_level: str = "INFO"

    # Database
    db_path: str | None = None

    # Thresholds
    offline_threshold: int = 300

    @model_validator(mode="before")
    @classmethod
    def _merge_yaml(cls, values: dict[str, Any]) -> dict[str, Any]:
        yaml_values = _load_yaml_config()
        # YAML values serve as defaults — explicit env/init values take priority
        merged = {**yaml_values, **{k: v for k, v in values.items() if v is not None}}
        return merged

    @property
    def resolved_db_path(self) -> Path:
        if self.db_path:
            return Path(self.db_path)
        return Path.home() / ".netsentinel" / "devices.db"

    @property
    def data_dir(self) -> Path:
        d = Path.home() / ".netsentinel"
        d.mkdir(parents=True, exist_ok=True)
        return d


def get_settings(**overrides: Any) -> Settings:
    """Create a Settings instance, optionally with overrides."""
    return Settings(**overrides)
