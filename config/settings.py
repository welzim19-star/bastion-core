"""
Bastion Audit v2.0 Enterprise - Settings & Configuration Loader
Zero-Trust Secret Handling & Environment Resolution
"""
from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from typing import Any, Dict


def get_base_dir() -> str:
    """Resolve base directory safely for both script and PyInstaller frozen binary."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    # Check if inside package directory, return parent project root
    current = os.path.dirname(os.path.abspath(__file__))
    parent = os.path.dirname(current)
    if os.path.basename(current) == "config":
        return parent
    return current


@dataclass
class AgentSettings:
    name: str = "BastionAgent"
    version: str = "2.0.0-enterprise"
    environment: str = "production"
    target_ip: str = "8.8.8.8"
    interface_name: str = "auto"
    base_subnet: str = "auto"
    ping_interval_seconds: int = 5
    arp_scan_interval_multiplier: int = 3
    alert_cooldown_seconds: int = 60
    report_interval_hours: int = 168
    dedup_hours: int = 24
    ping_timeout_ms: int = 1500
    max_concurrent_pings: int = 30


@dataclass
class SecuritySettings:
    enable_immutable_audit_log: bool = True
    audit_hash_algorithm: str = "sha256"
    auto_authorize_baseline_on_first_run: bool = True
    require_tls_verification: bool = True


@dataclass
class NotificationSettings:
    webhook_url: str = ""
    webhook_auth_header: str = ""
    webhook_type: str = "discord"  # "discord", "slack", "generic_webhook", "halo_itsm"
    enable_syslog: bool = True
    syslog_host: str = ""
    syslog_port: int = 514


@dataclass
class DefenseSettings:
    defense_mode: str = "interactive"  # "interactive" (human-in-the-loop) ou "monitor_only"
    enable_anti_arp_spoof: bool = True
    enable_gateway_lock: bool = False
    protected_ports: list[int] = field(default_factory=lambda: [22, 5055, 3000, 5000, 8000, 8080, 4200])
    whitelist_ips: list[str] = field(default_factory=lambda: ["127.0.0.1", "::1"])


@dataclass
class StorageSettings:
    base_dir: str = field(default_factory=get_base_dir)
    db_filename: str = "bastion_inventory.db"
    audit_log_filename: str = "bastion_audit_trail.jsonl"
    system_log_filename: str = "bastion_system.log"

    @property
    def db_path(self) -> str:
        return os.path.join(self.base_dir, self.db_filename)

    @property
    def audit_log_path(self) -> str:
        return os.path.join(self.base_dir, self.audit_log_filename)

    @property
    def system_log_path(self) -> str:
        return os.path.join(self.base_dir, self.system_log_filename)


@dataclass
class BastionConfig:
    agent: AgentSettings = field(default_factory=AgentSettings)
    security: SecuritySettings = field(default_factory=SecuritySettings)
    notifications: NotificationSettings = field(default_factory=NotificationSettings)
    defense: DefenseSettings = field(default_factory=DefenseSettings)
    storage: StorageSettings = field(default_factory=StorageSettings)


def _deep_update(source: Dict[str, Any], overrides: Dict[str, Any]) -> Dict[str, Any]:
    for key, value in overrides.items():
        if isinstance(value, dict) and key in source and isinstance(source[key], dict):
            source[key] = _deep_update(source[key], value)
        else:
            source[key] = value
    return source


def load_config(config_path: str | None = None) -> BastionConfig:
    """Load configuration from JSON file with ENV variable overrides and fallback defaults."""
    base_dir = get_base_dir()

    if not config_path:
        # Check adjacent config file or in config/ subfolder
        candidates = [
            os.path.join(base_dir, "bastion_config.json"),
            os.path.join(base_dir, "config", "bastion_config.json"),
        ]
        for candidate in candidates:
            if os.path.isfile(candidate):
                config_path = candidate
                break

    raw_data: Dict[str, Any] = {}
    if config_path and os.path.isfile(config_path):
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                raw_data = json.load(f)
        except Exception:
            raw_data = {}

    agent_data = raw_data.get("agent", {})
    sec_data = raw_data.get("security", {})
    notif_data = raw_data.get("notifications", {})
    defense_data = raw_data.get("defense", {})
    stor_data = raw_data.get("storage", {})

    # Environment variable overrides (SecOps best practice)
    if "BASTION_TARGET_IP" in os.environ:
        agent_data["target_ip"] = os.environ["BASTION_TARGET_IP"]
    if "BASTION_BASE_SUBNET" in os.environ:
        agent_data["base_subnet"] = os.environ["BASTION_BASE_SUBNET"]
    if "BASTION_WEBHOOK_URL" in os.environ:
        notif_data["webhook_url"] = os.environ["BASTION_WEBHOOK_URL"]
    if "BASTION_WEBHOOK_TYPE" in os.environ:
        notif_data["webhook_type"] = os.environ["BASTION_WEBHOOK_TYPE"]
    if "BASTION_PING_INTERVAL" in os.environ:
        try:
            agent_data["ping_interval_seconds"] = int(os.environ["BASTION_PING_INTERVAL"])
        except ValueError:
            pass

    agent_settings = AgentSettings(**{k: v for k, v in agent_data.items() if k in AgentSettings.__annotations__})
    sec_settings = SecuritySettings(**{k: v for k, v in sec_data.items() if k in SecuritySettings.__annotations__})
    notif_settings = NotificationSettings(**{k: v for k, v in notif_data.items() if k in NotificationSettings.__annotations__})
    defense_settings = DefenseSettings(**{k: v for k, v in defense_data.items() if k in DefenseSettings.__annotations__})
    stor_settings = StorageSettings(
        base_dir=base_dir,
        **{k: v for k, v in stor_data.items() if k in ["db_filename", "audit_log_filename", "system_log_filename"]}
    )

    return BastionConfig(
        agent=agent_settings,
        security=sec_settings,
        notifications=notif_settings,
        defense=defense_settings,
        storage=stor_settings,
    )

