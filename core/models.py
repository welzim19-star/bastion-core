"""
Bastion Audit v2.0 Enterprise - Domain Models
Modelos estritos e imutáveis para representação de ativos e eventos de auditoria.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, Optional


class DeviceStatus(str, Enum):
    AUTHORIZED = "authorized"
    UNKNOWN = "unknown"
    SUSPICIOUS = "suspicious"
    QUARANTINED = "quarantined"


@dataclass(frozen=True)
class Device:
    mac: str
    ip: str = "0.0.0.0"
    vendor: str = "Fabricante desconhecido"
    first_seen: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    last_seen: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    alert_sent: Optional[str] = None
    status: DeviceStatus = DeviceStatus.UNKNOWN
    hostname: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        return data


@dataclass(frozen=True)
class NetworkInterface:
    name: str
    ip_address: str
    netmask: str
    cidr_subnet: str
    gateway: Optional[str] = None
    mac_address: Optional[str] = None
    is_up: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class AuditEvent:
    event_id: str
    timestamp: str
    event_type: str  # e.g., "DEVICE_DISCOVERED", "LINK_DOWN", "LINK_RESTORED", "BASELINE_CREATED"
    source: str
    severity: str  # "INFO", "WARNING", "CRITICAL", "AUDIT"
    payload: Dict[str, Any]
    previous_hash: str
    entry_hash: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class AlertPayload:
    title: str
    severity: str  # "INFO", "WARNING", "CRITICAL"
    message: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
