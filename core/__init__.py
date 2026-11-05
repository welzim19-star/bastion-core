"""Core Domain Package for Bastion Audit Enterprise."""
# Apenas modelos puros e utilities de segurança (sem importar Engine ou Adapters)
from .models import Device, DeviceStatus, NetworkInterface, AuditEvent, AlertPayload
from .security import AuditLedger, sanitize_mac, sanitize_ip

__all__ = [
    "Device",
    "DeviceStatus",
    "NetworkInterface",
    "AuditEvent",
    "AlertPayload",
    "AuditLedger",
    "sanitize_mac",
    "sanitize_ip",
]
