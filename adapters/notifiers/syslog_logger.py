"""
Bastion Audit v2.0 Enterprise - Syslog & Structured Log Notifier
"""
from __future__ import annotations

import json
from adapters.notifiers.base import BaseNotifier
from core.models import AlertPayload
from telemetry.killcam_logger import get_logger

log = get_logger("BastionSyslog")


class SyslogNotifier(BaseNotifier):
    """Notificador local estruturado (Syslog / Console Telemetry)."""

    def send_alert(self, alert: AlertPayload, alert_key: str = "default") -> bool:
        structured_msg = json.dumps(alert.to_dict())
        if alert.severity == "CRITICAL":
            log.critical("[ALERT-CRITICAL] %s: %s", alert.title, alert.message)
        elif alert.severity == "WARNING":
            log.warning("[ALERT-WARN] %s: %s", alert.title, alert.message)
        else:
            log.info("[ALERT-INFO] %s: %s", alert.title, alert.message)
        return True
