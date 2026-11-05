"""
Bastion Audit v2.0 Enterprise - Webhook Notifier Adapter
Suporte a Discord, Slack, HaloITSM e SIEMs corporativos com rate limiting e headers de autenticação.
"""
from __future__ import annotations

import json
import ssl
import time
import urllib.request
from typing import Dict, Optional

from adapters.notifiers.base import BaseNotifier
from core.models import AlertPayload
from telemetry.killcam_logger import get_logger, track_action

log = get_logger("BastionWebhook")


class WebhookNotifier(BaseNotifier):
    """Adaptador de entrega de alertas via HTTP/HTTPS Webhook com resiliência a falhas."""

    def __init__(
        self,
        webhook_url: str,
        webhook_type: str = "discord",
        auth_header: str = "",
        alert_cooldown_seconds: int = 60,
        require_tls: bool = True,
    ):
        self.webhook_url = webhook_url
        self.webhook_type = webhook_type.lower()
        self.auth_header = auth_header
        self.alert_cooldown = alert_cooldown_seconds
        self.require_tls = require_tls
        self._last_alert_ts: Dict[str, float] = {}

    def send_alert(self, alert: AlertPayload, alert_key: str = "default") -> bool:
        if not self.webhook_url:
            return False

        now = time.time()
        last_ts = self._last_alert_ts.get(alert_key, 0.0)
        if now - last_ts < self.alert_cooldown:
            return False

        self._last_alert_ts[alert_key] = now
        payload = self._format_payload(alert)
        data = json.dumps(payload).encode("utf-8")

        headers = {
            "Content-Type": "application/json",
            "User-Agent": "BastionAudit-Enterprise/2.0",
        }
        if self.auth_header:
            headers["Authorization"] = self.auth_header

        ssl_ctx = ssl.create_default_context()
        if not self.require_tls:
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

        with track_action(action="http_webhook_dispatch", target=self.webhook_url[:35] + "..."):
            try:
                req = urllib.request.Request(self.webhook_url, data=data, headers=headers)
                with urllib.request.urlopen(req, timeout=10, context=ssl_ctx) as resp:
                    if resp.status in (200, 204):
                        return True
                    if resp.status == 429:
                        log.warning("Rate limit (HTTP 429) retornado pelo Webhook.")
                        return False
                return True
            except Exception as e:
                log.error("Falha ao entregar alerta via Webhook (%s): %s", self.webhook_type, e)
                return False

    def _format_payload(self, alert: AlertPayload) -> Dict:
        if self.webhook_type == "discord":
            severity_colors = {
                "INFO": 0x3498DB,      # Azul
                "WARNING": 0xE67E22,   # Laranja
                "CRITICAL": 0xE74C3C,  # Vermelho
            }
            color = severity_colors.get(alert.severity.upper(), 0x95A5A6)

            fields = []
            for k, v in alert.details.items():
                fields.append({"name": str(k), "value": f"`{v}`", "inline": True})

            return {
                "embeds": [
                    {
                        "title": alert.title,
                        "description": alert.message,
                        "color": color,
                        "fields": fields,
                        "footer": {"text": f"Bastion Enterprise · {alert.timestamp}"},
                    }
                ]
            }

        elif self.webhook_type == "slack":
            return {
                "text": f"*{alert.title}* [{alert.severity}]\n{alert.message}",
            }

        else:
            # Generic JSON / HaloITSM / SIEM
            return alert.to_dict()
