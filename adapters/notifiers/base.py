"""
Bastion Audit v2.0 Enterprise - Base Notifier Interface (Port)
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from core.models import AlertPayload


class BaseNotifier(ABC):
    """Port abstrato para entrega de alertas e telemetria."""

    @abstractmethod
    def send_alert(self, alert: AlertPayload, alert_key: str = "default") -> bool:
        """Envia um alerta para o canal de destino."""
        pass
