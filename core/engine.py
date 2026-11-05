"""
Bastion Audit v2.0 Enterprise - Core Orchestration Engine
Isolamento Galvânico: Orquestração de Domínio desacoplada de detalhes de infraestrutura.
"""
from __future__ import annotations

import signal
import sys
import threading
import time
from datetime import datetime
from typing import List, Optional

from config.settings import BastionConfig
from core.models import AlertPayload, AuditEvent, Device, DeviceStatus, NetworkInterface
from core.security import AuditLedger, sanitize_mac
from adapters.network_probe import NetworkProbe
from adapters.oui_resolver import OUIResolver
from adapters.storage_sqlite import SQLiteDeviceRepository
from adapters.device_intelligence import DeviceIntelligenceEngine, DeviceType
from adapters.host_defense import HostDefenseManager
from adapters.notifiers.base import BaseNotifier
from adapters.notifiers.webhook import WebhookNotifier
from adapters.notifiers.syslog_logger import SyslogNotifier
from telemetry.killcam_logger import get_logger, record_killcam, track_action
import json as _json

log = get_logger("BastionCore")


class BastionCoreEngine:
    """Motor central de auditoria, resiliência e inventário de rede."""

    def __init__(self, config: BastionConfig):
        self.config = config
        self._running = False
        self._shutdown_event = threading.Event()
        self._macs_lock = threading.Lock()
        self._last_report_ts = time.time()
        self.is_online: Optional[bool] = None

        # ─── Inicialização dos Adaptadores (Injeção de Dependências) ───────────
        self.audit_ledger = AuditLedger(self.config.storage.audit_log_path)
        self.storage = SQLiteDeviceRepository(self.config.storage.db_path)
        self.oui_resolver = OUIResolver()
        self.defense = HostDefenseManager(config=self.config.defense)
        self.network_probe = NetworkProbe(
            target_ip=self.config.agent.target_ip,
            ping_timeout_ms=self.config.agent.ping_timeout_ms,
            max_workers=self.config.agent.max_concurrent_pings,
        )

        self.notifiers: List[BaseNotifier] = [SyslogNotifier()]
        if self.config.notifications.webhook_url:
            self.notifiers.append(
                WebhookNotifier(
                    webhook_url=self.config.notifications.webhook_url,
                    webhook_type=self.config.notifications.webhook_type,
                    auth_header=self.config.notifications.webhook_auth_header,
                    alert_cooldown_seconds=self.config.agent.alert_cooldown_seconds,
                    require_tls=self.config.security.require_tls_verification,
                )
            )

        self.active_interface: Optional[NetworkInterface] = None
        self.intelligence = DeviceIntelligenceEngine(
            port_probe_timeout=0.55,
            http_timeout=2.0,
            max_open_ports=5,
        )

    def _broadcast_alert(self, alert: AlertPayload, alert_key: str = "default"):
        """Dispara o alerta para todos os notificadores configurados e grava no ledger imutável."""
        # 1. Registra no Ledger Criptográfico SHA-256
        self.audit_ledger.record_event(
            event_type=alert.title,
            source="BastionCoreEngine",
            severity=alert.severity,
            payload=alert.to_dict(),
        )

        # 2. Notifica Canais
        for notifier in self.notifiers:
            try:
                notifier.send_alert(alert, alert_key=alert_key)
            except Exception as e:
                log.error("Erro ao despachar notificador: %s", e)

    def startup(self):
        """Prepara o ambiente, descobre interfaces e registra evento de boot."""
        log.info("Inicializando Bastion Audit v%s...", self.config.agent.version)

        # Autodescoberta de Sub-rede & Interface
        if self.config.agent.base_subnet == "auto":
            self.active_interface = self.network_probe.detect_active_interface()
            effective_subnet = self.active_interface.cidr_subnet
        else:
            effective_subnet = self.config.agent.base_subnet

        log.info(
            "Alvo WAN: %s | Sub-rede Ativa: %s | Fabricantes OUI carregados: %d",
            self.config.agent.target_ip,
            effective_subnet,
            self.oui_resolver.total_vendors,
        )

        self._broadcast_alert(
            AlertPayload(
                title="SISTEMA INICIALIZADO",
                severity="INFO",
                message=f"Bastion Audit v{self.config.agent.version} ativo em modo Enterprise.",
                details={
                    "Alvo Monitorado": self.config.agent.target_ip,
                    "Sub-rede Auditada": effective_subnet,
                    "Total OUI Base": self.oui_resolver.total_vendors,
                },
            ),
            alert_key="startup",
        )

    def perform_radar_audit(self) -> int:
        """Executa uma rodada completa de Radar Sweep + ARP Discovery + Análise de Segurança."""
        subnet = (
            self.active_interface.cidr_subnet
            if self.active_interface
            else self.config.agent.base_subnet
        )
        if subnet == "auto":
            subnet = "192.168.1.0/24"

        # 1. Sweep de Ping em lotes para forçar resolução ARP do kernel
        self.network_probe.active_radar_sweep(subnet)

        # 2. Extração da tabela ARP filtrada
        arp_table = self.network_probe.get_arp_table()
        if not arp_table:
            return 0

        # 3. Verificação de Defesa do Host: Integridade do Gateway (Anti-ARP Spoofing)
        gateway_ip = self.active_interface.gateway if self.active_interface else None
        if gateway_ip and self.config.defense.enable_anti_arp_spoof:
            arp_anomaly = self.defense.check_gateway_integrity(arp_table, gateway_ip)
            if arp_anomaly:
                self._broadcast_alert(
                    AlertPayload(
                        title="ATAQUE ARP SPOOFING / MITM DETECTADO",
                        severity="CRITICAL",
                        message=arp_anomaly["message"],
                        details={
                            "Gateway IP": arp_anomaly["gateway_ip"],
                            "MAC Legítimo": arp_anomaly["legitimate_mac"],
                            "MAC Invasor": arp_anomaly["attacker_mac"],
                            "Ação Recomendada": "Travar Gateway ARP ou Bloquear Invasor na Central de Defesa",
                        },
                    ),
                    alert_key=f"arp_spoof_{arp_anomaly['attacker_mac']}",
                )

        with self._macs_lock:
            known_macs = self.storage.get_known_macs()

            # Caso seja o primeiro scan e baseline automática esteja ligada:
            if not known_macs and self.config.security.auto_authorize_baseline_on_first_run:
                baseline_devices = []
                for mac, ip in arp_table.items():
                    vendor = self.oui_resolver.lookup(mac)
                    # Fingerprinting completo na baseline inicial (todas as 11 lentes)
                    fp = self.intelligence.analyze(ip=ip, mac=mac, vendor=vendor)
                    # Usa OUI do banco se disponível, senão fingerprint
                    resolved_vendor = vendor if vendor != "Fabricante desconhecido" else (fp.http_banner or "")
                    device = Device(
                        mac=mac,
                        ip=ip,
                        vendor=vendor,
                        hostname=fp.hostname,
                        status=DeviceStatus.AUTHORIZED,
                        metadata={
                            "device_type": fp.device_type.value,
                            "os_hint": fp.os_fingerprint.value,
                            "is_mac_randomized": fp.is_mac_randomized,
                            "confidence_score": fp.confidence_score,
                            "evidence_json": _json.dumps(fp.evidence[:8]),
                        },
                    )
                    baseline_devices.append(device)
                self.storage.establish_baseline(baseline_devices)

                self._broadcast_alert(
                    AlertPayload(
                        title="BASELINE DE SEGURANÇA REGISTRADA",
                        severity="INFO",
                        message=f"{len(baseline_devices)} dispositivos autorizados na baseline inicial.",
                        details={"Dispositivos Cadastrados": len(baseline_devices)},
                    ),
                    alert_key="baseline",
                )
                return len(baseline_devices)

            # Detecção de novos dispositivos com fingerprinting
            new_devices_count = 0
            for mac, ip in arp_table.items():
                vendor = self.oui_resolver.lookup(mac)
                # Pipeline Red Team v3 — 11 lentes de fingerprinting
                fp = self.intelligence.analyze(ip=ip, mac=mac, vendor=vendor)

                device = Device(
                    mac=mac,
                    ip=ip,
                    vendor=vendor,
                    hostname=fp.hostname,
                    metadata={
                        "device_type": fp.device_type.value,
                        "os_hint": fp.os_fingerprint.value,
                        "is_mac_randomized": fp.is_mac_randomized,
                        "confidence_score": fp.confidence_score,
                        "evidence_json": _json.dumps(fp.evidence[:8]),
                    },
                )
                is_new = self.storage.upsert_device(device)

                if (is_new or mac not in known_macs) and self.storage.should_send_alert(
                    mac, dedup_hours=self.config.agent.dedup_hours
                ):
                    new_devices_count += 1
                    self._broadcast_alert(
                        AlertPayload(
                            title="ALERTA DE SEGURANÇA — NOVO ATIVO DETECTADO",
                            severity="WARNING",
                            message=f"Ativo não catalogado detectado na rede local.",
                            details={
                                "IP Alocado": ip,
                                "MAC Address": mac,
                                "Tipo de Dispositivo": fp.device_type.value,
                                "Sistema Operacional": fp.os_fingerprint.value,
                                "Fabricante (OUI)": vendor,
                                "Hostname": fp.hostname or "Não resolvido",
                                "MAC Randomizado": str(fp.is_mac_randomized),
                                "Portas Abertas": str(fp.open_ports) if fp.open_ports else "Nenhuma detectada",
                                "Confiança": f"{fp.confidence_score}%",
                                "Data Detecção": datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
                            },
                        ),
                        alert_key=f"mac_{mac}",
                    )
                    self.storage.mark_alert_sent(mac)

            return new_devices_count

    def _radar_loop(self):
        """Thread daemon responsável pelo radar contínuo."""
        scan_interval = (
            self.config.agent.ping_interval_seconds
            * self.config.agent.arp_scan_interval_multiplier
        )
        while not self._shutdown_event.is_set():
            try:
                self.perform_radar_audit()
            except Exception as e:
                record_killcam(e, custom_msg="Exceção no loop do radar daemon.")
            self._shutdown_event.wait(timeout=scan_interval)

    def _check_weekly_report(self):
        """Dispara relatório consolidado de integridade e inventário."""
        elapsed = time.time() - self._last_report_ts
        if elapsed < self.config.agent.report_interval_hours * 3600:
            return

        summary = self.storage.get_audit_summary()
        self._broadcast_alert(
            AlertPayload(
                title="RELATÓRIO CONSOLIDADO DE AUDITORIA",
                severity="INFO",
                message=f"Inventário Total: {summary['total_devices']} ativos monitorados.",
                details={
                    "Total de Ativos": summary["total_devices"],
                    "Autorizados": summary["authorized_devices"],
                    "Desconhecidos": summary["unknown_devices"],
                    "Período": "Últimos 7 dias",
                },
            ),
            alert_key="weekly_report",
        )
        self._last_report_ts = time.time()

    def run(self):
        """Loop principal com monitoramento de Keepalive WAN e Graceful Shutdown."""
        self.startup()
        self._running = True

        # Inicia thread do radar
        radar_thread = threading.Thread(
            target=self._radar_loop, name="BastionRadarDaemon", daemon=True
        )
        radar_thread.start()

        def _handle_signal(sig, frame):
            log.info("Sinal de encerramento recebido (%s). Parando...", sig)
            self.stop()

        try:
            signal.signal(signal.SIGINT, _handle_signal)
            signal.signal(signal.SIGTERM, _handle_signal)
        except Exception:
            pass

        while self._running and not self._shutdown_event.is_set():
            try:
                current_status = self.network_probe.ping(self.config.agent.target_ip)

                if self.is_online is None:
                    self.is_online = current_status
                    log.info("Conectividade inicial: %s", "ONLINE" if current_status else "OFFLINE")

                elif current_status and not self.is_online:
                    self.is_online = True
                    self._broadcast_alert(
                        AlertPayload(
                            title="LINK RESTABELECIDO",
                            severity="INFO",
                            message=f"Comunicação com o alvo `{self.config.agent.target_ip}` normalizada.",
                        ),
                        alert_key="link_up",
                    )

                elif not current_status and self.is_online:
                    self.is_online = False
                    self._broadcast_alert(
                        AlertPayload(
                            title="FALHA CRÍTICA DE LINK (DOWNTIME)",
                            severity="CRITICAL",
                            message=f"Perda total de comunicação com `{self.config.agent.target_ip}`.",
                        ),
                        alert_key="link_down",
                    )

                self._check_weekly_report()
                self._shutdown_event.wait(timeout=self.config.agent.ping_interval_seconds)

            except Exception as e:
                record_killcam(e, custom_msg="Exceção no loop de monitoramento de link.")
                self._shutdown_event.wait(timeout=self.config.agent.ping_interval_seconds)

        log.info("Bastion Audit encerrado com sucesso.")

    def stop(self):
        """Encerra a execução de forma graciosa."""
        self._running = False
        self._shutdown_event.set()

    def run_single_scan(self) -> int:
        """Modo CLI: executa uma varredura única e retorna o número de dispositivos."""
        self.startup()
        return self.perform_radar_audit()

    def verify_ledger_integrity(self) -> bool:
        """Valida a integridade da trilha de auditoria SHA-256."""
        valid, err, count = self.audit_ledger.verify_integrity()
        if valid:
            log.info("Trilha de auditoria 100%% ÍNTEGRA. Total de eventos auditados: %d", count)
            return True
        else:
            log.error("VIOLAÇÃO DE INTEGRIDADE NO AUDIT TRAIL: %s", err)
            return False
