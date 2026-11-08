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
from adapters.device_intelligence import DeviceIntelligenceEngine, DeviceType, OSFingerprint
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
        self.defense = HostDefenseManager(
            config=self.config.defense,
            on_intrusion_callback=self._on_honeyport_intrusion,
        )
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

    def _on_honeyport_intrusion(self, hit_data: dict):
        """Callback acionado quando o sensor Honeyport detecta varredura ou tentativa de intrusão."""
        attacker_ip = hit_data.get("attacker_ip", "0.0.0.0")
        trap_port = hit_data.get("trap_port", 0)
        decoy = hit_data.get("decoy_service", "Decoy")
        self._broadcast_alert(
            AlertPayload(
                title="HONEYPORT — VARREDURA DE PORTAS / INTRUSÃO DETECTADA",
                severity="CRITICAL",
                message=f"O host {attacker_ip} tentou conexão na porta isca {trap_port} ({decoy}).",
                details={
                    "IP Atacante": attacker_ip,
                    "Porta Isca Tocada": str(trap_port),
                    "Serviço Isca": decoy,
                    "Amostra Payload": hit_data.get("payload_sample", ""),
                    "Bloqueio Automático": "SIM" if hit_data.get("auto_blocked") else "NÃO (Modo Interativo)",
                },
            ),
            alert_key=f"honeyport_{attacker_ip}_{trap_port}",
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

        # Atualiza imediatamente OUI e heurística L11 para registros existentes no banco
        try:
            self.reclassify_all_devices(active_network_probe=False)
        except Exception as e:
            log.debug("Erro ao atualizar heurística inicial: %s", e)

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
                            "hardware_model": fp.hardware_model or "",
                            "is_mac_randomized": fp.is_mac_randomized,
                            "confidence_score": fp.confidence_score,
                            "open_ports": fp.open_ports,
                            "http_banner": fp.http_banner or "",
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
                existing_dev = self.storage.get_device(mac)
                # Pipeline de Handshake & Identificação (Zero Alucinação)
                fp = self.intelligence.analyze(ip=ip, mac=mac, vendor=vendor)

                eff_host = fp.hostname or (existing_dev.hostname if existing_dev else None)
                eff_model = fp.hardware_model or ""
                if eff_host and eff_model in ("", "Celular / Aparelho Wi-Fi (MAC Privado)", "Smartphone Android"):
                    if fp.device_type == DeviceType.ANDROID_DEVICE:
                        eff_model = f"Celular Android (ID: {eff_host})"

                device = Device(
                    mac=mac,
                    ip=ip,
                    vendor=vendor,
                    hostname=eff_host,
                    metadata={
                        "device_type": fp.device_type.value,
                        "os_hint": fp.os_fingerprint.value,
                        "hardware_model": eff_model,
                        "is_mac_randomized": fp.is_mac_randomized,
                        "confidence_score": fp.confidence_score,
                        "open_ports": fp.open_ports,
                        "http_banner": fp.http_banner or "",
                        "evidence_json": _json.dumps(fp.evidence[:8], ensure_ascii=False),
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
                                "Fabricante": vendor,
                                "Hostname / ID": eff_host or "Não resolvido",
                                "MAC Randomizado": str(fp.is_mac_randomized),
                                "Portas Abertas": str(fp.open_ports) if fp.open_ports else "Nenhuma detectada",
                                "Confiança": f"{fp.confidence_score}%",
                                "Data Detecção": datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
                            },
                        ),
                        alert_key=f"mac_{mac}",
                    )
                    self.storage.mark_alert_sent(mac)

            # Move para Inativos (0.0.0.0) aparelhos antigos que já saíram da rede
            try:
                self.storage.reconcile_online_devices(set(arp_table.keys()), max_idle_minutes=45)
            except Exception as e:
                log.debug("Erro ao reconciliar ativos inativos: %s", e)

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

        # Inicia escuta passiva mDNS Multicast (captura ID/Modelo de celulares assim que acendem a tela)
        mdns_thread = threading.Thread(
            target=self._passive_mdns_listener, name="BastionPassiveMDNS", daemon=True
        )
        mdns_thread.start()

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
        try:
            self.defense.stop_honeyport_traps()
        except Exception:
            pass

    def _passive_mdns_listener(self):
        """
        Escuta passivamente pacotes mDNS Multicast (224.0.0.251:5353).
        Assim que um celular acende a tela e anuncia seu ID (ex: Android_XXXX, iPhone) ou
        Google Quick Share / Apple Continuity, captura o nome/modelo em tempo real!
        """
        import socket
        import struct
        from adapters.device_intelligence import _parse_mdns_wire_packet, translate_hardware_model

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("", 5353))
            mreq = struct.pack("4sl", socket.inet_aton("224.0.0.251"), socket.INADDR_ANY)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            sock.settimeout(2.0)
        except Exception as e:
            log.debug("Passive mDNS listener indisponível na porta 5353: %s", e)
            return

        while self._running and not self._shutdown_event.is_set():
            try:
                data, addr = sock.recvfrom(4096)
                src_ip = addr[0]
                if not src_ip or src_ip.startswith("127."):
                    continue

                parsed = {
                    "hostname": None,
                    "services": [],
                    "model_hint": None,
                    "friendly_name": None,
                    "spotify_port": None,
                    "spotify_cpath": None,
                    "raw_strings": [],
                }
                _parse_mdns_wire_packet(data, parsed)
                host = parsed.get("hostname")
                fn = parsed.get("friendly_name")
                mdl = parsed.get("model_hint")
                if not (host or fn or mdl):
                    continue

                # Busca qual MAC detém atualmente este IP no banco
                all_devs = self.storage.get_all_devices()
                target_dev = next((d for d in all_devs if d.ip == src_ip), None)
                if not target_dev:
                    continue

                meta = target_dev.metadata or {}
                is_manual = bool(meta.get("manual_override"))
                eff_host = fn or host or target_dev.hostname
                updates = {}

                exact = translate_hardware_model(" | ".join(filter(None, [mdl or "", fn or "", host or ""])))
                if exact and not is_manual:
                    updates["hardware_model"] = exact[0]
                elif mdl and not is_manual:
                    updates["hardware_model"] = mdl
                elif eff_host and not is_manual and meta.get("hardware_model") in ("", None, "Celular / Aparelho Wi-Fi (MAC Privado)", "Smartphone Android"):
                    if target_dev.vendor == "MAC Privado (Wi-Fi Privacy)":
                        updates["hardware_model"] = f"Celular Android (ID: {eff_host})"

                if eff_host != target_dev.hostname or updates:
                    self.storage.update_device_metadata(
                        mac=target_dev.mac,
                        meta_updates=updates,
                        hostname=eff_host,
                    )
            except socket.timeout:
                continue
            except Exception:
                continue

    def reclassify_all_devices(self, active_network_probe: bool = True) -> int:
        """
        Reprocessa a inteligência (OUI, MAC Privacy, OS, Modelo Exato e Tipo) sem alucinações:
        1. Reconcilia a tabela ARP ao vivo para mover aparelhos antigos desconectados para Inativos (0.0.0.0).
        2. Só executa sondagem de rede ativa nos aparelhos realmente presentes na tabela ARP atual.
        """
        import concurrent.futures
        from adapters.device_intelligence import _classify_hostname, translate_hardware_model

        live_arp = {}
        try:
            live_arp = self.network_probe.get_arp_table() or {}
            if live_arp:
                self.storage.reconcile_online_devices(set(live_arp.keys()), max_idle_minutes=45)
        except Exception as e:
            log.debug("Aviso ao obter ARP em reclassify_all_devices: %s", e)

        devices = self.storage.get_all_devices()
        candidates = list(devices)

        def _probe_single(dev):
            vendor = self.oui_resolver.lookup(dev.mac)
            if vendor == "Fabricante desconhecido" and dev.vendor and dev.vendor != "Fabricante desconhecido":
                vendor = dev.vendor

            # Limpa hostnames corrompidos de colisões antigas (ex: MAC Privado que herdou nome de Smart TV)
            clean_stored_host = dev.hostname
            if vendor == "MAC Privado (Wi-Fi Privacy)" and clean_stored_host:
                low_h = clean_stored_host.lower()
                if any(tv_w in low_h for tv_w in ("tv da sala", "smart do andr", "uniontv", "tcl smart tv", "tv do quarto")):
                    clean_stored_host = None

            is_truly_online = (dev.mac in live_arp) and dev.ip and dev.ip not in ("0.0.0.0", "")
            if active_network_probe and is_truly_online:
                fp = self.intelligence.analyze(ip=dev.ip, mac=dev.mac, vendor=vendor)
            else:
                fp = self.intelligence.analyze(ip="", mac=dev.mac, vendor=vendor)
                fp.ip = dev.ip
                if fp.device_type == DeviceType.UNKNOWN and dev.ip and (dev.ip.endswith(".1") or dev.ip.endswith(".254")):
                    fp.device_type = DeviceType.ROUTER_GATEWAY
                    fp.confidence_score = max(fp.confidence_score, 65)

            eff_host = fp.hostname or clean_stored_host
            if eff_host:
                fp.hostname = eff_host
                _classify_hostname(eff_host, fp)
                exact = translate_hardware_model(eff_host)
                if exact:
                    fp.hardware_model = exact[0]
                    fp._update_if_better(exact[1], exact[2], 95, f"Modelo Identificado pelo Nome → '{exact[0]}'")

            if not fp.hardware_model or fp.hardware_model in ("Celular / Aparelho Wi-Fi (MAC Privado)", "Smartphone Android"):
                if fp.device_type == DeviceType.WINDOWS_PC:
                    fp.hardware_model = f"Computador Windows ({eff_host})" if eff_host else "Computador Windows"
                elif fp.device_type == DeviceType.GAME_CONSOLE:
                    fp.hardware_model = f"Sony PlayStation ({eff_host})" if eff_host else "Console PlayStation"
                elif fp.device_type == DeviceType.SMART_TV:
                    fp.hardware_model = fp.hardware_model if (fp.hardware_model and fp.hardware_model not in ("Smart TV", "Smartphone Android")) else (eff_host or vendor)
                elif fp.device_type == DeviceType.VIRTUALIZED:
                    fp.hardware_model = vendor if vendor != "Fabricante desconhecido" else "Máquina Virtual"
                elif fp.device_type in (DeviceType.ROUTER_GATEWAY, DeviceType.ACCESS_POINT):
                    fp.hardware_model = vendor if vendor != "Fabricante desconhecido" else "Roteador / Gateway da Rede"
                elif fp.device_type == DeviceType.ANDROID_DEVICE:
                    if eff_host:
                        fp.hardware_model = f"Celular Android (ID: {eff_host})"
                    elif vendor and "MAC Privado" not in vendor and vendor != "Fabricante desconhecido":
                        fp.hardware_model = f"Celular {vendor}"
                    else:
                        fp.hardware_model = "Celular / Aparelho Wi-Fi (MAC Privado)"

            return (dev, vendor, fp, clean_stored_host)

        results = []
        if active_network_probe:
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
                results = list(pool.map(_probe_single, candidates))
        else:
            results = [_probe_single(d) for d in candidates]

        updated_count = 0
        for dev, vendor, fp, clean_stored_host in results:
            meta = dev.metadata or {}
            is_manual = bool(meta.get("manual_override"))
            cur_type = meta.get("device_type") or ""
            if is_manual and cur_type:
                new_type = cur_type
            elif fp.confidence_score >= 60 and fp.device_type != DeviceType.UNKNOWN:
                new_type = fp.device_type.value
            else:
                new_type = fp.device_type.value if fp.device_type != DeviceType.UNKNOWN else (cur_type or fp.device_type.value)

            cur_os = meta.get("os_hint") or ""
            if fp.confidence_score >= 60 and fp.os_fingerprint != OSFingerprint.UNKNOWN:
                new_os = fp.os_fingerprint.value
            else:
                new_os = fp.os_fingerprint.value if fp.os_fingerprint != OSFingerprint.UNKNOWN else (cur_os or fp.os_fingerprint.value)

            new_conf = max(meta.get("confidence_score", 0), fp.confidence_score)
            new_ev = fp.evidence if (active_network_probe or not meta.get("evidence")) else meta.get("evidence")

            extra_updates = {}
            if fp.open_ports:
                extra_updates["open_ports"] = fp.open_ports
            if fp.http_banner:
                extra_updates["http_banner"] = fp.http_banner
            if fp.hardware_model and (not is_manual or not meta.get("hardware_model")):
                extra_updates["hardware_model"] = fp.hardware_model

            self.storage.update_device_metadata(
                mac=dev.mac,
                meta_updates=extra_updates,
                device_type=new_type,
                os_hint=new_os,
                hostname=fp.hostname or clean_stored_host or "",
                vendor=vendor,
                confidence_score=new_conf,
                evidence_list=new_ev,
            )
            updated_count += 1

        log.info("Reclassificação de inventário concluída: %d ativos atualizados.", updated_count)
        return updated_count

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
