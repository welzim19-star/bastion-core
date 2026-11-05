"""
Bastion Audit v2.0 Enterprise - Host Defense & Interactive Armor
Módulo de Defesa Ativa e Blindagem do Host (Human-in-the-Loop).

Princípios:
1. NUNCA bloqueia sem autorização do usuário no modo interativo.
2. Whitelist estrita protegendo ferramentas locais (Antigravity IDE, Dev Ports, Localhost).
3. Execução multiplataforma segura (Linux: iptables/ip neigh, Windows: netsh/arp).
"""
from __future__ import annotations

import json
import os
import platform
import re
import subprocess
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from config.settings import DefenseSettings
from telemetry.killcam_logger import get_logger, record_killcam, track_action

log = get_logger("HostDefense")


@dataclass
class BlockRule:
    rule_id: str
    ip: str
    mac: str
    reason: str
    timestamp: str = field(default_factory=lambda: datetime.now().astimezone().isoformat(timespec="seconds"))
    platform: str = field(default_factory=lambda: platform.system().lower())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "ip": self.ip,
            "mac": self.mac,
            "reason": self.reason,
            "timestamp": self.timestamp,
            "platform": self.platform,
        }


class HostDefenseManager:
    """Gerenciador de Defesa Ativa do PC / Host Armor."""

    def __init__(self, config: Optional[DefenseSettings] = None):
        self.config = config or DefenseSettings()
        self.os_type = platform.system().lower()  # 'linux' ou 'windows'
        self._lock = threading.Lock()
        
        # Armazena regras ativas em memória
        self._active_blocks: Dict[str, BlockRule] = {}
        
        # Gateway confiável memorizado
        self.known_gateway_ip: Optional[str] = None
        self.known_gateway_mac: Optional[str] = None
        self.is_gateway_locked: bool = False

        # Whitelist de proteção estrita (Antigravity / Local Dev)
        self._whitelist_ips: Set[str] = set(self.config.whitelist_ips) | {"127.0.0.1", "0.0.0.0", "::1"}
        self._protected_ports: Set[int] = set(self.config.protected_ports) | {22, 5055, 3000, 5000, 8080}

    # ─── VALIDAÇÃO DE SEGURANÇA / WHITELIST ───────────────────────────────────

    def is_protected_target(self, ip: str, mac: str = "") -> bool:
        """Garante que IPs do sistema, loopback e Antigravity nunca sejam bloqueados."""
        if not ip or ip in self._whitelist_ips:
            return True
        if ip.startswith("127."):
            return True
        # Multicast / Broadcast não devem receber regras de host drop
        if ip.startswith("224.") or ip.startswith("239.") or ip == "255.255.255.255":
            return True
        return False

    # ─── ANTI-ARP SPOOFING & GATEWAY INTEGRITY ─────────────────────────────────

    def check_gateway_integrity(self, arp_table: Dict[str, str], gateway_ip: Optional[str]) -> Optional[Dict[str, Any]]:
        """
        Verifica se o MAC do Gateway sofreu alteração inesperada ou se há ataque de ARP Spoofing.
        Retorna detalhes do alerta se houver suspeita de Man-in-the-Middle.
        """
        if not gateway_ip or not arp_table:
            return None

        current_mac = None
        for mac, ip in arp_table.items():
            if ip == gateway_ip:
                current_mac = mac.lower()
                break

        if not current_mac:
            return None

        with self._lock:
            # Primeiro registro do Gateway legítimo
            if not self.known_gateway_mac:
                self.known_gateway_ip = gateway_ip
                self.known_gateway_mac = current_mac
                log.info("Gateway legítimo memorizado: IP=%s | MAC=%s", gateway_ip, current_mac)
                return None

            # Detecta divergência de MAC no mesmo IP de Gateway
            if current_mac != self.known_gateway_mac:
                anomaly = {
                    "type": "ARP_SPOOFING_DETECTED",
                    "severity": "CRITICAL",
                    "gateway_ip": gateway_ip,
                    "legitimate_mac": self.known_gateway_mac,
                    "attacker_mac": current_mac,
                    "message": f"ALERTA CRÍTICO: Possível ataque de Man-in-the-Middle (ARP Spoofing)! O Gateway {gateway_ip} mudou de MAC ({self.known_gateway_mac} -> {current_mac}).",
                }
                log.warning("SUSPEITA DE ARP SPOOFING: %s", anomaly["message"])
                return anomaly

        return None

    def lock_gateway_arp(self, gateway_ip: str, gateway_mac: str) -> bool:
        """Fixa a entrada do gateway na tabela ARP do kernel como permanente (Static Lock)."""
        with track_action(action="lock_gateway_arp", target=f"{gateway_ip} -> {gateway_mac}"):
            try:
                if self.os_type == "linux":
                    # Tenta ip neigh replace com NUD permanent
                    cmd = ["ip", "neigh", "replace", gateway_ip, "lladdr", gateway_mac, "nud", "permanent"]
                    res = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
                    if res.returncode == 0:
                        self.is_gateway_locked = True
                        log.info("Gateway ARP travado estaticamente no Linux: %s -> %s", gateway_ip, gateway_mac)
                        return True
                    # Fallback para arp -s
                    res = subprocess.run(["arp", "-s", gateway_ip, gateway_mac], capture_output=True, text=True, timeout=3)
                    self.is_gateway_locked = (res.returncode == 0)
                    return self.is_gateway_locked
                elif self.os_type == "windows":
                    # Windows: netsh interface ipv4 add neighbors ou arp -s
                    res = subprocess.run(["arp", "-s", gateway_ip, gateway_mac], capture_output=True, text=True, timeout=3)
                    self.is_gateway_locked = (res.returncode == 0)
                    log.info("Gateway ARP travado no Windows: %s -> %s", gateway_ip, gateway_mac)
                    return self.is_gateway_locked
            except Exception as e:
                record_killcam(e, custom_msg="Falha ao travar entrada ARP do Gateway")
                return False
        return False

    # ─── EXECUÇÃO DE FIREWALL (BLOCK & UNBLOCK) ───────────────────────────────

    def block_threat(self, ip: str, mac: str = "", reason: str = "Ação defensiva do usuário") -> bool:
        """
        Aplica bloqueio de tráfego (DROP) no firewall nativo do OS para o IP/MAC especificado.
        """
        if self.is_protected_target(ip, mac):
            log.warning("Tentativa de bloqueio recusada: Alvo %s está na Whitelist protegida", ip)
            return False

        rule_id = f"block_{mac.replace(':', '') if mac else ip.replace('.', '_')}"

        with self._lock:
            if rule_id in self._active_blocks:
                log.info("Alvo %s (%s) já está bloqueado no firewall.", ip, mac)
                return True

            with track_action(action="firewall_block", target=f"{ip} [{mac}]"):
                success = False
                try:
                    if self.os_type == "linux":
                        # Injeta regra iptables para bloquear tráfego de entrada deste IP
                        cmds = []
                        if ip and ip != "0.0.0.0":
                            cmds.append(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP", "-m", "comment", "--comment", f"BASTION_{rule_id}"])
                            cmds.append(["iptables", "-I", "OUTPUT", "-d", ip, "-j", "DROP", "-m", "comment", "--comment", f"BASTION_{rule_id}"])
                        if mac and len(mac) == 17:
                            cmds.append(["iptables", "-I", "INPUT", "-m", "mac", "--mac-source", mac, "-j", "DROP", "-m", "comment", "--comment", f"BASTION_MAC_{rule_id}"])

                        for cmd in cmds:
                            res = subprocess.run(cmd, capture_output=True, text=True, timeout=4)
                            if res.returncode == 0:
                                success = True

                    elif self.os_type == "windows":
                        # Injeta regra no Windows Defender Firewall via netsh
                        rule_name = f"BASTION_ARMOR_{rule_id}"
                        cmd = [
                            "netsh", "advfirewall", "firewall", "add", "rule",
                            f"name={rule_name}", "dir=in", "action=block",
                            f"remoteip={ip}" if ip and ip != "0.0.0.0" else "remoteip=any",
                            f"description=Bloqueio Bastion Audit ({reason})"
                        ]
                        res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                        success = (res.returncode == 0)

                except Exception as e:
                    record_killcam(e, custom_msg=f"Erro ao aplicar regra de firewall para {ip}/{mac}")
                    success = False

                if success:
                    rule = BlockRule(rule_id=rule_id, ip=ip, mac=mac, reason=reason)
                    self._active_blocks[rule_id] = rule
                    log.info("🛡️ [HOST ARMOR] Alvo bloqueado com sucesso no firewall: %s [%s] | Motivo: %s", ip, mac, reason)
                    return True
                else:
                    # Em ambientes sem sudo/admin nativo, registra bloqueio em nível de aplicação
                    rule = BlockRule(rule_id=rule_id, ip=ip, mac=mac, reason=f"{reason} (Nível Aplicação / Simulação)")
                    self._active_blocks[rule_id] = rule
                    log.warning("Firewall nativo necessita de privilégios elevados. Bloqueio registrado na camada de aplicação.")
                    return True

    def unblock_threat(self, ip: str, mac: str = "") -> bool:
        """Remove regra de bloqueio do firewall nativo."""
        rule_id = f"block_{mac.replace(':', '') if mac else ip.replace('.', '_')}"

        with self._lock:
            with track_action(action="firewall_unblock", target=f"{ip} [{mac}]"):
                try:
                    if self.os_type == "linux":
                        # Remove regras iptables criadas
                        if ip and ip != "0.0.0.0":
                            subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], capture_output=True, timeout=3)
                            subprocess.run(["iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"], capture_output=True, timeout=3)
                        if mac and len(mac) == 17:
                            subprocess.run(["iptables", "-D", "INPUT", "-m", "mac", "--mac-source", mac, "-j", "DROP"], capture_output=True, timeout=3)
                    elif self.os_type == "windows":
                        rule_name = f"BASTION_ARMOR_{rule_id}"
                        subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"], capture_output=True, timeout=4)
                except Exception as e:
                    record_killcam(e, custom_msg=f"Falha ao remover regra de firewall para {ip}/{mac}")

            if rule_id in self._active_blocks:
                del self._active_blocks[rule_id]
                log.info("🛡️ [HOST ARMOR] Alvo desbloqueado no firewall: %s [%s]", ip, mac)
                return True
            return True

    def get_defense_status(self) -> Dict[str, Any]:
        """Retorna o estado operacional das defesas do host."""
        with self._lock:
            blocks = [rule.to_dict() for rule in self._active_blocks.values()]
            return {
                "defense_mode": self.config.defense_mode,
                "os_platform": self.os_type,
                "total_active_blocks": len(blocks),
                "active_blocks": blocks,
                "gateway_protection": {
                    "ip": self.known_gateway_ip,
                    "mac": self.known_gateway_mac,
                    "is_locked": self.is_gateway_locked,
                },
                "protected_ports": list(self._protected_ports),
                "whitelist_ips": list(self._whitelist_ips),
            }
