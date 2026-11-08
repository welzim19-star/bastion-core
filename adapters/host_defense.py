"""
Bastion Audit v2.0 Enterprise - Host Defense & Interactive Armor
Módulo de Defesa Ativa e Blindagem do Host (Human-in-the-Loop).

Princípios:
1. NUNCA bloqueia sem autorização do usuário no modo interativo.
2. Whitelist estrita protegendo ferramentas locais (Antigravity IDE, Dev Ports, Localhost).
3. Execução multiplataforma segura (Linux: iptables/ip neigh, Windows: netsh/arp).
"""
from __future__ import annotations

import ctypes
import json
import os
import platform
import re
import socket
import subprocess
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from config.settings import DefenseSettings
from telemetry.killcam_logger import get_logger, record_killcam, track_action

log = get_logger("HostDefense")


def check_os_privileges() -> bool:
    """Verifica se o processo possui privilégios de Administrador (Windows) ou Root (Linux)."""
    try:
        if os.name == "nt":
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0  # type: ignore
    except Exception:
        return False


@dataclass
class BlockRule:
    rule_id: str
    ip: str
    mac: str
    reason: str
    timestamp: str = field(default_factory=lambda: datetime.now().astimezone().isoformat(timespec="seconds"))
    platform: str = field(default_factory=lambda: platform.system().lower())
    kernel_enforced: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "ip": self.ip,
            "mac": self.mac,
            "reason": self.reason,
            "timestamp": self.timestamp,
            "platform": self.platform,
            "kernel_enforced": self.kernel_enforced,
        }


@dataclass
class HoneyportHit:
    hit_id: str
    attacker_ip: str
    attacker_port: int
    trap_port: int
    decoy_service: str
    payload_sample: str
    auto_blocked: bool
    timestamp: str = field(default_factory=lambda: datetime.now().astimezone().isoformat(timespec="seconds"))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hit_id": self.hit_id,
            "attacker_ip": self.attacker_ip,
            "attacker_port": self.attacker_port,
            "trap_port": self.trap_port,
            "decoy_service": self.decoy_service,
            "payload_sample": self.payload_sample,
            "auto_blocked": self.auto_blocked,
            "timestamp": self.timestamp,
        }


class HostDefenseManager:
    """Gerenciador de Defesa Ativa do PC / Host Armor + Honeyport Trap."""

    _DECOY_BANNERS: Dict[int, Tuple[str, bytes]] = {
        2222: ("SSH-Decoy", b"SSH-2.0-OpenSSH_8.4p1 Bastion-Trap\r\n"),
        2323: ("Telnet-Decoy", b"\r\nBastion Enterprise Gatekeeper Login: "),
        4444: ("Shell-Backdoor-Decoy", b"root@bastion-vault:~# "),
        8899: ("ONVIF-Cam-Decoy", b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"BastionCam\"\r\n\r\n"),
    }

    def __init__(self, config: Optional[DefenseSettings] = None, on_intrusion_callback: Optional[Callable[[Dict[str, Any]], None]] = None):
        self.config = config or DefenseSettings()
        self.os_type = platform.system().lower()  # 'linux' ou 'windows'
        self._lock = threading.Lock()
        self.is_elevated = check_os_privileges()
        self.on_intrusion_callback = on_intrusion_callback

        # Armazena regras ativas em memória
        self._active_blocks: Dict[str, BlockRule] = {}

        # Gateway confiável memorizado
        self.known_gateway_ip: Optional[str] = None
        self.known_gateway_mac: Optional[str] = None
        self.is_gateway_locked: bool = False

        # Whitelist de proteção estrita (Antigravity / Local Dev)
        self._whitelist_ips: Set[str] = set(self.config.whitelist_ips) | {"127.0.0.1", "0.0.0.0", "::1"}
        self._protected_ports: Set[int] = set(self.config.protected_ports) | {22, 5055, 3000, 5000, 8080}

        # Honeyport Active Reconnaissance Defense
        self.honeyport_enabled: bool = False
        self.honeyport_auto_block: bool = False
        self.honeyport_ports: List[int] = [2222, 2323, 4444]
        self._honeyport_sockets: List[socket.socket] = []
        self._honeyport_hits: List[HoneyportHit] = []
        self.start_honeyport_traps(ports=self.honeyport_ports, auto_block=False)

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
                    res = subprocess.run(cmd, capture_output=True, text=True, errors="ignore", timeout=3)
                    if res.returncode == 0:
                        self.is_gateway_locked = True
                        log.info("Gateway ARP travado estaticamente no Linux: %s -> %s", gateway_ip, gateway_mac)
                        return True
                    # Fallback para arp -s
                    res = subprocess.run(["arp", "-s", gateway_ip, gateway_mac], capture_output=True, text=True, errors="ignore", timeout=3)
                    self.is_gateway_locked = (res.returncode == 0)
                    return self.is_gateway_locked
                elif self.os_type == "windows":
                    # Windows: netsh interface ipv4 add neighbors ou arp -s
                    res = subprocess.run(["arp", "-s", gateway_ip, gateway_mac], capture_output=True, text=True, errors="ignore", timeout=3)
                    self.is_gateway_locked = (res.returncode == 0)
                    log.info("Gateway ARP travado no Windows: %s -> %s", gateway_ip, gateway_mac)
                    return self.is_gateway_locked
            except Exception as e:
                record_killcam(e, custom_msg="Falha ao travar entrada ARP do Gateway")
                return False
        return False

    # ─── HONEYPORT TRAP (DETECTOR DE VARREDURA DE PORTAS / NMAP) ─────────────

    def start_honeyport_traps(self, ports: Optional[List[int]] = None, auto_block: Optional[bool] = None) -> Dict[str, Any]:
        """Inicia sensores Honeyport TCP em background para flagrar scanners (Nmap/Intrusos)."""
        if ports is not None:
            self.honeyport_ports = [p for p in ports if p not in self._protected_ports and 1024 <= p <= 65535]
        if auto_block is not None:
            self.honeyport_auto_block = bool(auto_block)

        self.stop_honeyport_traps()
        self.honeyport_enabled = True
        bound_ports: List[int] = []

        for port in self.honeyport_ports:
            try:
                srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                srv.bind(("0.0.0.0", port))
                srv.listen(10)
                srv.settimeout(1.5)
                self._honeyport_sockets.append(srv)
                bound_ports.append(port)

                t = threading.Thread(
                    target=self._honeyport_listener_loop,
                    args=(srv, port),
                    name=f"BastionHoneyport-{port}",
                    daemon=True,
                )
                t.start()
            except Exception as e:
                log.debug("Porta isca %d já ocupada ou indisponível: %s", port, e)

        log.info("🎯 [HONEYPORT] Sensores de intrusão ativos nas portas: %s (Auto-Block: %s)", bound_ports, self.honeyport_auto_block)
        return {"enabled": self.honeyport_enabled, "active_ports": bound_ports, "auto_block": self.honeyport_auto_block}

    def stop_honeyport_traps(self):
        """Encerra os sockets de escuta do Honeyport."""
        self.honeyport_enabled = False
        for srv in self._honeyport_sockets:
            try:
                srv.close()
            except Exception:
                pass
        self._honeyport_sockets.clear()

    def _honeyport_listener_loop(self, srv: socket.socket, trap_port: int):
        decoy_name, decoy_banner = self._DECOY_BANNERS.get(trap_port, ("Generic-Decoy", b"220 Bastion Vault Ready\r\n"))
        while self.honeyport_enabled:
            try:
                client_sock, addr = srv.accept()
                attacker_ip, attacker_port = addr[0], addr[1]
            except socket.timeout:
                continue
            except Exception:
                break

            payload_sample = ""
            try:
                client_sock.settimeout(0.8)
                client_sock.sendall(decoy_banner)
                data = client_sock.recv(128)
                if data:
                    payload_sample = data.decode("utf-8", errors="ignore").strip()[:80]
            except Exception:
                pass
            finally:
                try:
                    client_sock.close()
                except Exception:
                    pass

            # Ignora sondas locais da própria máquina
            if attacker_ip in ("127.0.0.1", "::1"):
                continue

            auto_blocked = False
            if self.honeyport_auto_block and not self.is_protected_target(attacker_ip):
                auto_blocked = self.block_threat(
                    ip=attacker_ip,
                    reason=f"Auto-Block Honeyport: Varredura na porta isca {trap_port} ({decoy_name})",
                )

            hit = HoneyportHit(
                hit_id=f"hp_{int(time.time() * 1000)}_{trap_port}",
                attacker_ip=attacker_ip,
                attacker_port=attacker_port,
                trap_port=trap_port,
                decoy_service=decoy_name,
                payload_sample=payload_sample or "SYN/Connect Probe (Port Scan)",
                auto_blocked=auto_blocked,
            )
            with self._lock:
                self._honeyport_hits.insert(0, hit)
                self._honeyport_hits = self._honeyport_hits[:50]

            log.warning(
                "🚨 [HONEYPORT INTRUSION] Origem %s:%d tocou a porta isca %d (%s) | Payload: %s",
                attacker_ip, attacker_port, trap_port, decoy_name, hit.payload_sample,
            )

            if self.on_intrusion_callback:
                try:
                    self.on_intrusion_callback(hit.to_dict())
                except Exception:
                    pass

    # ─── WAKE-ON-LAN (MAGIC PACKET L2/UDP) ───────────────────────────────────

    def send_wake_on_lan(self, mac: str, broadcast_ip: str = "255.255.255.255") -> bool:
        """Dispara Magic Packet IEEE 802.3 (Wake-on-LAN) para ligar um equipamento remotamente."""
        clean_mac = re.sub(r"[^0-9a-fA-F]", "", mac or "")
        if len(clean_mac) != 12:
            return False

        with track_action(action="wake_on_lan", target=mac):
            try:
                mac_bytes = bytes.fromhex(clean_mac)
                magic_packet = b"\xff" * 6 + mac_bytes * 16
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                    sock.sendto(magic_packet, (broadcast_ip, 9))
                    sock.sendto(magic_packet, (broadcast_ip, 7))
                log.info("⚡ [WAKE-ON-LAN] Magic Packet disparado para %s via %s", mac, broadcast_ip)
                return True
            except Exception as e:
                record_killcam(e, custom_msg=f"Falha ao enviar Wake-on-LAN para {mac}")
                return False

    # ─── EXECUÇÃO DE FIREWALL (BLOCK & UNBLOCK BIDIRECIONAL) ──────────────────

    def is_ip_blocked(self, ip: str) -> bool:
        """Verifica em O(1)/O(N) se um IP possui regra de bloqueio ativa no Bastion."""
        if not ip or ip in ("127.0.0.1", "::1", "0.0.0.0"):
            return False
        with self._lock:
            for rule in self._active_blocks.values():
                if rule.ip == ip:
                    return True
        return False

    def elevate_windows_firewall_rules(self) -> bool:
        """
        Solicita elevação UAC do Windows (ShellExecuteW 'runas') para aplicar todas as regras
        de bloqueio ativas diretamente no Kernel do Windows Defender Firewall.
        """
        if self.os_type != "windows":
            return False
        with self._lock:
            if not self._active_blocks:
                return False
            cmds = []
            for rule_id, rule in self._active_blocks.items():
                if not rule.ip or rule.ip == "0.0.0.0":
                    continue
                rule_in = f"BASTION_ARMOR_IN_{rule_id}"
                rule_out = f"BASTION_ARMOR_OUT_{rule_id}"
                cmds.append(f'netsh advfirewall firewall add rule name="{rule_in}" dir=in action=block remoteip={rule.ip}')
                cmds.append(f'netsh advfirewall firewall add rule name="{rule_out}" dir=out action=block remoteip={rule.ip}')
            if not cmds:
                return False
            joined_cmd = " & ".join(cmds)
            try:
                ret = ctypes.windll.shell32.ShellExecuteW(
                    None, "runas", "cmd.exe", f"/c {joined_cmd}", None, 0
                )
                if int(ret) > 32:
                    for rule in self._active_blocks.values():
                        if rule.ip and rule.ip != "0.0.0.0":
                            rule.kernel_enforced = True
                    return True
            except Exception as e:
                log.error("Falha ao solicitar UAC para regras de firewall: %s", e)
        return False

    def block_threat(self, ip: str, mac: str = "", reason: str = "Ação defensiva do usuário") -> bool:
        """
        Aplica bloqueio de tráfego bidirecional (INBOUND + OUTBOUND DROP) no firewall nativo do OS.
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
                        cmds = []
                        if ip and ip != "0.0.0.0":
                            cmds.append(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP", "-m", "comment", "--comment", f"BASTION_{rule_id}"])
                            cmds.append(["iptables", "-I", "OUTPUT", "-d", ip, "-j", "DROP", "-m", "comment", "--comment", f"BASTION_{rule_id}"])
                        if mac and len(mac) == 17:
                            cmds.append(["iptables", "-I", "INPUT", "-m", "mac", "--mac-source", mac, "-j", "DROP", "-m", "comment", "--comment", f"BASTION_MAC_{rule_id}"])

                        for cmd in cmds:
                            res = subprocess.run(cmd, capture_output=True, text=True, errors="ignore", timeout=4)
                            if res.returncode == 0:
                                success = True

                    elif self.os_type == "windows":
                        # Injeta regras de Entrada (IN) e Saída (OUT) no Windows Defender Firewall via netsh
                        rule_in = f"BASTION_ARMOR_IN_{rule_id}"
                        rule_out = f"BASTION_ARMOR_OUT_{rule_id}"
                        target_ip_arg = f"remoteip={ip}" if ip and ip != "0.0.0.0" else "remoteip=any"
                        cmd_in = [
                            "netsh", "advfirewall", "firewall", "add", "rule",
                            f"name={rule_in}", "dir=in", "action=block",
                            target_ip_arg, f"description=Bloqueio Entrada Bastion Audit ({reason})"
                        ]
                        cmd_out = [
                            "netsh", "advfirewall", "firewall", "add", "rule",
                            f"name={rule_out}", "dir=out", "action=block",
                            target_ip_arg, f"description=Bloqueio Saida Bastion Audit ({reason})"
                        ]
                        res_in = subprocess.run(cmd_in, capture_output=True, text=True, errors="ignore", timeout=5)
                        res_out = subprocess.run(cmd_out, capture_output=True, text=True, errors="ignore", timeout=5)
                        success = (res_in.returncode == 0 or res_out.returncode == 0)

                except Exception as e:
                    record_killcam(e, custom_msg=f"Erro ao aplicar regra de firewall para {ip}/{mac}")
                    success = False

                if success:
                    rule = BlockRule(rule_id=rule_id, ip=ip, mac=mac, reason=reason, kernel_enforced=True)
                    self._active_blocks[rule_id] = rule
                    log.info("🛡️ [HOST ARMOR] Alvo bloqueado no Kernel/Firewall (IN+OUT): %s [%s] | Motivo: %s", ip, mac, reason)
                    return True
                else:
                    rule = BlockRule(
                        rule_id=rule_id,
                        ip=ip,
                        mac=mac,
                        reason=f"{reason} (Isolamento Lógico — Execute como Admin para Firewall Kernel)",
                        kernel_enforced=False,
                    )
                    self._active_blocks[rule_id] = rule
                    log.warning("Firewall nativo requer elevação de Administrador. Bloqueio registrado na camada de aplicação.")
                    return True

    def unblock_threat(self, ip: str, mac: str = "") -> bool:
        """Remove regras de bloqueio (IN/OUT) do firewall nativo."""
        rule_id = f"block_{mac.replace(':', '') if mac else ip.replace('.', '_')}"

        with self._lock:
            with track_action(action="firewall_unblock", target=f"{ip} [{mac}]"):
                try:
                    if self.os_type == "linux":
                        if ip and ip != "0.0.0.0":
                            subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], capture_output=True, timeout=3)
                            subprocess.run(["iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"], capture_output=True, timeout=3)
                        if mac and len(mac) == 17:
                            subprocess.run(["iptables", "-D", "INPUT", "-m", "mac", "--mac-source", mac, "-j", "DROP"], capture_output=True, timeout=3)
                    elif self.os_type == "windows":
                        for prefix in ("BASTION_ARMOR_", "BASTION_ARMOR_IN_", "BASTION_ARMOR_OUT_"):
                            rule_name = f"{prefix}{rule_id}"
                            subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"], capture_output=True, timeout=4)
                except Exception as e:
                    record_killcam(e, custom_msg=f"Falha ao remover regra de firewall para {ip}/{mac}")

            if rule_id in self._active_blocks:
                del self._active_blocks[rule_id]
                log.info("🛡️ [HOST ARMOR] Alvo desbloqueado no firewall: %s [%s]", ip, mac)
                return True
            return True

    def get_defense_status(self) -> Dict[str, Any]:
        """Retorna o estado operacional das defesas do host + Honeyport."""
        with self._lock:
            blocks = [rule.to_dict() for rule in self._active_blocks.values()]
            hits = [h.to_dict() for h in self._honeyport_hits]
            return {
                "defense_mode": self.config.defense_mode,
                "os_platform": self.os_type,
                "is_admin_elevated": self.is_elevated,
                "total_active_blocks": len(blocks),
                "active_blocks": blocks,
                "gateway_protection": {
                    "ip": self.known_gateway_ip,
                    "mac": self.known_gateway_mac,
                    "is_locked": self.is_gateway_locked,
                },
                "honeyport": {
                    "enabled": self.honeyport_enabled,
                    "auto_block": self.honeyport_auto_block,
                    "ports": self.honeyport_ports,
                    "total_hits": len(hits),
                    "recent_hits": hits,
                },
                "protected_ports": list(self._protected_ports),
                "whitelist_ips": list(self._whitelist_ips),
            }
