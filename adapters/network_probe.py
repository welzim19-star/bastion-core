"""
Bastion Audit v2.0 Enterprise - Network Probe Adapter
Autodescoberta de Sub-rede, Gateway, Ping Sweep em Lotes e Parser de Tabela ARP.
"""
from __future__ import annotations

import concurrent.futures
import ipaddress
import os
import re
import socket
import subprocess
from typing import Dict, List, Optional, Tuple

from core.models import NetworkInterface
from core.security import sanitize_ip, sanitize_mac
from telemetry.killcam_logger import track_action

_MAC_REGEX = re.compile(r"\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b")
_IP_REGEX = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")


class NetworkProbe:
    """Sonda de rede multiplataforma (Windows/Linux) com autodescoberta de topologia."""

    def __init__(self, target_ip: str = "8.8.8.8", ping_timeout_ms: int = 1500, max_workers: int = 30):
        self.target_ip = target_ip
        self.ping_timeout_ms = ping_timeout_ms
        self.max_workers = max_workers

    def detect_active_interface(self) -> NetworkInterface:
        """Descobre automaticamente o IP local, máscara e sub-rede da rota primária."""
        local_ip = "127.0.0.1"
        gateway = None

        # 1. Descobre IP local via conexão dummy UDP
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect((self.target_ip, 80))
                local_ip = s.getsockname()[0]
        except Exception:
            try:
                local_ip = socket.gethostbyname(socket.gethostname())
            except Exception:
                local_ip = "192.168.1.1"

        # 2. Descobre Gateway e Subnet
        subnet_cidr = self._discover_subnet_cidr(local_ip)
        octets = local_ip.split(".")
        if len(octets) == 4 and local_ip != "127.0.0.1":
            gateway = f"{octets[0]}.{octets[1]}.{octets[2]}.1"

        return NetworkInterface(
            name="auto_detected",
            ip_address=local_ip,
            netmask="255.255.255.0",
            cidr_subnet=subnet_cidr,
            gateway=gateway,
        )

    def _discover_subnet_cidr(self, local_ip: str) -> str:
        """Gera o bloco CIDR (/24) a partir do IP local como fallback inteligente."""
        try:
            ip_obj = ipaddress.IPv4Interface(f"{local_ip}/24")
            return str(ip_obj.network)
        except Exception:
            octets = local_ip.split(".")
            if len(octets) == 4:
                return f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
            return "192.168.1.0/24"

    def ping(self, host_ip: str, timeout_ms: Optional[int] = None) -> bool:
        """Executa um ping primitivo de baixo overhead (Zero dependências externas)."""
        t_ms = timeout_ms or self.ping_timeout_ms
        with track_action(action="icmp_ping_primitive", target=host_ip):
            if os.name == "nt":
                cmd = ["ping", "-n", "1", "-w", str(t_ms), host_ip]
                CREATE_NO_WINDOW = 0x08000000
                return (
                    subprocess.call(
                        cmd,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.STDOUT,
                        creationflags=CREATE_NO_WINDOW,
                    )
                    == 0
                )
            else:
                timeout_s = max(1, t_ms // 1000)
                cmd = ["ping", "-c", "1", "-W", str(timeout_s), host_ip]
                return (
                    subprocess.call(
                        cmd,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.STDOUT,
                    )
                    == 0
                )

    def active_radar_sweep(self, subnet_cidr: str) -> List[str]:
        """
        Executa varredura de ping em lotes cadenciados para popular o cache ARP.
        Evita o churn excessivo de processos e reduz alertas em firewalls IDS/IPS.
        """
        try:
            net = ipaddress.IPv4Network(subnet_cidr, strict=False)
            hosts = [str(ip) for ip in net.hosts()]
            # Limita a 512 hosts para evitar varreduras desmedidas em /16 acidental
            if len(hosts) > 512:
                hosts = hosts[:512]
        except Exception:
            # Fallback para range padrão
            prefix = ".".join(subnet_cidr.split(".")[:3])
            hosts = [f"{prefix}.{i}" for i in range(1, 255)]

        responded_ips: List[str] = []
        # Disparo concorrente com ThreadPool controlado
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self.ping, ip, 1200): ip for ip in hosts}
            for f in concurrent.futures.as_completed(futures):
                ip = futures[f]
                try:
                    if f.result():
                        responded_ips.append(ip)
                except Exception:
                    pass

        return responded_ips

    def get_arp_table(self) -> Dict[str, str]:
        """
        Extrai o mapeamento atual de MAC -> IP a partir da tabela ARP do SO.
        Filtra endereços de broadcast, multicast e entradas inválidas.
        """
        with track_action(action="arp_table_query", target="system_arp"):
            try:
                if os.name == "nt":
                    CREATE_NO_WINDOW = 0x08000000
                    raw = subprocess.check_output(
                        ["arp", "-a"], creationflags=CREATE_NO_WINDOW
                    ).decode("utf-8", errors="ignore")
                else:
                    raw = subprocess.check_output(["arp", "-a"]).decode(
                        "utf-8", errors="ignore"
                    )
            except Exception:
                return {}

        mac_ip_map: Dict[str, str] = {}

        for line in raw.splitlines():
            line_lower = line.lower()
            if "incomplete" in line_lower or "incompleto" in line_lower:
                continue

            mac_match = _MAC_REGEX.search(line)
            if not mac_match:
                continue

            mac = sanitize_mac(mac_match.group(0))
            if not mac:
                continue

            # Filtros de exclusão (Multicast / Broadcast / Loopback)
            if (
                mac == "ff:ff:ff:ff:ff:ff"
                or mac.startswith("01:00:5e")  # IPv4 Multicast
                or mac.startswith("33:33")      # IPv6 Multicast
                or mac == "00:00:00:00:00:00"
            ):
                continue

            ip_match = _IP_REGEX.search(line)
            ip = sanitize_ip(ip_match.group(0)) if ip_match else "0.0.0.0"

            mac_ip_map[mac] = ip

        return mac_ip_map
