"""
Bastion Audit v2.0 Enterprise - OUI Vendor Resolver
Base expandida de fabricantes de rede, CFTV, servidores, switches e IoT com busca O(1).
"""
from __future__ import annotations

from typing import Dict, Optional

# Base OUI Expandida Embutida (Zero Dependências Externas)
_EMBEDDED_OUI_DATABASE: Dict[str, str] = {
    # ─── CFTV & Segurança Eletrônica ──────────────────────────────────────────
    "00:12:12": "Intelbras",
    "00:1a:3f": "Intelbras",
    "48:28:2f": "Intelbras",
    "ec:1a:59": "Intelbras",
    "90:02:a9": "Intelbras",
    "a0:f3:c1": "Intelbras",
    "00:40:8c": "Axis Communications",
    "ac:cc:8e": "Axis Communications",
    "b8:a4:4f": "Hikvision",
    "44:19:b6": "Hikvision",
    "bc:ad:28": "Hikvision",
    "c4:2f:90": "Hikvision",
    "e0:50:8b": "Hikvision",
    "ec:a8:6b": "Hikvision",
    "3c:ef:8c": "Dahua Technology",
    "4c:11:bf": "Dahua Technology",
    "90:02:a9": "Dahua Technology",
    "a4:14:37": "Dahua Technology",
    "bc:32:53": "Dahua Technology",
    "00:1c:27": "Bosch Security",
    "00:07:5f": "Hanwha Techwin (Samsung CFTV)",
    "00:16:6c": "Hanwha Techwin",
    "00:0f:7c": "Uniview (UNV)",
    "00:02:d1": "Vivotek",
    "00:04:7d": "Pelco",
    "00:18:85": "Avigilon",

    # ─── Switches, Roteadores & Infraestrutura Corporativa ────────────────────
    "00:00:0c": "Cisco",
    "00:01:42": "Cisco",
    "00:01:43": "Cisco",
    "00:17:94": "Cisco",
    "00:1d:aa": "Cisco",
    "00:23:5e": "Cisco",
    "00:26:0b": "Cisco",
    "c4:71:fe": "Cisco",
    "f0:29:29": "Cisco",
    "00:0b:86": "Aruba Networks (HPE)",
    "00:1a:1e": "Aruba Networks (HPE)",
    "24:de:c6": "Aruba Networks (HPE)",
    "00:1a:8c": "Sophos",
    "00:08:54": "Netgear",
    "00:14:6c": "Netgear",
    "00:09:5b": "Netgear",
    "00:18:e7": "D-Link",
    "1c:7e:e5": "D-Link",
    "00:05:5d": "D-Link",
    "14:cc:20": "TP-Link",
    "50:c7:bf": "TP-Link",
    "c8:d7:19": "TP-Link",
    "e8:94:f6": "TP-Link",
    "f4:ec:38": "TP-Link",
    "c8:3a:35": "Tenda",
    "00:0c:42": "MikroTik",
    "48:8f:5a": "MikroTik",
    "64:d1:54": "MikroTik",
    "cc:2d:e0": "MikroTik",
    "dc:2c:6e": "MikroTik",
    "00:27:22": "Ubiquiti Networks",
    "24:a4:3c": "Ubiquiti Networks",
    "78:8a:20": "Ubiquiti Networks",
    "80:2a:a8": "Ubiquiti Networks",
    "b4:fb:e4": "Ubiquiti Networks",
    "dc:9f:db": "Ubiquiti Networks",
    "00:09:0f": "Fortinet",
    "70:4c:a5": "Fortinet",
    "90:6c:ac": "Fortinet",
    "00:1c:7f": "Check Point",
    "00:90:fb": "Portwell (Firewall Appliance)",
    "00:1b:17": "Palo Alto Networks",
    "00:04:96": "Extreme Networks",
    "00:05:85": "Juniper Networks",
    "00:10:db": "Juniper Networks",
    "00:26:88": "Juniper Networks",

    # ─── Servidores, Datacenter & Virtualização ───────────────────────────────
    "00:50:56": "VMware ESXi",
    "00:0c:29": "VMware Workstation",
    "00:05:69": "VMware",
    "00:15:5d": "Microsoft Hyper-V",
    "00:16:3e": "Xen / Proxmox / Oracle VM",
    "52:54:00": "QEMU / KVM",
    "02:42:ac": "Docker Container Bridge",
    "00:13:21": "Dell Technologies",
    "14:18:77": "Dell Technologies",
    "f8:db:88": "Dell Technologies",
    "00:14:22": "Dell Technologies",
    "00:1f:9e": "HP / HPE",
    "3c:d9:2b": "HP / HPE",
    "fc:15:b4": "HP / HPE",
    "00:22:19": "Lenovo",
    "28:d2:44": "Lenovo",
    "00:02:b3": "Intel Corporation",
    "00:08:22": "Intel Corporation",
    "00:1b:21": "Intel Corporation",
    "00:26:c7": "Intel Corporation",
    "8c:8d:28": "Intel Corporation",
    "00:25:90": "Supermicro",
    "0c:c4:7a": "Supermicro",
    "ac:1f:6b": "Supermicro",

    # ─── Cloud Providers & Big Tech ───────────────────────────────────────────
    "00:1a:11": "Google LLC",
    "3c:5a:b4": "Google LLC",
    "f4:f5:d8": "Google LLC",
    "00:e0:4f": "Microsoft Corporation",
    "28:18:78": "Microsoft Corporation",
    "60:45:cb": "Microsoft Corporation",
    "00:1b:63": "Apple Inc.",
    "00:1e:c2": "Apple Inc.",
    "00:23:12": "Apple Inc.",
    "00:26:bb": "Apple Inc.",
    "3c:07:54": "Apple Inc.",
    "58:55:ca": "Apple Inc.",
    "a4:c3:f0": "Apple Inc.",
    "f0:18:98": "Apple Inc.",
    "00:1a:8a": "Samsung Electronics",
    "00:21:19": "Samsung Electronics",
    "8c:77:12": "Samsung Electronics",
    "f0:25:b7": "Samsung Electronics",
    "00:26:18": "Huawei Technologies",
    "00:e0:fc": "Huawei Technologies",
    "40:cb:c0": "Xiaomi Communications",
    "28:6c:07": "Xiaomi Communications",
    "f4:8e:92": "Motorola Mobility",
    "ac:c1:ee": "Motorola Mobility",

    # ─── Impressoras & Periféricos Corporativos ──────────────────────────────
    "00:90:4c": "Epson",
    "00:00:74": "Ricoh",
    "00:00:aa": "Xerox",
    "00:00:85": "Canon",
    "00:80:77": "Brother Industries",
    "00:c0:ee": "Kyocera Document Solutions",
    "00:07:4d": "Zebra Technologies (Etiquetas/Código de Barras)",

    # ─── IoT, Microcontroladores & SBCs ───────────────────────────────────────
    "dc:a6:32": "Raspberry Pi Trading",
    "b8:27:eb": "Raspberry Pi Foundation",
    "e4:5f:01": "Raspberry Pi Foundation",
    "24:0a:c4": "Espressif Systems (ESP32/ESP8266)",
    "30:ae:a4": "Espressif Systems",
    "a4:cf:12": "Espressif Systems",
    "84:0d:8e": "Tuya Smart IoT",
    "10:52:1c": "Tuya Smart IoT",
}


class OUIResolver:
    """Resolvedor de fabricantes de hardware via prefixo OUI com tempo de resposta O(1)."""

    def __init__(self, custom_table: Optional[Dict[str, str]] = None):
        self._table: Dict[str, str] = dict(_EMBEDDED_OUI_DATABASE)
        if custom_table:
            self._table.update(custom_table)

    def lookup(self, mac_address: str) -> str:
        """Retorna o nome do fabricante baseado nos primeiros 3 octetos do MAC."""
        if not mac_address or len(mac_address) < 8:
            return "Fabricante desconhecido"

        normalized = mac_address.lower().replace("-", ":")
        prefix = normalized[:8]
        return self._table.get(prefix, "Fabricante desconhecido")

    def register_vendor(self, prefix: str, vendor_name: str):
        """Registra dinamicamente um novo fabricante na memória."""
        clean_prefix = prefix.lower().replace("-", ":")[:8]
        self._table[clean_prefix] = vendor_name

    @property
    def total_vendors(self) -> int:
        return len(self._table)
