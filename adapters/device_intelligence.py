"""
Bastion Audit v2.0 Enterprise — Device Intelligence Engine v3.0
Red Team Lens: Identificação agressiva de dispositivos. Zero "Desconhecidos".

Técnicas encadeadas (ordem crescente de intrusividade):
  L0. MAC Análise Especial (multicast, broadcast, STP, VRRP, HSRP)
  L1. OUI Vendor Hint → inferência de tipo pelo fabricante
  L2. MAC Randomization Bit (Wi-Fi Privacy)
  L3. TTL Fingerprinting via ICMP (OS inference)
  L4. Reverse DNS / PTR hostname lookup
  L5. Hostname pattern analysis
  L6. NetBIOS Name Service query (UDP 137) — Windows/Samba
  L7. mDNS/Bonjour query (UDP 5353) — Apple/Android/Linux
  L8. UPnP SSDP discovery (UDP 1900) — Câmeras, TVs, Roteadores
  L9. Port probing inteligente (TCP connect scan seletivo)
  L10. HTTP/HTTPS banner grabbing + title/server header analysis
  L11. Síntese cruzada (evidence fusion) — resultado final
"""
from __future__ import annotations

import json
import re
import socket
import struct
import time
import urllib.request
import ssl
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from telemetry.killcam_logger import get_logger, track_action

log = get_logger("DeviceIntelligence")


# ─────────────────────────────────────────────────────────────────────────────
# ENUMS
# ─────────────────────────────────────────────────────────────────────────────

class DeviceType(str, Enum):
    ROUTER_GATEWAY   = "Router/Gateway"
    SWITCH           = "Switch Gerenciável"
    ACCESS_POINT     = "Access Point (Wi-Fi)"
    WINDOWS_PC       = "Computador Windows"
    LINUX_SERVER     = "Servidor Linux"
    MACOS_DEVICE     = "Mac / MacBook"
    IOS_DEVICE       = "iPhone / iPad"
    ANDROID_DEVICE   = "Smartphone/Tablet Android"
    CCTV_CAMERA      = "Câmera IP / CFTV"
    NVR_DVR          = "NVR / DVR"
    PRINTER          = "Impressora de Rede"
    VOIP_PHONE       = "Telefone VoIP"
    SMART_TV         = "Smart TV / Mídia"
    GAME_CONSOLE     = "Console de Videogame"
    IOT_SENSOR       = "Dispositivo IoT"
    VIRTUALIZED      = "Máquina Virtual / Container"
    NETWORK_PROBE    = "Sonda de Rede / SNMP"
    MULTICAST_ADDR   = "Endereço Multicast (não é dispositivo)"
    BROADCAST_ADDR   = "Endereço Broadcast"
    NETWORK_PROTOCOL = "Protocolo de Rede (STP/VRRP/HSRP)"
    UNKNOWN          = "Dispositivo Desconhecido"


class OSFingerprint(str, Enum):
    WINDOWS     = "Windows"
    LINUX       = "Linux"
    ANDROID     = "Android"
    IOS         = "iOS / macOS"
    TIZEN       = "Tizen OS (Samsung)"
    ORBIS_OS    = "Orbis OS (PlayStation)"
    CISCO_IOS   = "Cisco IOS"
    MIKROTIK    = "RouterOS (MikroTik)"
    EMBEDDED    = "Sistema Embarcado"
    PROTOCOL    = "Protocolo de Rede"
    UNKNOWN     = "Indefinido"


# ─────────────────────────────────────────────────────────────────────────────
# DATACLASS DE RESULTADO
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class DeviceFingerprint:
    ip: str
    mac: str
    device_type: DeviceType = DeviceType.UNKNOWN
    os_fingerprint: OSFingerprint = OSFingerprint.UNKNOWN
    hostname: Optional[str] = None
    hardware_model: Optional[str] = None
    open_ports: List[int] = field(default_factory=list)
    http_banner: Optional[str] = None
    confidence_score: int = 0
    evidence: List[str] = field(default_factory=list)
    is_mac_randomized: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip": self.ip,
            "mac": self.mac,
            "device_type": self.device_type.value,
            "os_fingerprint": self.os_fingerprint.value,
            "hostname": self.hostname,
            "hardware_model": self.hardware_model,
            "open_ports": self.open_ports,
            "http_banner": self.http_banner,
            "confidence_score": self.confidence_score,
            "evidence": self.evidence,
            "is_mac_randomized": self.is_mac_randomized,
        }

    def _update_if_better(self, dev_type: DeviceType, os_fp: OSFingerprint,
                           score: int, evidence_msg: str):
        """Atualiza tipo/OS/score apenas se a nova evidência for mais forte."""
        self.evidence.append(evidence_msg)
        if score > self.confidence_score:
            self.device_type = dev_type
            self.os_fingerprint = os_fp
            self.confidence_score = score


# ─────────────────────────────────────────────────────────────────────────────
# L0 — TABELA DE MACs ESPECIAIS (Multicast / Broadcast / Protocolos)
# ─────────────────────────────────────────────────────────────────────────────

# (prefixo_hex_lower, DeviceType, OSFingerprint, confiança, descrição)
_SPECIAL_MAC_PREFIXES: List[Tuple[str, DeviceType, OSFingerprint, int, str]] = [
    ("ff:ff:ff:ff:ff:ff", DeviceType.BROADCAST_ADDR,   OSFingerprint.PROTOCOL, 100, "Broadcast Ethernet (ff:ff:ff:ff:ff:ff)"),
    ("01:00:5e",          DeviceType.MULTICAST_ADDR,   OSFingerprint.PROTOCOL,  99, "Multicast IPv4 (01:00:5e:xx — IANA/RFC1112)"),
    ("33:33",             DeviceType.MULTICAST_ADDR,   OSFingerprint.PROTOCOL,  99, "Multicast IPv6 (33:33:xx — RFC4291)"),
    ("01:80:c2",          DeviceType.NETWORK_PROTOCOL, OSFingerprint.PROTOCOL,  99, "IEEE 802.1 STP/LLDP/PAgP (01:80:c2:xx)"),
    ("01:00:0c",          DeviceType.NETWORK_PROTOCOL, OSFingerprint.CISCO_IOS, 99, "Cisco CDP/VTP/PVST (01:00:0c:xx)"),
    ("00:00:5e:00:01",    DeviceType.NETWORK_PROTOCOL, OSFingerprint.EMBEDDED,  99, "VRRP Virtual MAC (00:00:5e:00:01:xx)"),
    ("00:00:0c:07:ac",    DeviceType.NETWORK_PROTOCOL, OSFingerprint.CISCO_IOS, 99, "HSRP Virtual MAC (Cisco)"),
]

# ─────────────────────────────────────────────────────────────────────────────
# L1 — OUI VENDOR → DEVICE TYPE HINTS
# ─────────────────────────────────────────────────────────────────────────────

_OUI_VENDOR_HINTS: List[Tuple[str, DeviceType, OSFingerprint, int]] = [
    (r"hikvision|dahua|intelbras|axis|vivotek|hanwha|bosch.*security|pelco|avigilon|reolink|uniview|tiandy|smart cftv",
     DeviceType.CCTV_CAMERA, OSFingerprint.EMBEDDED, 75),
    (r"cisco|mikrotik|ubiquiti|unifi|tp.?link|tplink|netgear|d.?link|zyxel|juniper|aruba|fortinet|palo alto|watchguard|mitrastar|gateway fibra|wireless gateway|mesh ap",
     DeviceType.ROUTER_GATEWAY, OSFingerprint.EMBEDDED, 70),
    (r"hewlett.packard|hp inc|epson|canon|ricoh|xerox|lexmark|konica|kyocera|brother|samsung.*print",
     DeviceType.PRINTER, OSFingerprint.EMBEDDED, 75),
    (r"sony interactive|playstation|nintendo|xbox",
     DeviceType.GAME_CONSOLE, OSFingerprint.ORBIS_OS, 88),
    (r"samsung.*tv|lg.*display|sony.*visual|roku|amazon.*fire|nvidia.*shield|google.*cast|tcl|hisense|vizio",
     DeviceType.SMART_TV, OSFingerprint.LINUX, 78),
    (r"samsung electronics|xiaomi|huawei|motorola|lg electronics|oneplus|oppo|vivo|zte|realme|nothing technology",
     DeviceType.ANDROID_DEVICE, OSFingerprint.ANDROID, 70),
    (r"apple",
     DeviceType.IOS_DEVICE, OSFingerprint.IOS, 75),
    (r"grandstream|yealink|polycom|cisco.*phone|avaya|snom|fanvil",
     DeviceType.VOIP_PHONE, OSFingerprint.EMBEDDED, 75),
    (r"realtek|workstation nic|micro-star|gigabyte|asrock|asustek|lcfc",
     DeviceType.WINDOWS_PC, OSFingerprint.WINDOWS, 65),
    (r"intel.*corp|supermicro|dell.*inc|hewlett.*packard.*enterprise|synology|qnap|buffalo",
     DeviceType.LINUX_SERVER, OSFingerprint.LINUX, 55),
    # Virtualização — OUIs bem conhecidos
    (r"vmware|virtualbox|virtual box|cadmus.*computer|virt|parallels|xen source",
     DeviceType.VIRTUALIZED, OSFingerprint.LINUX, 85),
    (r"qemu|kvm|proxmox",
     DeviceType.VIRTUALIZED, OSFingerprint.LINUX, 85),
    (r"espressif|tuya|shelly|sonoff|tasmota|particle|arduino|raspberry|smart home",
     DeviceType.IOT_SENSOR, OSFingerprint.EMBEDDED, 70),
]

# ─────────────────────────────────────────────────────────────────────────────
# L9 — PORT → DEVICE TYPE MAP
# ─────────────────────────────────────────────────────────────────────────────

_PORT_DEVICE_MAP: Dict[int, Tuple[DeviceType, OSFingerprint, str, int]] = {
    554:  (DeviceType.CCTV_CAMERA,    OSFingerprint.EMBEDDED,  "RTSP (554) — câmera IP",              50),
    8554: (DeviceType.CCTV_CAMERA,    OSFingerprint.EMBEDDED,  "RTSP alt (8554) — câmera IP",          45),
    37777:(DeviceType.CCTV_CAMERA,    OSFingerprint.EMBEDDED,  "Dahua SDK (37777)",                   55),
    34567:(DeviceType.CCTV_CAMERA,    OSFingerprint.EMBEDDED,  "HikVision TCP (34567)",               55),
    8000: (DeviceType.CCTV_CAMERA,    OSFingerprint.EMBEDDED,  "HikVision SDK (8000)",                50),
    9000: (DeviceType.NVR_DVR,        OSFingerprint.EMBEDDED,  "NVR protocol (9000)",                 40),
    445:  (DeviceType.WINDOWS_PC,     OSFingerprint.WINDOWS,   "SMB (445) — Windows",                 45),
    3389: (DeviceType.WINDOWS_PC,     OSFingerprint.WINDOWS,   "RDP (3389) — Desktop Windows",        60),
    135:  (DeviceType.WINDOWS_PC,     OSFingerprint.WINDOWS,   "MS-RPC (135) — Windows",              45),
    5985: (DeviceType.WINDOWS_PC,     OSFingerprint.WINDOWS,   "WinRM (5985) — Windows",              50),
    22:   (DeviceType.LINUX_SERVER,   OSFingerprint.LINUX,     "SSH (22) — Linux/Unix",               35),
    23:   (DeviceType.ROUTER_GATEWAY, OSFingerprint.EMBEDDED,  "Telnet (23) — equipamento legado",    40),
    179:  (DeviceType.ROUTER_GATEWAY, OSFingerprint.CISCO_IOS, "BGP (179) — roteador de borda",       60),
    161:  (DeviceType.NETWORK_PROBE,  OSFingerprint.EMBEDDED,  "SNMP (161) — agente de rede",         50),
    631:  (DeviceType.PRINTER,        OSFingerprint.EMBEDDED,  "IPP (631) — impressora",              55),
    9100: (DeviceType.PRINTER,        OSFingerprint.EMBEDDED,  "RAW Print (9100) — impressora",       60),
    5060: (DeviceType.VOIP_PHONE,     OSFingerprint.EMBEDDED,  "SIP (5060) — VoIP",                   60),
    7000: (DeviceType.IOS_DEVICE,     OSFingerprint.IOS,       "AirPlay (7000) — Apple TV/iOS",       55),
    62078:(DeviceType.IOS_DEVICE,     OSFingerprint.IOS,       "iTunes sync (62078) — iOS/macOS",     65),
    5000: (DeviceType.SMART_TV,       OSFingerprint.LINUX,     "UPnP/DLNA (5000) — Smart TV",         35),
    8001: (DeviceType.SMART_TV,       OSFingerprint.TIZEN,     "Samsung SmartTV API (8001)",          85),
    8002: (DeviceType.SMART_TV,       OSFingerprint.TIZEN,     "Samsung SmartTV TLS (8002)",          85),
    9197: (DeviceType.SMART_TV,       OSFingerprint.TIZEN,     "Samsung DLNA DMR (9197)",             82),
    8008: (DeviceType.SMART_TV,       OSFingerprint.LINUX,     "Google Cast / Smart TV (8008)",       78),
    8888: (DeviceType.SMART_TV,       OSFingerprint.LINUX,     "Smart TV control (8888)",             30),
    1883: (DeviceType.IOT_SENSOR,     OSFingerprint.EMBEDDED,  "MQTT (1883) — IoT",                   55),
    8883: (DeviceType.IOT_SENSOR,     OSFingerprint.EMBEDDED,  "MQTT TLS (8883) — IoT",               50),
    502:  (DeviceType.IOT_SENSOR,     OSFingerprint.EMBEDDED,  "Modbus (502) — ICS/SCADA",            60),
    8443: (DeviceType.ROUTER_GATEWAY, OSFingerprint.EMBEDDED,  "HTTPS / Cast TLS (8443)",             35),
}

_HTTP_PROBE_PORTS = [80, 8080, 8008, 443, 8443, 8000, 81, 4200, 8888, 8081]

# ─────────────────────────────────────────────────────────────────────────────
# L10 — HTTP BANNER SIGNATURES
# ─────────────────────────────────────────────────────────────────────────────

_HTTP_BANNER_SIGNATURES: List[Tuple[str, DeviceType, OSFingerprint, int]] = [
    (r"dahua",                          DeviceType.CCTV_CAMERA,    OSFingerprint.EMBEDDED, 85),
    (r"hikvision|hik.connect",          DeviceType.CCTV_CAMERA,    OSFingerprint.EMBEDDED, 85),
    (r"intelbras",                      DeviceType.CCTV_CAMERA,    OSFingerprint.EMBEDDED, 85),
    (r"axis.*camera|axis.*network",     DeviceType.CCTV_CAMERA,    OSFingerprint.EMBEDDED, 80),
    (r"vivotek",                        DeviceType.CCTV_CAMERA,    OSFingerprint.EMBEDDED, 85),
    (r"hanwha|wisenet",                 DeviceType.CCTV_CAMERA,    OSFingerprint.EMBEDDED, 85),
    (r"reolink",                        DeviceType.CCTV_CAMERA,    OSFingerprint.EMBEDDED, 80),
    (r"uniview|unv",                    DeviceType.CCTV_CAMERA,    OSFingerprint.EMBEDDED, 80),
    (r"nvr|dvr|digital video recorder", DeviceType.NVR_DVR,        OSFingerprint.EMBEDDED, 65),
    (r"ip camera|ipcamera|webcam|netcam",DeviceType.CCTV_CAMERA,   OSFingerprint.EMBEDDED, 70),
    (r"rtsp://",                        DeviceType.CCTV_CAMERA,    OSFingerprint.EMBEDDED, 60),
    (r"mikrotik|routeros",              DeviceType.ROUTER_GATEWAY,  OSFingerprint.MIKROTIK, 92),
    (r"cisco.*ios|cisco.*router",       DeviceType.ROUTER_GATEWAY,  OSFingerprint.CISCO_IOS,88),
    (r"ubiquiti|unifi|airmax|airfiber", DeviceType.ACCESS_POINT,    OSFingerprint.LINUX,    85),
    (r"openwrt",                        DeviceType.ROUTER_GATEWAY,  OSFingerprint.LINUX,    85),
    (r"dd.wrt",                         DeviceType.ROUTER_GATEWAY,  OSFingerprint.LINUX,    85),
    (r"tp.?link|tplink",                DeviceType.ROUTER_GATEWAY,  OSFingerprint.EMBEDDED, 75),
    (r"netgear",                        DeviceType.ROUTER_GATEWAY,  OSFingerprint.EMBEDDED, 75),
    (r"d.link|dlink",                   DeviceType.ROUTER_GATEWAY,  OSFingerprint.EMBEDDED, 75),
    (r"zyxel",                          DeviceType.ROUTER_GATEWAY,  OSFingerprint.EMBEDDED, 75),
    (r"fortinet|fortigate",             DeviceType.ROUTER_GATEWAY,  OSFingerprint.EMBEDDED, 88),
    (r"palo alto|pan.os",               DeviceType.ROUTER_GATEWAY,  OSFingerprint.EMBEDDED, 88),
    (r"synology.*dsm|diskstation",      DeviceType.LINUX_SERVER,    OSFingerprint.LINUX,    85),
    (r"qnap.*qts|turbonas",             DeviceType.LINUX_SERVER,    OSFingerprint.LINUX,    85),
    (r"samsung.*tv|lg.*webos|lg.*smart",DeviceType.SMART_TV,        OSFingerprint.LINUX,    78),
    (r"vizio|roku|chromecast|fire tv",  DeviceType.SMART_TV,        OSFingerprint.LINUX,    78),
    (r"epson|ricoh|xerox|canon|hp.*laserjet|brother|kyocera|konica",
                                        DeviceType.PRINTER,         OSFingerprint.EMBEDDED, 82),
    (r"grandstream|yealink|polycom|snom|fanvil|avaya",
                                        DeviceType.VOIP_PHONE,      OSFingerprint.EMBEDDED, 82),
    (r"vmware|esxi|vcenter",            DeviceType.VIRTUALIZED,     OSFingerprint.LINUX,    85),
    (r"proxmox",                        DeviceType.VIRTUALIZED,     OSFingerprint.LINUX,    85),
    (r"iis/\d|microsoft.*iis",          DeviceType.WINDOWS_PC,      OSFingerprint.WINDOWS,  65),
    (r"windows.*server",                DeviceType.WINDOWS_PC,      OSFingerprint.WINDOWS,  60),
    (r"apache|nginx|lighttpd",          DeviceType.LINUX_SERVER,    OSFingerprint.LINUX,    50),
    (r"raspberry pi|raspbian",          DeviceType.IOT_SENSOR,      OSFingerprint.LINUX,    80),
    (r"espressif|esp8266|esp32",        DeviceType.IOT_SENSOR,      OSFingerprint.EMBEDDED, 82),
    (r"shelly|tasmota|sonoff",          DeviceType.IOT_SENSOR,      OSFingerprint.EMBEDDED, 85),
    (r"tuya|smart life",                DeviceType.IOT_SENSOR,      OSFingerprint.EMBEDDED, 80),
]


# ─────────────────────────────────────────────────────────────────────────────
# FUNÇÕES AUXILIARES
# ─────────────────────────────────────────────────────────────────────────────

def _is_mac_randomized(mac: str) -> bool:
    try:
        return bool(int(mac[:2], 16) & 0x02) if mac and len(mac) >= 2 else False
    except ValueError:
        return False


def _check_special_mac(mac: str) -> Optional[Tuple[DeviceType, OSFingerprint, int, str]]:
    mac_l = mac.lower()
    for prefix, dev_type, os_fp, confidence, desc in _SPECIAL_MAC_PREFIXES:
        if mac_l.startswith(prefix) or mac_l == prefix:
            return dev_type, os_fp, confidence, desc
    return None


def _oui_vendor_hint(vendor: str) -> Optional[Tuple[DeviceType, OSFingerprint, int]]:
    if not vendor or vendor in ("Fabricante desconhecido", ""):
        return None
    v = vendor.lower()
    for pattern, dev_type, os_fp, confidence in _OUI_VENDOR_HINTS:
        if re.search(pattern, v):
            return dev_type, os_fp, confidence
    return None


def _ttl_fingerprint(ip: str, timeout_s: float = 1.5) -> Tuple[Optional[int], OSFingerprint, str]:
    try:
        import subprocess, os as _os
        if _os.name == "nt":
            result = subprocess.run(
                ["ping", "-n", "1", "-w", str(int(timeout_s * 1000)), ip],
                capture_output=True, text=True, errors="ignore", timeout=timeout_s + 1,
                creationflags=0x08000000
            )
        else:
            result = subprocess.run(
                ["ping", "-c", "1", "-W", str(int(max(1, timeout_s))), ip],
                capture_output=True, text=True, errors="ignore", timeout=timeout_s + 2
            )
        ttl_match = re.search(r"ttl[= ](\d+)", result.stdout.lower())
        if not ttl_match:
            return None, OSFingerprint.UNKNOWN, ""
        ttl = int(ttl_match.group(1))
        if ttl >= 240:
            return ttl, OSFingerprint.CISCO_IOS, f"TTL={ttl} → Cisco IOS / Juniper (padrão 255)"
        elif ttl >= 100:
            return ttl, OSFingerprint.WINDOWS,   f"TTL={ttl} → Windows (padrão 128)"
        elif ttl >= 50:
            return ttl, OSFingerprint.LINUX,     f"TTL={ttl} → Linux/Android/iOS (padrão 64)"
        else:
            return ttl, OSFingerprint.EMBEDDED,  f"TTL={ttl} → Sistema embarcado (TTL atípico)"
    except Exception:
        return None, OSFingerprint.UNKNOWN, ""


def _resolve_hostname(ip: str, timeout_s: float = 0.45) -> Optional[str]:
    """Resolve PTR DNS rapidamente sem bloquear por 4.5s no fallback NetBIOS do Windows."""
    import concurrent.futures
    def _do_lookup():
        try:
            name, _, _ = socket.gethostbyaddr(ip)
            return name if name and name != ip else None
        except Exception:
            return None
    try:
        ex = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        fut = ex.submit(_do_lookup)
        res = fut.result(timeout=timeout_s)
        ex.shutdown(wait=False, cancel_futures=True)
        return res
    except Exception:
        return None


def _netbios_query(ip: str, timeout_s: float = 1.5) -> Optional[str]:
    """NetBIOS Name Service NBSTAT request (UDP 137)."""
    NBNS_REQUEST = (
        b"\x82\x28\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x20\x43\x4b\x41\x41\x41\x41\x41\x41\x41\x41\x41"
        b"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"
        b"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00"
        b"\x00\x21\x00\x01"
    )
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout_s)
            s.sendto(NBNS_REQUEST, (ip, 137))
            data, _ = s.recvfrom(1024)
            if len(data) < 57:
                return None
            num_names = data[56]
            if num_names == 0 or len(data) < 57 + 18:
                return None
            raw_name = data[57:57 + 15].decode("ascii", errors="ignore")
            name = raw_name.rstrip("\x00").strip()
            return name if name else None
    except Exception:
        return None


# ─────────────────────────────────────────────────────────────────────────────
# L12 — CATÁLOGO DE MODELOS EXATOS (Samsung, Motorola, Apple iPhone, Xiaomi, TV)
# ─────────────────────────────────────────────────────────────────────────────

_EXACT_MODEL_CATALOG: List[Tuple[str, str, DeviceType, OSFingerprint]] = [
    # ── Samsung Galaxy S Series (incluindo S20 FE / S21 FE / S23 FE) ──────────
    (r"\bSM-G78[01][A-Z0-9]*\b|galaxy\s*s20\s*fe|\bs20\s*fe\b", "Samsung Galaxy S20 FE", DeviceType.ANDROID_DEVICE, OSFingerprint.ANDROID),
    (r"\bSM-G990[A-Z0-9]*\b|galaxy\s*s21\s*fe|\bs21\s*fe\b", "Samsung Galaxy S21 FE", DeviceType.ANDROID_DEVICE, OSFingerprint.ANDROID),
    (r"\bSM-S711[A-Z0-9]*\b|galaxy\s*s23\s*fe|\bs23\s*fe\b", "Samsung Galaxy S23 FE", DeviceType.ANDROID_DEVICE, OSFingerprint.ANDROID),
    (r"\bSM-G98[01568][A-Z0-9]*\b|galaxy\s*s20\b", "Samsung Galaxy S20", DeviceType.ANDROID_DEVICE, OSFingerprint.ANDROID),
    (r"\bSM-G99[168][A-Z0-9]*\b|galaxy\s*s21\b", "Samsung Galaxy S21", DeviceType.ANDROID_DEVICE, OSFingerprint.ANDROID),
    (r"\bSM-S90[168][A-Z0-9]*\b|galaxy\s*s22\b", "Samsung Galaxy S22", DeviceType.ANDROID_DEVICE, OSFingerprint.ANDROID),
    (r"\bSM-S91[168][A-Z0-9]*\b|galaxy\s*s23\b", "Samsung Galaxy S23", DeviceType.ANDROID_DEVICE, OSFingerprint.ANDROID),
    (r"\bSM-S92[168][A-Z0-9]*\b|galaxy\s*s24\b", "Samsung Galaxy S24", DeviceType.ANDROID_DEVICE, OSFingerprint.ANDROID),
    # ── Samsung Galaxy A & M Series ───────────────────────────────────────────
    (r"\bSM-A546[A-Z0-9]*\b|galaxy\s*a54\b", "Samsung Galaxy A54 5G", DeviceType.ANDROID_DEVICE, OSFingerprint.ANDROID),
    (r"\bSM-A556[A-Z0-9]*\b|galaxy\s*a55\b", "Samsung Galaxy A55 5G", DeviceType.ANDROID_DEVICE, OSFingerprint.ANDROID),
    (r"\bSM-A536[A-Z0-9]*\b|galaxy\s*a53\b", "Samsung Galaxy A53 5G", DeviceType.ANDROID_DEVICE, OSFingerprint.ANDROID),
    (r"\bSM-A52[568][A-Z0-9]*\b|galaxy\s*a52\b", "Samsung Galaxy A52", DeviceType.ANDROID_DEVICE, OSFingerprint.ANDROID),
    (r"\bSM-A346[A-Z0-9]*\b|galaxy\s*a34\b", "Samsung Galaxy A34 5G", DeviceType.ANDROID_DEVICE, OSFingerprint.ANDROID),
    (r"\bSM-A356[A-Z0-9]*\b|galaxy\s*a35\b", "Samsung Galaxy A35 5G", DeviceType.ANDROID_DEVICE, OSFingerprint.ANDROID),
    (r"\bSM-A15[56][A-Z0-9]*\b|galaxy\s*a15\b", "Samsung Galaxy A15", DeviceType.ANDROID_DEVICE, OSFingerprint.ANDROID),
    (r"\bSM-A14[56][A-Z0-9]*\b|galaxy\s*a14\b", "Samsung Galaxy A14", DeviceType.ANDROID_DEVICE, OSFingerprint.ANDROID),
    (r"\bSM-A05[57][A-Z0-9]*\b|galaxy\s*a05\b", "Samsung Galaxy A05", DeviceType.ANDROID_DEVICE, OSFingerprint.ANDROID),
    (r"\bSM-M536[A-Z0-9]*\b|galaxy\s*m53\b", "Samsung Galaxy M53 5G", DeviceType.ANDROID_DEVICE, OSFingerprint.ANDROID),
    (r"\bSM-M546[A-Z0-9]*\b|galaxy\s*m54\b", "Samsung Galaxy M54 5G", DeviceType.ANDROID_DEVICE, OSFingerprint.ANDROID),
    # ── Motorola Moto E, Moto G & Edge Series ─────────────────────────────────
    (r"moto\s*e50|motorola\s*e50|\bXT215[0-9]\b", "Motorola Moto E50", DeviceType.ANDROID_DEVICE, OSFingerprint.ANDROID),
    (r"moto\s*e40|motorola\s*e40|\bXT2159\b", "Motorola Moto E40", DeviceType.ANDROID_DEVICE, OSFingerprint.ANDROID),
    (r"moto\s*e22|motorola\s*e22|\bXT2239\b", "Motorola Moto E22", DeviceType.ANDROID_DEVICE, OSFingerprint.ANDROID),
    (r"moto\s*e20|motorola\s*e20|\bXT2155\b", "Motorola Moto E20", DeviceType.ANDROID_DEVICE, OSFingerprint.ANDROID),
    (r"moto\s*e13|motorola\s*e13|\bXT2345\b", "Motorola Moto E13", DeviceType.ANDROID_DEVICE, OSFingerprint.ANDROID),
    (r"moto\s*g84|\bXT2347\b", "Motorola Moto G84 5G", DeviceType.ANDROID_DEVICE, OSFingerprint.ANDROID),
    (r"moto\s*g54|\bXT2343\b", "Motorola Moto G54 5G", DeviceType.ANDROID_DEVICE, OSFingerprint.ANDROID),
    (r"moto\s*g53|\bXT2335\b", "Motorola Moto G53 5G", DeviceType.ANDROID_DEVICE, OSFingerprint.ANDROID),
    (r"moto\s*g52|\bXT2221\b", "Motorola Moto G52", DeviceType.ANDROID_DEVICE, OSFingerprint.ANDROID),
    (r"moto\s*g34|\bXT2363\b", "Motorola Moto G34 5G", DeviceType.ANDROID_DEVICE, OSFingerprint.ANDROID),
    (r"moto\s*g24|\bXT2423\b", "Motorola Moto G24", DeviceType.ANDROID_DEVICE, OSFingerprint.ANDROID),
    (r"motorola\s*edge\s*40|\bXT230[13]\b", "Motorola Edge 40", DeviceType.ANDROID_DEVICE, OSFingerprint.ANDROID),
    (r"motorola\s*edge\s*30|\bXT2203\b", "Motorola Edge 30", DeviceType.ANDROID_DEVICE, OSFingerprint.ANDROID),
    # ── Apple iPhone Models (Internal Identifiers & Marketing Names) ──────────
    (r"iphone16,2|iphone\s*15\s*pro\s*max", "Apple iPhone 15 Pro Max", DeviceType.IOS_DEVICE, OSFingerprint.IOS),
    (r"iphone16,1|iphone\s*15\s*pro\b", "Apple iPhone 15 Pro", DeviceType.IOS_DEVICE, OSFingerprint.IOS),
    (r"iphone15,5|iphone\s*15\s*plus", "Apple iPhone 15 Plus", DeviceType.IOS_DEVICE, OSFingerprint.IOS),
    (r"iphone15,4|iphone\s*15\b", "Apple iPhone 15", DeviceType.IOS_DEVICE, OSFingerprint.IOS),
    (r"iphone15,3|iphone\s*14\s*pro\s*max", "Apple iPhone 14 Pro Max", DeviceType.IOS_DEVICE, OSFingerprint.IOS),
    (r"iphone15,2|iphone\s*14\s*pro\b", "Apple iPhone 14 Pro", DeviceType.IOS_DEVICE, OSFingerprint.IOS),
    (r"iphone14,8|iphone\s*14\s*plus", "Apple iPhone 14 Plus", DeviceType.IOS_DEVICE, OSFingerprint.IOS),
    (r"iphone14,7|iphone\s*14\b", "Apple iPhone 14", DeviceType.IOS_DEVICE, OSFingerprint.IOS),
    (r"iphone14,3|iphone\s*13\s*pro\s*max", "Apple iPhone 13 Pro Max", DeviceType.IOS_DEVICE, OSFingerprint.IOS),
    (r"iphone14,2|iphone\s*13\s*pro\b", "Apple iPhone 13 Pro", DeviceType.IOS_DEVICE, OSFingerprint.IOS),
    (r"iphone14,4|iphone\s*13\s*mini", "Apple iPhone 13 mini", DeviceType.IOS_DEVICE, OSFingerprint.IOS),
    (r"iphone14,5|iphone\s*13\b", "Apple iPhone 13", DeviceType.IOS_DEVICE, OSFingerprint.IOS),
    (r"iphone13,4|iphone\s*12\s*pro\s*max", "Apple iPhone 12 Pro Max", DeviceType.IOS_DEVICE, OSFingerprint.IOS),
    (r"iphone13,3|iphone\s*12\s*pro\b", "Apple iPhone 12 Pro", DeviceType.IOS_DEVICE, OSFingerprint.IOS),
    (r"iphone13,2|iphone\s*12\b", "Apple iPhone 12", DeviceType.IOS_DEVICE, OSFingerprint.IOS),
    (r"iphone12,5|iphone\s*11\s*pro\s*max", "Apple iPhone 11 Pro Max", DeviceType.IOS_DEVICE, OSFingerprint.IOS),
    (r"iphone12,3|iphone\s*11\s*pro\b", "Apple iPhone 11 Pro", DeviceType.IOS_DEVICE, OSFingerprint.IOS),
    (r"iphone12,1|iphone\s*11\b", "Apple iPhone 11", DeviceType.IOS_DEVICE, OSFingerprint.IOS),
    # ── Xiaomi / Redmi / POCO ─────────────────────────────────────────────────
    (r"redmi\s*note\s*13\s*pro", "Xiaomi Redmi Note 13 Pro", DeviceType.ANDROID_DEVICE, OSFingerprint.ANDROID),
    (r"redmi\s*note\s*13\b", "Xiaomi Redmi Note 13", DeviceType.ANDROID_DEVICE, OSFingerprint.ANDROID),
    (r"redmi\s*note\s*12\b", "Xiaomi Redmi Note 12", DeviceType.ANDROID_DEVICE, OSFingerprint.ANDROID),
    (r"poco\s*x6\s*pro", "Xiaomi POCO X6 Pro", DeviceType.ANDROID_DEVICE, OSFingerprint.ANDROID),
    (r"poco\s*x5\s*pro", "Xiaomi POCO X5 Pro", DeviceType.ANDROID_DEVICE, OSFingerprint.ANDROID),
    (r"poco\s*f5\b", "Xiaomi POCO F5", DeviceType.ANDROID_DEVICE, OSFingerprint.ANDROID),
    # ── Smart TVs & Consoles (Samsung Tizen, TCL Android TV / UnionTV, LG webOS, PlayStation) ─
    (r"UN32T4300[A-Z0-9]*", "Samsung Smart TV 32\" Série 4 (UN32T4300)", DeviceType.SMART_TV, OSFingerprint.TIZEN),
    (r"\[tv\]\s*samsung\s*([a-z0-9 \(\)]+)|samsung.*series.*tv", "Samsung Smart TV (Tizen)", DeviceType.SMART_TV, OSFingerprint.TIZEN),
    (r"tcl\s*tv\s*c06|mediatek\s*t56\s*cast", "TCL Smart TV (Série C06 / Google Cast)", DeviceType.SMART_TV, OSFingerprint.LINUX),
    (r"tcl\s*tv\s*uniontv|uniontv.*rt2984|uniontv|tcl\s*smart\s*tv|beyondtv", "TCL Smart TV (Android TV / Google Cast)", DeviceType.SMART_TV, OSFingerprint.LINUX),
    (r"lg\s*webos|\[lg\]\s*webos", "LG Smart TV (webOS)", DeviceType.SMART_TV, OSFingerprint.LINUX),
    (r"\bps5\b|playstation\s*5", "Sony PlayStation 5", DeviceType.GAME_CONSOLE, OSFingerprint.ORBIS_OS),
    (r"\bps4\b|playstation\s*4|\bps4-[0-9a-z]+\b", "Sony PlayStation 4", DeviceType.GAME_CONSOLE, OSFingerprint.ORBIS_OS),
]


def translate_hardware_model(raw_text: str) -> Optional[Tuple[str, DeviceType, OSFingerprint]]:
    """
    Traduz códigos técnicos de OEM (ex: SM-G780G, XT2155, iPhone14,5, UN32T4300) ou nomes de marketing
    para o nome comercial amigável completo + categoria de dispositivo + sistema operacional.
    """
    if not raw_text:
        return None
    cleaned = raw_text.strip()
    for pattern, friendly_model, dev_type, os_fp in _EXACT_MODEL_CATALOG:
        if re.search(pattern, cleaned, re.IGNORECASE):
            return (friendly_model, dev_type, os_fp)

    # Fallback genérico para códigos SM-XXXX da Samsung ainda não listados individualmente
    m_sam = re.search(r"\b(SM-[A-Z][0-9]{3}[A-Z0-9]*)\b", cleaned, re.IGNORECASE)
    if m_sam:
        return (f"Samsung Galaxy ({m_sam.group(1).upper()})", DeviceType.ANDROID_DEVICE, OSFingerprint.ANDROID)

    # Fallback genérico para códigos XTXXXX da Motorola
    m_moto = re.search(r"\b(XT[0-9]{4}[A-Z0-9-]*)\b", cleaned, re.IGNORECASE)
    if m_moto:
        return (f"Motorola ({m_moto.group(1).upper()})", DeviceType.ANDROID_DEVICE, OSFingerprint.ANDROID)

    # Fallback genérico para códigos UNXX / QNXX de Smart TVs Samsung
    m_tv = re.search(r"\b((?:UN|QN)[0-9]{2}[A-Z0-9]{4,12})\b", cleaned, re.IGNORECASE)
    if m_tv:
        return (f"Samsung Smart TV ({m_tv.group(1).upper()})", DeviceType.SMART_TV, OSFingerprint.TIZEN)

    return None


def _get_local_bind_ip_for_target(target_ip: str) -> str:
    """Descobre o IP local da interface que roteia para target_ip (necessário para mDNS QU)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((target_ip, 5353))
            return s.getsockname()[0]
    except Exception:
        return "0.0.0.0"


def _encode_dns_name(name: str) -> bytes:
    out = b""
    for part in name.strip(".").split("."):
        b = part.encode("utf-8")
        out += bytes([len(b)]) + b
    return out + b"\x00"


def _decode_dns_name(data: bytes, offset: int, max_jumps: int = 12) -> Tuple[str, int]:
    """Decodifica um nome DNS do formato de fio (wire format), suportando ponteiros 0xC0."""
    labels: List[str] = []
    pos = offset
    end_pos = -1
    jumps = 0
    n = len(data)
    while pos < n and jumps < max_jumps:
        length = data[pos]
        if length == 0:
            pos += 1
            break
        if (length & 0xC0) == 0xC0:
            if pos + 1 >= n:
                pos += 1
                break
            if end_pos == -1:
                end_pos = pos + 2
            pointer = ((length & 0x3F) << 8) | data[pos + 1]
            pos = pointer
            jumps += 1
            continue
        pos += 1
        if pos + length > n:
            break
        label = data[pos:pos + length].decode("utf-8", errors="ignore")
        labels.append(label)
        pos += length
    if end_pos == -1:
        end_pos = pos
    return ".".join(labels), end_pos


def _decode_nearby_endpoint_name(instance_label: str) -> Optional[str]:
    """
    Decodifica o nome/modelo do smartphone a partir do Endpoint Info Base64URL
    do Google Quick Share / Nearby Share (_FC9F5ED42C8A._tcp.local).
    Estrutura do byte array: [version/vis(1B)][endpoint_id(4B)][service_id_hash(3B)]...[len(1B)][UTF-8 device name].
    """
    try:
        import base64
        padded = instance_label.strip() + "=" * ((4 - len(instance_label.strip()) % 4) % 4)
        raw = base64.urlsafe_b64decode(padded)
        if len(raw) >= 18:
            name_len = raw[17]
            if 2 <= name_len <= 64 and 18 + name_len <= len(raw):
                dev_name = raw[18:18 + name_len].decode("utf-8", errors="ignore").strip()
                if dev_name and all(ord(c) >= 32 for c in dev_name):
                    return dev_name
    except Exception:
        pass
    return None


def _fetch_spotify_zeroconf(ip: str, port: int, cpath: str = "/spConn", timeout_s: float = 0.85) -> Optional[Dict[str, str]]:
    """Executa Handshake ZeroConf na porta Spotify Connect anunciada via mDNS (?action=getInfo)."""
    if not cpath.startswith("/"):
        cpath = "/" + cpath
    url = f"http://{ip}:{port}{cpath}?action=getInfo"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "BastionAudit-Intel/4.0"})
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            data = json.loads(resp.read(4096).decode("utf-8", errors="ignore"))
            remote_name = str(data.get("remoteName") or "").strip()
            brand = str(data.get("brandDisplayName") or "").strip()
            model = str(data.get("modelDisplayName") or "").strip()
            dev_type = str(data.get("deviceType") or "").strip()
            if remote_name or model or brand:
                return {
                    "remote_name": remote_name,
                    "brand": brand,
                    "model": model,
                    "device_type": dev_type,
                }
    except Exception:
        pass
    return None


def _parse_mdns_wire_packet(data: bytes, result: Dict[str, Any]):
    """
    Parser estruturado de pacotes DNS/mDNS (RFC 6762):
    Extrai PTR, SRV (porta e hostname .local) e registros TXT em UTF-8 completo
    sem truncar acentos (ex: 'smart do André') e sem perder labels comprimidos ('PS4-734165.local').
    """
    try:
        if len(data) < 12:
            return
        qdcount, ancount, nscount, arcount = struct.unpack("!HHHH", data[4:12])
        pos = 12
        n = len(data)
        for _ in range(qdcount):
            if pos >= n:
                return
            _, pos = _decode_dns_name(data, pos)
            pos += 4

        total_rr = ancount + nscount + arcount
        for _ in range(total_rr):
            if pos >= n:
                break
            rr_name, pos = _decode_dns_name(data, pos)
            if pos + 10 > n:
                break
            rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", data[pos:pos + 10])
            pos += 10
            if pos + rdlen > n:
                break
            rdata = data[pos:pos + rdlen]
            rdata_offset = pos
            pos += rdlen

            rr_low = rr_name.lower()
            for svc in (
                "_nearbypresence", "_fc9f5ed42c8a", "_companion-link", "_airplay",
                "_raop", "_googlecast", "_androidtvremote2", "_spotify-connect",
                "_samsungmsf", "_smartview", "_mi-connect", "_kdeconnect",
                "_adb-tls-connect", "_smb", "_ipp", "_printer", "_ssh",
            ):
                if svc in rr_low and svc not in result["services"]:
                    result["services"].append(svc)

            # PTR (12)
            if rtype == 12:
                target_name, _ = _decode_dns_name(data, rdata_offset)
                if target_name and target_name not in result["raw_strings"]:
                    result["raw_strings"].append(target_name)
                t_low = target_name.lower()
                for svc in (
                    "_nearbypresence", "_fc9f5ed42c8a", "_companion-link", "_airplay",
                    "_raop", "_googlecast", "_androidtvremote2", "_spotify-connect",
                    "_samsungmsf", "_smartview", "_mi-connect", "_kdeconnect",
                    "_adb-tls-connect",
                ):
                    if svc in t_low and svc not in result["services"]:
                        result["services"].append(svc)

                # Google Quick Share / Nearby Share endpoint decoding
                if "_fc9f5ed42c8a._tcp.local" in t_low:
                    inst = target_name.split(".")[0]
                    decoded_nearby = _decode_nearby_endpoint_name(inst)
                    if decoded_nearby:
                        result["friendly_name"] = decoded_nearby
                        result["model_hint"] = decoded_nearby

                if t_low.endswith(".local") and not any(x in t_low for x in ("_tcp", "_udp", "_dns-sd")):
                    cand = target_name[:-6].strip(".")
                    if cand and not result["hostname"]:
                        result["hostname"] = cand

            # SRV (33) -> priority(2), weight(2), port(2), target_name
            elif rtype == 33 and rdlen >= 6:
                _, _, srv_port = struct.unpack("!HHH", rdata[:6])
                srv_target, _ = _decode_dns_name(data, rdata_offset + 6)
                if srv_target and srv_target.lower().endswith(".local"):
                    cand = srv_target[:-6].strip(".")
                    if cand and not any(x in cand.lower() for x in ("_tcp", "_udp", "_dns-sd")):
                        if not result["hostname"]:
                            result["hostname"] = cand
                if "_spotify-connect" in rr_low and srv_port > 0:
                    result["spotify_port"] = srv_port

            # TXT (16) -> sequence of length-prefixed UTF-8 strings
            elif rtype == 16:
                tpos = 0
                while tpos < len(rdata):
                    tlen = rdata[tpos]
                    tpos += 1
                    if tpos + tlen > len(rdata):
                        break
                    kv = rdata[tpos:tpos + tlen].decode("utf-8", errors="ignore").strip()
                    tpos += tlen
                    if kv and kv not in result["raw_strings"]:
                        result["raw_strings"].append(kv)
                    kv_low = kv.lower()
                    for prefix, key in (
                        ("model=", "model_hint"),
                        ("md=", "model_hint"),
                        ("fn=", "friendly_name"),
                        ("ty=", "model_hint"),
                        ("n=", "friendly_name"),
                        ("name=", "friendly_name"),
                        ("cpath=", "spotify_cpath"),
                    ):
                        if kv_low.startswith(prefix) and len(kv) > len(prefix):
                            val = kv[len(prefix):].strip()
                            if val and not result.get(key):
                                result[key] = val
    except Exception:
        pass


def _mdns_query(ip: str, timeout_s: float = 0.9) -> Dict[str, Any]:
    """
    L7: Handshake mDNS / Bonjour / Google Quick Share / Apple Continuity / Spotify Connect (UDP 5353).
    Suporta decodificação DNS Wire-Format completa (ponteiros 0xC0 + UTF-8 com acentuação).
    """
    result: Dict[str, Any] = {
        "hostname": None,
        "services": [],
        "model_hint": None,
        "friendly_name": None,
        "spotify_port": None,
        "spotify_cpath": None,
        "raw_strings": [],
    }
    try:
        rev_ip = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
        questions = [
            (rev_ip, 255),                            # ANY / PTR do IP
            ("_services._dns-sd._udp.local", 255),    # Todos os serviços DNS-SD
            ("_FC9F5ED42C8A._tcp.local", 255),        # Google Quick Share / Nearby Share (contém nome do modelo)
            ("_nearbypresence._tcp.local", 255),      # Android Nearby Presence
            ("_companion-link._tcp.local", 255),      # Apple iOS / macOS Continuity
            ("_device-info._tcp.local", 255),         # Apple / Linux Device Info
            ("_airplay._tcp.local", 255),             # Apple AirPlay / Smart TV
            ("_spotify-connect._tcp.local", 255),     # Spotify Connect ZeroConf
            ("_googlecast._tcp.local", 255),          # Google Cast / Smart TV
            ("_androidtvremote2._tcp.local", 255),    # Android TV Remote
            ("_samsungmsf._tcp.local", 255),          # Samsung SmartThings / MultiScreen
            ("_mi-connect._udp.local", 255),          # Xiaomi Mi Connect
        ]
        header = struct.pack("!HHHHHH", 0x1337, 0x0000, len(questions), 0, 0, 0)
        q_bytes = b""
        for qname, qtype in questions:
            q_bytes += _encode_dns_name(qname) + struct.pack("!HH", qtype, 0x8001)
        pkt = header + q_bytes

        local_ip = _get_local_bind_ip_for_target(ip)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as s:
            s.settimeout(timeout_s)
            if local_ip and local_ip != "0.0.0.0":
                try:
                    s.bind((local_ip, 0))
                except Exception:
                    pass
            try:
                s.sendto(pkt, (ip, 5353))
            except Exception:
                pass
            try:
                s.sendto(pkt, ("224.0.0.251", 5353))
            except Exception:
                pass

            deadline = time.time() + timeout_s
            while time.time() < deadline:
                rem = max(0.05, deadline - time.time())
                s.settimeout(rem)
                try:
                    data, addr = s.recvfrom(4096)
                except socket.timeout:
                    break
                except Exception:
                    break

                if addr[0] != ip:
                    continue

                # 1. Parser estruturado Wire-Format + UTF-8
                _parse_mdns_wire_packet(data, result)

                # 2. Fallback para strings UTF-8 caso pacotes não convencionais venham no payload
                text_utf8 = data.decode("utf-8", errors="ignore")
                for tok in re.findall(r"[\w\-\.\:\=\/\(\)\[\]\s\u00C0-\u017F]{3,}", text_utf8):
                    tok = tok.strip()
                    if not tok:
                        continue
                    if tok not in result["raw_strings"]:
                        result["raw_strings"].append(tok)
                    for prefix, key in (("model=", "model_hint"), ("md=", "model_hint"), ("fn=", "friendly_name"), ("ty=", "model_hint")):
                        if tok.lower().startswith(prefix) and len(tok) > len(prefix):
                            val = tok[len(prefix):].strip()
                            if val and not result[key]:
                                result[key] = val
                    if not result["hostname"]:
                        m_win = re.search(r"\b(DESKTOP-[A-Za-z0-9_-]+|LAPTOP-[A-Za-z0-9_-]+|Android_[A-Za-z0-9_-]+|Galaxy-[A-Za-z0-9_-]+|PS4-[A-Za-z0-9_-]+|PS5-[A-Za-z0-9_-]+|iPhone[A-Za-z0-9_-]*|iPad[A-Za-z0-9_-]*)\b", tok)
                        if m_win:
                            result["hostname"] = m_win.group(1)

        # Se o dispositivo anunciou porta Spotify Connect ZeroConf, faz o handshake HTTP para pegar modelo e nome real!
        if result.get("spotify_port"):
            sp_info = _fetch_spotify_zeroconf(ip, int(result["spotify_port"]), result.get("spotify_cpath") or "/spConn")
            if sp_info:
                if sp_info.get("remote_name") and not result["friendly_name"]:
                    result["friendly_name"] = sp_info["remote_name"]
                if sp_info.get("model"):
                    result["model_hint"] = sp_info["model"]
                result["spotify_info"] = sp_info
    except Exception:
        pass
    return result


def _fetch_samsung_tv_info(ip: str, timeout_s: float = 0.9) -> Optional[Dict[str, str]]:
    """
    Handshake Oficial Samsung SmartTV Tizen REST API v2 (:8001/api/v2/) e UPnP DMR (:9197/dmr).
    Retorna nome amigável ('[TV] Samsung 4 Series (32)'), código exato do modelo ('UN32T4300AGXZD'),
    sistema operacional ('Tizen'), resolução ('1366x768') e número de série ('Y4HX3X2R908441D').
    """
    info: Dict[str, str] = {
        "friendly_name": "",
        "model_code": "",
        "os": "",
        "resolution": "",
        "serial_number": "",
    }
    try:
        req = urllib.request.Request(f"http://{ip}:8001/api/v2/", headers={"User-Agent": "BastionAudit-Intel/4.0"})
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            data = json.loads(resp.read(4096).decode("utf-8", errors="ignore"))
            dev = data.get("device") or {}
            info["friendly_name"] = str(dev.get("name") or data.get("name") or "").strip()
            info["model_code"] = str(dev.get("modelName") or dev.get("model") or "").strip()
            info["os"] = str(dev.get("OS") or "Tizen").strip()
            info["resolution"] = str(dev.get("resolution") or "").strip()
    except Exception:
        pass

    try:
        req_dmr = urllib.request.Request(f"http://{ip}:9197/dmr", headers={"User-Agent": "BastionAudit-Intel/4.0"})
        with urllib.request.urlopen(req_dmr, timeout=timeout_s) as resp_dmr:
            xml = resp_dmr.read(4096).decode("utf-8", errors="ignore")
            fn = re.search(r"<friendlyName>([^<]+)</friendlyName>", xml, re.IGNORECASE)
            mdl = re.search(r"<modelName>([^<]+)</modelName>", xml, re.IGNORECASE)
            sn = re.search(r"<serialNumber>([^<]+)</serialNumber>", xml, re.IGNORECASE)
            if fn and not info["friendly_name"]:
                info["friendly_name"] = fn.group(1).strip()
            if mdl and not info["model_code"]:
                info["model_code"] = mdl.group(1).strip()
            if sn:
                info["serial_number"] = sn.group(1).strip()
    except Exception:
        pass

    if any(info.values()):
        return info
    return None


def _fetch_playstation_info(ip: str, timeout_s: float = 0.75) -> Optional[Dict[str, str]]:
    """
    Handshake Oficial Sony PlayStation DDPlay Discovery (UDP 987 / 9302).
    Identifica PS4 e PS5 mesmo em Modo Repouso (620 Server Standby) ou Ligado (200 OK),
    extraindo host-type (PS4/PS5), host-name (PS4-364), host-id e versão de sistema.
    """
    probe_pkt = b"SRCH * HTTP/1.1\r\ndevice-discovery-protocol-version:00020020\r\n\r\n"
    for port in (987, 9302):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout_s)
                s.sendto(probe_pkt, (ip, port))
                data, addr = s.recvfrom(2048)
                if addr[0] != ip:
                    continue
                txt = data.decode("utf-8", errors="ignore")
                if "host-type:" in txt.lower() or "device-discovery-protocol" in txt.lower():
                    ht = re.search(r"host-type:\s*([^\r\n]+)", txt, re.IGNORECASE)
                    hn = re.search(r"host-name:\s*([^\r\n]+)", txt, re.IGNORECASE)
                    hid = re.search(r"host-id:\s*([^\r\n]+)", txt, re.IGNORECASE)
                    sv = re.search(r"system-version:\s*([^\r\n]+)", txt, re.IGNORECASE)
                    power_state = "Modo Repouso" if "620" in txt.splitlines()[0] else "Ligado"
                    return {
                        "host_type": ht.group(1).strip() if ht else "PlayStation",
                        "host_name": hn.group(1).strip() if hn else "PlayStation",
                        "host_id": hid.group(1).strip() if hid else "",
                        "system_version": sv.group(1).strip() if sv else "",
                        "power_state": power_state,
                    }
        except Exception:
            pass
    return None


def _ssdp_query(ip: str, timeout_s: float = 1.2) -> Optional[str]:
    """UPnP SSDP unicast M-SEARCH (UDP 1900) com extração automática do XML de LOCATION."""
    req = (
        f"M-SEARCH * HTTP/1.1\r\n"
        f"HOST: {ip}:1900\r\n"
        f"MAN: \"ssdp:discover\"\r\n"
        f"MX: 1\r\n"
        f"ST: ssdp:all\r\n"
        f"\r\n"
    ).encode()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout_s)
            s.sendto(req, (ip, 1900))
            data, _ = s.recvfrom(2048)
            raw_resp = data.decode("utf-8", errors="ignore")
            response = raw_resp.lower()

            # Se houver header LOCATION apuntando para um XML UPnP, busca friendlyName/modelName
            loc_m = re.search(r"location:\s*(http://[^\r\n]+)", raw_resp, re.IGNORECASE)
            xml_summary = ""
            if loc_m:
                loc_url = loc_m.group(1).strip()
                try:
                    r_xml = urllib.request.Request(loc_url, headers={"User-Agent": "BastionAudit-Intel/4.0"})
                    with urllib.request.urlopen(r_xml, timeout=0.75) as u_resp:
                        xml = u_resp.read(4096).decode("utf-8", errors="ignore")
                        fn = re.search(r"<friendlyName>([^<]+)</friendlyName>", xml, re.IGNORECASE)
                        mfg = re.search(r"<manufacturer>([^<]+)</manufacturer>", xml, re.IGNORECASE)
                        mdl = re.search(r"<modelName>([^<]+)</modelName>", xml, re.IGNORECASE)
                        parts = [x.group(1).strip() for x in (fn, mfg, mdl) if x]
                        if parts:
                            xml_summary = " | ".join(parts)
                except Exception:
                    pass

            m = re.search(r"server:\s*(.+)", response)
            srv = m.group(1).strip()[:100] if m else ""
            if xml_summary:
                return f"{xml_summary} ({srv})".strip()[:160]
            if srv:
                return srv
            m = re.search(r"\nst:\s*(.+)", response)
            if m:
                return m.group(1).strip()[:120]
    except Exception:
        pass
    return None


def _probe_port(ip: str, port: int, timeout_s: float = 0.55) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout_s)
            return s.connect_ex((ip, port)) == 0
    except Exception:
        return False


def _fetch_upnp_dial_info(ip: str, port: int = 8008, timeout_s: float = 0.9) -> Optional[Dict[str, str]]:
    """
    Extrai friendlyName, manufacturer, modelName e build via UPnP/DIAL XML (:8008/ssdp/device-desc.xml)
    e Google Cast Eureka Info (:8008/setup/eureka_info?options=detail).
    """
    info: Dict[str, str] = {"friendly_name": "", "manufacturer": "", "model_name": "", "cast_build": ""}
    url_xml = f"http://{ip}:{port}/ssdp/device-desc.xml"
    try:
        req = urllib.request.Request(url_xml, headers={"User-Agent": "BastionAudit-Intel/4.0"})
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            xml = resp.read(4096).decode("utf-8", errors="ignore")
            fn = re.search(r"<friendlyName>([^<]+)</friendlyName>", xml, re.IGNORECASE)
            mfg = re.search(r"<manufacturer>([^<]+)</manufacturer>", xml, re.IGNORECASE)
            mdl = re.search(r"<modelName>([^<]+)</modelName>", xml, re.IGNORECASE)
            if fn:
                info["friendly_name"] = fn.group(1).strip()
            if mfg:
                info["manufacturer"] = mfg.group(1).strip()
            if mdl:
                info["model_name"] = mdl.group(1).strip()
    except Exception:
        pass

    url_eureka = f"http://{ip}:{port}/setup/eureka_info?options=detail"
    try:
        req_e = urllib.request.Request(url_eureka, headers={"User-Agent": "BastionAudit-Intel/4.0"})
        with urllib.request.urlopen(req_e, timeout=timeout_s) as resp_e:
            import json as _json
            ej = _json.loads(resp_e.read(4096).decode("utf-8", errors="ignore"))
            if not info["friendly_name"] and ej.get("name"):
                info["friendly_name"] = str(ej["name"]).strip()
            if ej.get("cast_build_revision"):
                info["cast_build"] = str(ej["cast_build_revision"]).strip()
    except Exception:
        pass

    if any(info.values()):
        return info
    return None


def _grab_tls_cert_subject(ip: str, port: int = 8443, timeout_s: float = 0.9) -> Optional[str]:
    """Extrai strings legíveis do certificado X.509 (DER) sem precisar de autenticação."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=timeout_s) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                der = ssock.getpeercert(binary_form=True)
                if der:
                    strings = [
                        s.decode("ascii", errors="ignore").strip()
                        for s in re.findall(rb"[A-Za-z0-9 _.@-]{5,}", der)
                    ]
                    filtered = [s for s in strings if not s.isdigit() and len(s) <= 64]
                    return " | ".join(filtered[:6]) if filtered else None
    except Exception:
        pass
    return None


def _probe_rtsp_anonymous(ip: str, port: int = 554, timeout_s: float = 0.9) -> Dict[str, Any]:
    """Testa se a porta RTSP responde sem senha (DESCRIBE rtsp://ip:port/)."""
    try:
        with socket.create_connection((ip, port), timeout=timeout_s) as sock:
            req = (
                f"DESCRIBE rtsp://{ip}:{port}/ RTSP/1.0\r\n"
                f"CSeq: 1\r\n"
                f"User-Agent: BastionCyberHUD/2.0\r\n\r\n"
            ).encode("ascii")
            sock.sendall(req)
            resp = sock.recv(1024).decode("utf-8", errors="ignore")
            first_line = resp.splitlines()[0] if resp else ""
            if "200 OK" in first_line:
                return {"open_without_password": True, "status": "200 OK (Stream RTSP Aberto Sem Senha!)", "raw": first_line}
            elif "401" in first_line:
                return {"open_without_password": False, "status": "401 Unauthorized (Exige Senha RTSP)", "raw": first_line}
            elif "404" in first_line:
                return {"open_without_password": False, "status": "404 Stream Path (Serviço RTSP Ativo, caminho específico requerido)", "raw": first_line}
            return {"open_without_password": False, "status": first_line or "RTSP Ativo", "raw": first_line}
    except Exception as e:
        return {"open_without_password": False, "status": f"Sem resposta RTSP ({e})", "raw": ""}


def _grab_http_banner(ip: str, port: int, timeout_s: float = 2.5) -> Optional[str]:
    scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{ip}:{port}/"
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={"User-Agent": "BastionAudit-Intel/3.0"})
        with urllib.request.urlopen(
            req, timeout=timeout_s,
            context=ctx if scheme == "https" else None
        ) as resp:
            server = resp.headers.get("Server", "")
            x_powered = resp.headers.get("X-Powered-By", "")
            raw = resp.read(3000).decode("utf-8", errors="ignore")
            title_m = re.search(r"<title[^>]*>(.*?)</title>", raw, re.IGNORECASE | re.DOTALL)
            title = title_m.group(1).strip()[:80] if title_m else ""
            combined = f"{server} {x_powered} {title} {raw[:400]}".strip()
            return combined[:600] if combined else None
    except Exception:
        return None


def _classify_banner(banner: str, fp: DeviceFingerprint):
    b = banner.lower()
    for pattern, dev_type, os_fp, confidence in _HTTP_BANNER_SIGNATURES:
        if re.search(pattern, b, re.IGNORECASE):
            fp._update_if_better(dev_type, os_fp, confidence,
                                  f"L10 HTTP banner → '{pattern}'")
            return


def _classify_hostname(hostname: str, fp: DeviceFingerprint):
    h = hostname.lower()
    patterns = [
        (r"cam|camera|cctv|nvr|dvr|ipcam|axis|hik|dahua|intelbras",
         DeviceType.CCTV_CAMERA,    OSFingerprint.EMBEDDED, 60),
        (r"router|gateway|gw\b|fw\b|firewall|pfctl|mikrotik",
         DeviceType.ROUTER_GATEWAY, OSFingerprint.EMBEDDED, 55),
        (r"ap\b|access.?point|wap|wifi.*ap",
         DeviceType.ACCESS_POINT,   OSFingerprint.EMBEDDED, 55),
        (r"print|mfp|hp|epson|ricoh|canon|xerox|brother",
         DeviceType.PRINTER,        OSFingerprint.EMBEDDED, 58),
        (r"\bps4\b|\bps5\b|playstation|xbox|nintendo",
         DeviceType.GAME_CONSOLE,   OSFingerprint.ORBIS_OS, 92),
        (r"android|pixel|galaxy|moto|redmi|poco|oneplus",
         DeviceType.ANDROID_DEVICE, OSFingerprint.ANDROID,  78),
        (r"iphone|ipad|macbook|macmini|imac|apple|airtunes",
         DeviceType.IOS_DEVICE,     OSFingerprint.IOS,      82),
        (r"desktop|workstation|win|pc\b|laptop",
         DeviceType.WINDOWS_PC,     OSFingerprint.WINDOWS,  85),
        (r"server|srv|nas|storage|synology|qnap",
         DeviceType.LINUX_SERVER,   OSFingerprint.LINUX,    52),
        (r"voip|sip|phone|pbx|asterisk",
         DeviceType.VOIP_PHONE,     OSFingerprint.EMBEDDED, 58),
        (r"tv\b|smarttv|chromecast|firetv|roku|shield|uniontv",
         DeviceType.SMART_TV,       OSFingerprint.LINUX,    72),
        (r"vm\b|virt|docker|proxmox|esxi",
         DeviceType.VIRTUALIZED,    OSFingerprint.LINUX,    65),
        (r"iot|sensor|esp|arduino|tasmota|shelly",
         DeviceType.IOT_SENSOR,     OSFingerprint.EMBEDDED, 65),
    ]
    for pattern, dev_type, os_fp, confidence in patterns:
        if re.search(pattern, h):
            fp._update_if_better(dev_type, os_fp, confidence,
                                  f"Nome de rede '{hostname}' identificado como {dev_type.value}")
            return


def _classify_ssdp(ssdp_resp: str, fp: DeviceFingerprint):
    r = ssdp_resp.lower()
    sigs = [
        (r"camera|cam|ipcam|cctv",        DeviceType.CCTV_CAMERA,    OSFingerprint.EMBEDDED, 72),
        (r"nvr|dvr",                       DeviceType.NVR_DVR,        OSFingerprint.EMBEDDED, 70),
        (r"router|gateway|modem",          DeviceType.ROUTER_GATEWAY, OSFingerprint.EMBEDDED, 65),
        (r"printer|mfp|ipp",              DeviceType.PRINTER,         OSFingerprint.EMBEDDED, 68),
        (r"samsung.*upnp|tv|television|mediarenderer|dlna", DeviceType.SMART_TV, OSFingerprint.LINUX, 75),
        (r"nas|storage|diskstation|qnap",  DeviceType.LINUX_SERVER,   OSFingerprint.LINUX,    68),
        (r"phone|voip|sip",               DeviceType.VOIP_PHONE,      OSFingerprint.EMBEDDED, 65),
    ]
    for pattern, dev_type, os_fp, confidence in sigs:
        if re.search(pattern, r):
            fp._update_if_better(dev_type, os_fp, confidence,
                                  f"Resposta UPnP/SSDP: {ssdp_resp[:70]}")
            return


def _synthesis_os_mac(fp: DeviceFingerprint):
    """
    L11: Fusão final de evidências — Política ZERO ALUCINAÇÃO:
    Nunca inventa 'Servidor Linux' apenas por ter TTL=64.
    Destaca o ID real dos aparelhos com MAC Privado quando disponível.
    """
    rand = fp.is_mac_randomized
    os_fp = fp.os_fingerprint
    unknown = fp.device_type == DeviceType.UNKNOWN
    has_ip = fp.ip and fp.ip not in ("0.0.0.0", "")

    if rand and os_fp == OSFingerprint.LINUX and unknown:
        fp._update_if_better(DeviceType.ANDROID_DEVICE, OSFingerprint.ANDROID, 60,
                              "MAC Privado (Wi-Fi Privacy) + Pilha Linux/Android (TTL=64)")
    elif rand and os_fp == OSFingerprint.IOS and unknown:
        fp._update_if_better(DeviceType.IOS_DEVICE, OSFingerprint.IOS, 62,
                              "MAC Privado (Wi-Fi Privacy) + Pilha iOS/Apple")
    elif rand and os_fp == OSFingerprint.WINDOWS:
        fp._update_if_better(DeviceType.WINDOWS_PC, OSFingerprint.WINDOWS, 62,
                              "MAC Privado + Pilha Windows (TTL=128)")
    elif not rand and os_fp == OSFingerprint.CISCO_IOS and unknown:
        fp._update_if_better(DeviceType.ROUTER_GATEWAY, OSFingerprint.CISCO_IOS, 65,
                              "Equipamento de Rede / Roteador (TTL=255)")
    elif not rand and os_fp == OSFingerprint.WINDOWS and unknown:
        fp._update_if_better(DeviceType.WINDOWS_PC, OSFingerprint.WINDOWS, 55,
                              "Computador Windows (TTL=128)")
    elif not rand and os_fp == OSFingerprint.LINUX and unknown and (22 in fp.open_ports):
        fp._update_if_better(DeviceType.LINUX_SERVER, OSFingerprint.LINUX, 55,
                              "Servidor Linux (SSH ativo + TTL=64)")

    # — Inferência de Gateway pelo sufixo IP (.1 ou .254)
    if fp.device_type == DeviceType.UNKNOWN and has_ip and (fp.ip.endswith(".1") or fp.ip.endswith(".254")):
        fp._update_if_better(DeviceType.ROUTER_GATEWAY, OSFingerprint.EMBEDDED, 65,
                              f"IP de Gateway da Rede ({fp.ip})")

    # — Aparelhos móveis em economia de bateria com MAC Privado
    if fp.device_type == DeviceType.UNKNOWN and rand:
        fp._update_if_better(DeviceType.ANDROID_DEVICE, OSFingerprint.ANDROID, 50,
                              "Aparelho Móvel com MAC Privado (Wi-Fi Privacy)")


# ─────────────────────────────────────────────────────────────────────────────
# ENGINE PRINCIPAL
# ─────────────────────────────────────────────────────────────────────────────

class DeviceIntelligenceEngine:
    """
    Motor de Identificação & Handshake Ativo v4.0 (Zero Alucinação).
    """

    def __init__(
        self,
        port_probe_timeout: float = 0.45,
        http_timeout: float = 1.8,
        max_open_ports: int = 8,
        enable_netbios: bool = True,
        enable_ssdp: bool = True,
    ):
        self.port_probe_timeout = port_probe_timeout
        self.http_timeout = http_timeout
        self.max_open_ports = max_open_ports
        self.enable_netbios = enable_netbios
        self.enable_ssdp = enable_ssdp

    def analyze(self, ip: str, mac: str, vendor: str = "") -> DeviceFingerprint:
        """Executa handshakes ativos e passivos para identificar o aparelho sem alucinação."""
        import concurrent.futures
        fp = DeviceFingerprint(ip=ip, mac=mac)
        has_ip = ip and ip not in ("0.0.0.0", "IP Indisponível", "")

        # ── L0: MACs Especiais ─────────────────────────────────────────────────
        special = _check_special_mac(mac)
        if special:
            dev_type, os_fp, confidence, desc = special
            fp.device_type = dev_type
            fp.os_fingerprint = os_fp
            fp.confidence_score = confidence
            fp.evidence.append(f"Endereço de Protocolo: {desc}")
            return fp

        # ── L1: OUI Vendor Hint ────────────────────────────────────────────────
        hint = _oui_vendor_hint(vendor)
        if hint:
            dev_type, os_fp, confidence = hint
            fp._update_if_better(dev_type, os_fp, confidence,
                                  f"Fabricante do Hardware: '{vendor}' → {dev_type.value}")

        # ── L2: MAC Randomization Detection ───────────────────────────────────
        fp.is_mac_randomized = _is_mac_randomized(mac)
        if fp.is_mac_randomized:
            fp.evidence.append("MAC Privado / Aleatório ativo (Wi-Fi Privacy)")

        if not has_ip:
            _synthesis_os_mac(fp)
            return fp

        # ── L3: TTL Fingerprinting ─────────────────────────────────────────────
        with track_action(action="ttl_fp", target=ip):
            ttl, os_fp, ttl_ev = _ttl_fingerprint(ip, timeout_s=1.0)
            if ttl and ttl_ev:
                if fp.os_fingerprint == OSFingerprint.UNKNOWN:
                    fp.os_fingerprint = os_fp
                fp.evidence.append(f"Resposta Ping ICMP: {ttl_ev}")
                if fp.confidence_score < 15:
                    fp.confidence_score = 15

        # ── L4: PTR Hostname Resolution ────────────────────────────────────────
        with track_action(action="ptr", target=ip):
            hostname = _resolve_hostname(ip, timeout_s=0.8)
            if hostname:
                fp.hostname = hostname
                fp.evidence.append(f"Nome DNS (PTR): {hostname}")

        # ── L5: Hostname Pattern ────────────────────────────────────────────────
        if fp.hostname:
            _classify_hostname(fp.hostname, fp)

        # ── L6: NetBIOS Name Query (UDP 137) ───────────────────────────────────
        if self.enable_netbios:
            with track_action(action="netbios", target=ip):
                nbname = _netbios_query(ip, timeout_s=0.6)
                if nbname:
                    if not fp.hostname:
                        fp.hostname = nbname
                    fp._update_if_better(DeviceType.WINDOWS_PC, OSFingerprint.WINDOWS, 75,
                                          f"Handshake NetBIOS: '{nbname}' (Windows)")

        # ── L7: Handshake mDNS / Quick Share / Continuity / Spotify (UDP 5353) ─
        with track_action(action="mdns", target=ip):
            mdns_info = _mdns_query(ip, timeout_s=0.85)
            mdns_host = mdns_info.get("hostname")
            mdns_svcs = mdns_info.get("services") or []
            mdns_model = mdns_info.get("model_hint")
            mdns_fn = mdns_info.get("friendly_name")
            sp_info = mdns_info.get("spotify_info")

            if mdns_host and not fp.hostname:
                fp.hostname = mdns_host
                fp.evidence.append(f"Handshake mDNS ID: '{mdns_host}'")
                _classify_hostname(mdns_host, fp)

            if mdns_fn:
                if not fp.hostname:
                    fp.hostname = mdns_fn
                fp.evidence.append(f"Nome Amigável mDNS: '{mdns_fn}'")

            if mdns_model:
                fp.hardware_model = mdns_model
                fp.evidence.append(f"Modelo reportado via mDNS: '{mdns_model}'")

            if sp_info:
                sp_name = sp_info.get("remote_name") or mdns_host or ""
                sp_model = sp_info.get("model") or ""
                sp_dtype = (sp_info.get("device_type") or "").upper()
                fp.evidence.append(f"Handshake Spotify ZeroConf: Nome='{sp_name}' Modelo='{sp_model}' Tipo='{sp_dtype}'")
                if sp_dtype == "GAMECONSOLE" or "ps4" in sp_model.lower() or "ps5" in sp_model.lower():
                    fp.hostname = sp_name or fp.hostname
                    fp.hardware_model = f"Sony PlayStation 4 ({sp_name})" if "ps4" in sp_model.lower() else f"Console ({sp_name})"
                    fp._update_if_better(DeviceType.GAME_CONSOLE, OSFingerprint.ORBIS_OS, 96,
                                          f"Handshake Spotify Connect → {fp.hardware_model}")

            if "_nearbypresence" in mdns_svcs or "_fc9f5ed42c8a" in mdns_svcs:
                fp._update_if_better(
                    DeviceType.ANDROID_DEVICE, OSFingerprint.ANDROID, 90,
                    f"Handshake Google Quick Share ativo ({mdns_fn or mdns_host or ip})"
                )
                if mdns_fn and not fp.hardware_model:
                    fp.hardware_model = mdns_fn
            if "_companion-link" in mdns_svcs:
                fp._update_if_better(
                    DeviceType.IOS_DEVICE, OSFingerprint.IOS, 92,
                    f"Handshake Apple Continuity ativo ({mdns_fn or mdns_host or ip})"
                )
                if not fp.hardware_model:
                    fp.hardware_model = mdns_model or f"Apple iPhone / iPad ({mdns_host or 'iOS'})"
            if "_googlecast" in mdns_svcs or "_androidtvremote2" in mdns_svcs:
                fp._update_if_better(
                    DeviceType.SMART_TV, OSFingerprint.LINUX, 90,
                    f"Handshake Google Cast / Android TV ({mdns_fn or mdns_host or ip})"
                )

        # ── L7b: Handshake Sony PlayStation DDPlay (UDP 987) ───────────────────
        if (
            fp.device_type == DeviceType.GAME_CONSOLE
            or "playstation" in (vendor or "").lower()
            or "_spotify-connect" in (mdns_info.get("services") or [])
            or (fp.hostname and ("ps4" in fp.hostname.lower() or "ps5" in fp.hostname.lower()))
        ):
            ps_info = _fetch_playstation_info(ip, timeout_s=0.65)
            if ps_info:
                ht = ps_info.get("host_type", "PS4")
                hn = ps_info.get("host_name", "PS4")
                hid = ps_info.get("host_id", "")
                pstate = ps_info.get("power_state", "Ativo")
                fp.hostname = hn
                fp.hardware_model = f"Sony PlayStation 4 ({hn} · {pstate})" if "PS4" in ht.upper() else f"Sony {ht} ({hn} · {pstate})"
                fp._update_if_better(
                    DeviceType.GAME_CONSOLE, OSFingerprint.ORBIS_OS, 98,
                    f"Handshake PlayStation DDPlay (UDP 987): {ht} '{hn}' [ID: {hid}] ({pstate})"
                )

        # ── L8: UPnP SSDP Discovery (UDP 1900) ────────────────────────────────
        if self.enable_ssdp:
            with track_action(action="ssdp", target=ip):
                ssdp_resp = _ssdp_query(ip, timeout_s=0.7)
                if ssdp_resp:
                    _classify_ssdp(ssdp_resp, fp)
                    if not fp.hardware_model and "|" in ssdp_resp:
                        fp.hardware_model = ssdp_resp.split("(")[0].strip()

        # ── L9: Port Probing Concorrente (Alta Velocidade) ────────────────────
        with track_action(action="port_scan", target=ip):
            ports_to_check = list(_PORT_DEVICE_MAP.keys())
            with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
                fut_map = {
                    pool.submit(_probe_port, ip, p, self.port_probe_timeout): p
                    for p in ports_to_check
                }
                for fut in concurrent.futures.as_completed(fut_map):
                    port = fut_map[fut]
                    try:
                        if fut.result():
                            fp.open_ports.append(port)
                    except Exception:
                        pass
            fp.open_ports.sort()
            for port in fp.open_ports[:self.max_open_ports]:
                dev_type, os_fp, evidence_msg, weight = _PORT_DEVICE_MAP[port]
                fp._update_if_better(dev_type, os_fp, weight,
                                      f"Porta TCP/{port} aberta → {evidence_msg}")

            # ── L9a: Handshake Oficial Samsung SmartTV Tizen (:8001 / :9197) ───
            if any(p in fp.open_ports for p in (8001, 8002, 9197)):
                sam_tv = _fetch_samsung_tv_info(ip, timeout_s=0.85)
                if sam_tv:
                    fn = sam_tv.get("friendly_name", "")
                    mcode = sam_tv.get("model_code", "")
                    res = sam_tv.get("resolution", "")
                    sn = sam_tv.get("serial_number", "")
                    if fn:
                        fp.hostname = fn
                    if mcode:
                        fp.hardware_model = f"Samsung Smart TV ({mcode})" + (f" · {res}" if res else "")
                    else:
                        fp.hardware_model = fn or "Samsung Smart TV (Tizen)"
                    fp._update_if_better(
                        DeviceType.SMART_TV, OSFingerprint.TIZEN, 98,
                        f"Handshake Samsung SmartTV API (:8001): Nome='{fn}' Modelo='{mcode}' Serial='{sn}'"
                    )

            # ── L9b: Handshake UPnP/DIAL (:8008) & Certificado TLS (:8443/:443) ─
            cast_friendly = ""
            cast_mfg_mdl = ""
            if 8008 in fp.open_ports:
                dial_info = _fetch_upnp_dial_info(ip, port=8008, timeout_s=0.8)
                if dial_info:
                    cast_friendly = dial_info.get("friendly_name", "")
                    mfg = dial_info.get("manufacturer", "")
                    mdl = dial_info.get("model_name", "")
                    cast_mfg_mdl = f"{mfg} {mdl}".strip()
                    if cast_friendly:
                        fp.hostname = cast_friendly
                    if cast_mfg_mdl:
                        fp.hardware_model = f"{cast_mfg_mdl} (Google Cast)"
                    fp._update_if_better(
                        DeviceType.SMART_TV, OSFingerprint.LINUX, 95,
                        f"Handshake Google Cast (:8008): '{cast_friendly}' [{cast_mfg_mdl}]"
                    )
            for tls_p in (8443, 443):
                if tls_p in fp.open_ports:
                    cert_subj = _grab_tls_cert_subject(ip, port=tls_p, timeout_s=0.8)
                    if cert_subj:
                        fp.evidence.append(f"Certificado TLS (:{tls_p}): {cert_subj[:100]}")
                        cs_low = cert_subj.lower()
                        if "tcl tv" in cs_low:
                            m_tcl = re.search(r"(TCL TV [A-Za-z0-9 _-]+?)(?:\s+Cast|\s+ICA0|\|)", cert_subj, re.IGNORECASE)
                            tcl_chip = m_tcl.group(1).strip() if m_tcl else "TCL Smart TV"
                            fp.hardware_model = f"{tcl_chip} (Android TV)"
                            fp._update_if_better(
                                DeviceType.SMART_TV, OSFingerprint.LINUX, 97,
                                f"Certificado de Hardware TLS (:{tls_p}) → '{tcl_chip}'"
                            )
                        elif any(k in cs_low for k in ("cast", "widevine", "chromecast", "bravia")):
                            fp._update_if_better(
                                DeviceType.SMART_TV, OSFingerprint.LINUX, 92,
                                f"Certificado TLS (:{tls_p}) → Smart TV / Google Cast"
                            )
                        elif any(k in cs_low for k in ("hikvision", "dahua", "intelbras", "ipcamera", "axis")):
                            fp._update_if_better(
                                DeviceType.CCTV_CAMERA, OSFingerprint.EMBEDDED, 90,
                                f"Certificado TLS (:{tls_p}) → Câmera IP / CFTV"
                            )

        # ── L10: HTTP Banner Grabbing ──────────────────────────────────────────
        http_candidates = [p for p in fp.open_ports if p in _HTTP_PROBE_PORTS]
        if not http_candidates:
            for p in (80, 8080, 443):
                if _probe_port(ip, p, timeout_s=0.35):
                    if p not in fp.open_ports:
                        fp.open_ports.append(p)
                    http_candidates.append(p)
        for port in http_candidates[:3]:
            with track_action(action="http_banner", target=f"{ip}:{port}"):
                banner = _grab_http_banner(ip, port, timeout_s=self.http_timeout)
                if banner:
                    fp.http_banner = banner[:250]
                    _classify_banner(banner, fp)
                    if fp.confidence_score >= 70:
                        break

        # ── L11: Síntese Final de Evidências (Zero Alucinação) ────────────────
        _synthesis_os_mac(fp)

        # ── L12: Tradução de Modelo Comercial & Destaque do ID Único ──────────
        if not fp.hardware_model or fp.hardware_model in ("Smart TV", "UnionTV", "Smartphone Android"):
            combined_clues = " | ".join(
                filter(None, [
                    fp.hardware_model or "",
                    fp.hostname or "",
                    fp.http_banner or "",
                    " ".join(mdns_info.get("raw_strings", []) if "mdns_info" in locals() else []),
                ])
            )
            exact_match = translate_hardware_model(combined_clues)
            if exact_match:
                exact_model, exact_type, exact_os = exact_match
                fp.hardware_model = exact_model
                fp._update_if_better(
                    exact_type, exact_os, 96,
                    f"Modelo Exato Identificado → '{exact_model}'"
                )

        if not fp.hardware_model:
            if fp.device_type == DeviceType.WINDOWS_PC:
                fp.hardware_model = f"Computador Windows ({fp.hostname})" if fp.hostname else (vendor if vendor != "Fabricante desconhecido" else "Computador Windows")
            elif fp.device_type == DeviceType.GAME_CONSOLE:
                fp.hardware_model = f"Sony PlayStation ({fp.hostname})" if fp.hostname else "Console PlayStation"
            elif fp.device_type == DeviceType.SMART_TV:
                fp.hardware_model = fp.hostname or (vendor if vendor != "Fabricante desconhecido" else "Smart TV")
            elif fp.device_type == DeviceType.VIRTUALIZED:
                fp.hardware_model = vendor if vendor != "Fabricante desconhecido" else "Máquina Virtual"
            elif fp.device_type in (DeviceType.ROUTER_GATEWAY, DeviceType.ACCESS_POINT):
                fp.hardware_model = vendor if vendor != "Fabricante desconhecido" else "Roteador / Gateway da Rede"
            elif fp.device_type == DeviceType.ANDROID_DEVICE:
                if fp.hostname:
                    fp.hardware_model = f"Celular Android (ID: {fp.hostname})"
                elif vendor and "MAC Privado" not in vendor and vendor != "Fabricante desconhecido":
                    fp.hardware_model = f"Celular {vendor}"
                else:
                    fp.hardware_model = "Celular / Aparelho Wi-Fi (MAC Privado)"

        log.info(
            "Intel[%s|%s] → %s | model='%s' (%s) score=%d%% ev=%d",
            ip, mac, fp.device_type.value, fp.hardware_model or "N/A",
            fp.os_fingerprint.value, fp.confidence_score, len(fp.evidence),
        )
        return fp

    def perform_identity_handshake(self, ip: str, mac: str, vendor: str = "") -> Dict[str, Any]:
        """
        Executa um Handshake de Identidade Ativo sob demanda (botão '📡 Identificar'):
        1. Envia rajada de Wake-up (UDP + 2x ICMP Ping) para acordar o rádio Wi-Fi de celulares em repouso.
        2. Mede o tempo de resposta (latência em ms) e TTL da pilha de rede.
        3. Executa todos os handshakes de protocolo (mDNS/QuickShare/Continuity, Samsung Tizen,
           Google Cast Eureka, PlayStation DDPlay, TLS X.509, UPnP SSDP e NetBIOS).
        """
        import subprocess, os as _os
        latency_ms: Optional[float] = None
        is_reachable = False

        if ip and ip not in ("0.0.0.0", ""):
            # 1. Rajada UDP curta para tirar o rádio Wi-Fi do modo de economia DTIM
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    for p in (5353, 1900, 137, 33434):
                        try:
                            s.sendto(b"\x00", (ip, p))
                        except Exception:
                            pass
            except Exception:
                pass

            # 2. Ping rápido para medir latência real e acordar a pilha IP
            try:
                cmd = ["ping", "-n", "1", "-w", "600", ip] if _os.name == "nt" else ["ping", "-c", "1", "-W", "1", ip]
                res = subprocess.run(
                    cmd, capture_output=True, text=True, errors="ignore", timeout=1.5,
                    creationflags=0x08000000 if _os.name == "nt" else 0,
                )
                out_low = res.stdout.lower()
                if "ttl=" in out_low or "ttl " in out_low:
                    is_reachable = True
                    m_time = re.findall(r"(?:tempo|time)[=<]\s*(\d+)\s*ms", out_low)
                    if m_time:
                        latency_ms = float(m_time[-1])
                    else:
                        latency_ms = 1.0
            except Exception:
                pass

        fp = self.analyze(ip=ip, mac=mac, vendor=vendor)
        if latency_ms is not None:
            fp.evidence.insert(0, f"Handshake ICMP Respondido: Latência de {int(latency_ms)}ms (Aparelho Online)")

        return {
            "reachable": is_reachable or len(fp.open_ports) > 0 or bool(fp.hostname),
            "latency_ms": latency_ms,
            "fingerprint": fp.to_dict(),
        }

    def deep_scan_device(self, ip: str, mac: str, vendor: str = "") -> Dict[str, Any]:
        """
        Executa uma auditoria tática profunda (29 portas críticas + análise de risco CVSS/superfície)
        em um único ativo sob demanda.
        """
        import concurrent.futures
        fp = self.analyze(ip=ip, mac=mac, vendor=vendor)

        extended_ports = [
            21, 22, 23, 53, 80, 81, 135, 139, 443, 445, 502, 554, 631,
            1883, 1935, 3306, 3389, 5000, 5060, 5432, 5900, 5985,
            8000, 8080, 8081, 8443, 8554, 8888, 9000, 9100, 34567, 37777
        ]
        open_set = set(fp.open_ports)

        if ip and ip not in ("0.0.0.0", ""):
            remaining = [p for p in extended_ports if p not in open_set]
            with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
                fut_map = {pool.submit(_probe_port, ip, p, 0.5): p for p in remaining}
                for fut in concurrent.futures.as_completed(fut_map):
                    p = fut_map[fut]
                    try:
                        if fut.result():
                            open_set.add(p)
                    except Exception:
                        pass

        all_open = sorted(open_set)
        fp.open_ports = all_open

        # Avaliação de Risco e Superfície de Ataque
        risk_score = 10
        risk_findings: List[Dict[str, str]] = []

        port_risk_catalog = {
            21:    ("HIGH",     "FTP (21) Aberto", "Tráfego e credenciais em texto claro."),
            22:    ("LOW",      "SSH (22) Ativo", "Acesso remoto administrativo criptografado."),
            23:    ("CRITICAL", "Telnet (23) Exposto", "Protocolo legado sem criptografia! Altíssimo risco de interceptação."),
            53:    ("LOW",      "DNS (53) Ativo", "Serviço de resolução de nomes (comum em Gateways)."),
            80:    ("MEDIUM",   "HTTP (80) Sem TLS", "Painel web sem criptografia HTTPS na rede local."),
            81:    ("MEDIUM",   "HTTP Alt (81)", "Interface web secundária (comum em câmeras/DVRs)."),
            135:   ("MEDIUM",   "MS-RPC (135)", "Endpoint Mapper do Windows ativo."),
            139:   ("HIGH",     "NetBIOS Session (139)", "Compartilhamento legado Windows/Samba."),
            443:   ("LOW",      "HTTPS (443) Ativo", "Interface web protegida por TLS/SSL."),
            445:   ("HIGH",     "SMB (445) Exposto", "Atenção: vetor frequente de movimentação lateral e ransomware."),
            502:   ("CRITICAL", "Modbus TCP (502)", "Protocolo industrial sem autenticação nativa!"),
            554:   ("MEDIUM",   "RTSP Video Stream (554)", "Fluxo de vídeo de câmera IP / NVR disponível."),
            1883:  ("HIGH",     "MQTT (1883) Sem TLS", "Broker IoT sem criptografia de transporte."),
            3306:  ("HIGH",     "MySQL/MariaDB (3306)", "Banco de dados exposto diretamente na rede."),
            3389:  ("HIGH",     "RDP (3389) Área de Trabalho Remota", "Alvo comum de força bruta e exploração remota."),
            5900:  ("HIGH",     "VNC (5900) Acesso Remoto Visual", "Controle remoto de tela exposto na LAN."),
            8000:  ("MEDIUM",   "Porta de Mídia / CFTV SDK (8000)", "Comum em câmeras Hikvision/ONVIF ou servidores locais."),
            8080:  ("MEDIUM",   "HTTP Proxy / Painel Web (8080)", "Interface administrativa alternativa em texto claro."),
            8443:  ("LOW",      "HTTPS Gerência (8443)", "Painel administrativo criptografado (NVR/Gateway)."),
            8554:  ("MEDIUM",   "RTSP Alternativo (8554)", "Stream de câmera IP em porta alternativa."),
            9000:  ("MEDIUM",   "Protocolo NVR / DVR (9000)", "Canal de controle de gravador de vídeo CFTV."),
            34567: ("HIGH",     "DVR Xiongmai / NetSurveillance (34567)", "Protocolo proprietário CFTV — verifique senha padrão."),
            37777: ("MEDIUM",   "Dahua / Intelbras SDK (37777)", "Canal de vídeo e controle CFTV Intelbras/Dahua."),
        }

        for p in all_open:
            if p in port_risk_catalog:
                sev, title, desc = port_risk_catalog[p]
                risk_findings.append({"port": str(p), "severity": sev, "title": title, "description": desc})
                if sev == "CRITICAL":
                    risk_score += 35
                elif sev == "HIGH":
                    risk_score += 22
                elif sev == "MEDIUM":
                    risk_score += 10
                else:
                    risk_score += 3
            else:
                risk_findings.append({
                    "port": str(p),
                    "severity": "INFO",
                    "title": f"Porta TCP/{p} Aberta",
                    "description": "Serviço de rede ativo respondendo a conexões TCP.",
                })
                risk_score += 5

        risk_score = min(100, risk_score)
        if risk_score >= 70:
            risk_level = "CRITICAL"
        elif risk_score >= 45:
            risk_level = "HIGH"
        elif risk_score >= 25:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        is_camera_capable = (
            fp.device_type in (DeviceType.CCTV_CAMERA, DeviceType.NVR_DVR)
            or any(p in all_open for p in (554, 8554, 8000, 9000, 34567, 37777))
        )

        return {
            "fingerprint": fp.to_dict(),
            "open_ports": all_open,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "risk_findings": risk_findings,
            "is_camera_capable": is_camera_capable,
        }

    def probe_camera_capabilities(self, ip: str, username: str = "admin", password: str = "") -> Dict[str, Any]:
        """
        Descobre portas de CFTV, interfaces web, certificado TLS/UPnP e audita se é possível
        conectar às portas abertas SEM SENHA (Acesso Anônimo vs Bloqueado por Autenticação).
        """
        import concurrent.futures
        import base64

        cam_ports = [80, 81, 443, 554, 1935, 5000, 8000, 8008, 8080, 8081, 8443, 8554, 8899, 9000, 34567, 37777]
        open_ports: List[int] = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
            fut_map = {pool.submit(_probe_port, ip, p, 0.45): p for p in cam_ports}
            for fut in concurrent.futures.as_completed(fut_map):
                p = fut_map[fut]
                try:
                    if fut.result():
                        open_ports.append(p)
                except Exception:
                    pass
        open_ports.sort()

        # 1. Identificação Real do Hardware por trás das portas (UPnP DIAL :8008 / TLS Cert :8443/:443)
        hardware_identity: Optional[str] = None
        is_smart_tv_cast = False
        if 8008 in open_ports:
            dial = _fetch_upnp_dial_info(ip, port=8008, timeout_s=0.8)
            if dial:
                fn = dial.get("friendly_name", "")
                mfg = dial.get("manufacturer", "")
                mdl = dial.get("model_name", "")
                hardware_identity = f"Smart TV / Cast: {fn} ({mfg} {mdl})".strip()
                is_smart_tv_cast = True

        tls_cert_info: Optional[str] = None
        for tls_p in (8443, 443):
            if tls_p in open_ports:
                tls_cert_info = _grab_tls_cert_subject(ip, port=tls_p, timeout_s=0.8)
                if tls_cert_info and not hardware_identity:
                    hardware_identity = f"Certificado TLS (:{tls_p}): {tls_cert_info}"
                    if any(k in tls_cert_info.lower() for k in ("tcl tv", "cast", "widevine", "chromecast")):
                        is_smart_tv_cast = True

        # Interfaces Web HTTP/HTTPS disponíveis
        web_interfaces: List[Dict[str, Any]] = []
        for p in open_ports:
            if p in (80, 81, 8080, 8081, 8000, 8008, 5000):
                web_interfaces.append({"protocol": "http", "port": p, "url": f"http://{ip}:{p}" if p != 80 else f"http://{ip}"})
            elif p in (443, 8443):
                web_interfaces.append({"protocol": "https", "port": p, "url": f"https://{ip}:{p}" if p != 443 else f"https://{ip}"})
            elif p == 9000:
                web_interfaces.append({"protocol": "http", "port": p, "url": f"http://{ip}:9000"})

        # 2. Auditoria de Conexão Sem Senha nas Portas Abertas (Anonymous Port Audit)
        anonymous_port_audit: List[Dict[str, Any]] = []
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        for p in open_ports:
            if p in (554, 8554):
                rtsp_res = _probe_rtsp_anonymous(ip, port=p, timeout_s=0.85)
                anonymous_port_audit.append({
                    "port": p,
                    "service": "RTSP Video Stream",
                    "open_without_password": rtsp_res["open_without_password"],
                    "status": rtsp_res["status"],
                })
            elif p == 8008:
                anonymous_port_audit.append({
                    "port": p,
                    "service": "Google Cast / UPnP DIAL",
                    "open_without_password": True,
                    "status": f"Aberto sem senha para metadados Smart TV ({hardware_identity or 'Cast'}) — Não é câmera de vídeo",
                })
            elif p == 8443 and is_smart_tv_cast:
                anonymous_port_audit.append({
                    "port": p,
                    "service": "Google Cast TLS Control",
                    "open_without_password": False,
                    "status": f"Canal criptografado de Smart TV ({tls_cert_info or 'Google Cast'}) — Não possui vídeo CFTV",
                })
            elif p in (80, 81, 443, 8000, 8080, 8081, 8443, 8899, 9000):
                scheme = "https" if p in (443, 8443) else "http"
                test_url = f"{scheme}://{ip}:{p}/"
                try:
                    req = urllib.request.Request(test_url, headers={"User-Agent": "BastionCyberHUD/2.0"})
                    with urllib.request.urlopen(req, timeout=0.8, context=ctx if scheme == "https" else None) as resp:
                        body_sample = resp.read(1200).decode("utf-8", errors="ignore").lower()
                        if "login" in body_sample or "password" in body_sample or "tpencrypt" in body_sample:
                            anonymous_port_audit.append({
                                "port": p,
                                "service": f"{scheme.upper()} Painel Web",
                                "open_without_password": False,
                                "status": "HTTP 200 (Página de Login — Exige Usuário/Senha no Painel)",
                            })
                        else:
                            anonymous_port_audit.append({
                                "port": p,
                                "service": f"{scheme.upper()} Web / Stream",
                                "open_without_password": True,
                                "status": "HTTP 200 OK (Responde sem senha na raiz!)",
                            })
                except urllib.error.HTTPError as he:
                    if he.code in (401, 403):
                        anonymous_port_audit.append({
                            "port": p,
                            "service": f"{scheme.upper()} Autenticação CFTV",
                            "open_without_password": False,
                            "status": f"HTTP {he.code} Bloqueado por Senha no Firmware (Exige Credencial Basic/Digest)",
                        })
                    else:
                        anonymous_port_audit.append({
                            "port": p,
                            "service": f"{scheme.upper()} Serviço",
                            "open_without_password": False,
                            "status": f"Porta aberta (HTTP {he.code} — Sem stream público na raiz)",
                        })
                except Exception:
                    anonymous_port_audit.append({
                        "port": p,
                        "service": "Protocolo Proprietário Binário",
                        "open_without_password": False,
                        "status": "Porta TCP aberta (Protocolo binário SDK — exige handshake autenticado)",
                    })
            else:
                anonymous_port_audit.append({
                    "port": p,
                    "service": "SDK CFTV Proprietário (Dahua/XM)",
                    "open_without_password": False,
                    "status": "Porta TCP aberta (Exige autenticação criptografada no protocolo SDK)",
                })

        # 3. Testa endpoints comuns de Snapshot JPEG / MJPEG (Primeiro SEM SENHA, depois COM SENHA se fornecida)
        snapshot_paths = [
            "/cgi-bin/snapshot.cgi",
            "/Streaming/Channels/1/picture",
            "/Streaming/channels/101/picture",
            "/onvifsnapshot/media_service/snapshot",
            "/snapshot.jpg",
            "/image/jpeg.cgi",
            "/axis-cgi/jpg/image.cgi",
            "/capture",
            "/shot.jpg",
            "/mjpg/video.mjpg",
            "/video",
            "/videostream.cgi",
        ]

        working_snapshots: List[Dict[str, Any]] = []
        auth_header = None
        if username and password:
            creds = f"{username}:{password}".encode("utf-8")
            auth_header = "Basic " + base64.b64encode(creds).decode("ascii")

        http_ports = [w["port"] for w in web_interfaces if w["port"] != 8008] or [80, 8080, 8443]
        for port in http_ports[:3]:
            scheme = "https" if port in (443, 8443) else "http"
            for path in snapshot_paths:
                url = f"{scheme}://{ip}:{port}{path}"
                try:
                    # Tenta sem senha primeiro se password estiver vazio, ou com auth_header se informado
                    req = urllib.request.Request(url, headers={"User-Agent": "BastionCyberHUD/2.0"})
                    if auth_header:
                        req.add_header("Authorization", auth_header)
                    with urllib.request.urlopen(req, timeout=0.65, context=ctx if scheme == "https" else None) as resp:
                        ctype = (resp.headers.get("Content-Type") or "").lower()
                        if resp.status == 200 and ("image" in ctype or "multipart" in ctype or "octet-stream" in ctype):
                            working_snapshots.append({
                                "url": url,
                                "content_type": ctype,
                                "path": path,
                                "port": str(port),
                                "passwordless": not bool(password),
                            })
                            break
                except urllib.error.HTTPError as he:
                    if he.code == 401:
                        working_snapshots.append({
                            "url": url,
                            "content_type": "auth_required",
                            "path": path,
                            "port": str(port),
                            "passwordless": False,
                        })
                        break
                except Exception:
                    pass

        # Gera perfis RTSP prontos para CFTV (incluindo opção Sem Senha e Com Senha)
        auth_prefix = f"{username}:{password}@" if password else ""
        rtsp_port = 554 if 554 in open_ports else (8554 if 8554 in open_ports else 554)
        rtsp_profiles = [
            {
                "brand": "Acesso Direto Sem Senha (ONVIF / Stream Público)",
                "url": f"rtsp://{ip}:{rtsp_port}/onvif1",
            },
            {
                "brand": "Intelbras / Dahua (Stream Principal)",
                "url": f"rtsp://{auth_prefix}{ip}:{rtsp_port}/cam/realmonitor?channel=1&subtype=0",
            },
            {
                "brand": "Intelbras / Dahua (Stream Extra Leve)",
                "url": f"rtsp://{auth_prefix}{ip}:{rtsp_port}/cam/realmonitor?channel=1&subtype=1",
            },
            {
                "brand": "Hikvision / HiLook (Canal 1 Main)",
                "url": f"rtsp://{auth_prefix}{ip}:{rtsp_port}/Streaming/Channels/101",
            },
            {
                "brand": "TP-Link Tapo / IPCam",
                "url": f"rtsp://{auth_prefix}{ip}:{rtsp_port}/stream1",
            },
        ]

        return {
            "ip": ip,
            "open_camera_ports": open_ports,
            "hardware_identity": hardware_identity,
            "is_smart_tv_cast": is_smart_tv_cast,
            "tls_cert_info": tls_cert_info,
            "anonymous_port_audit": anonymous_port_audit,
            "web_interfaces": web_interfaces,
            "working_snapshots": working_snapshots,
            "rtsp_profiles": rtsp_profiles,
            "has_web_ui": len(web_interfaces) > 0,
            "has_rtsp": 554 in open_ports or 8554 in open_ports,
            "has_nvr_port": 9000 in open_ports or 37777 in open_ports or 8000 in open_ports,
        }
