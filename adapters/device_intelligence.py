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
    (r"hikvision|dahua|intelbras|axis|vivotek|hanwha|bosch.*security|pelco|avigilon|reolink|uniview|tiandy",
     DeviceType.CCTV_CAMERA, OSFingerprint.EMBEDDED, 75),
    (r"cisco|mikrotik|ubiquiti|unifi|tp.?link|tplink|netgear|d.?link|zyxel|juniper|aruba|fortinet|palo alto|watchguard",
     DeviceType.ROUTER_GATEWAY, OSFingerprint.EMBEDDED, 70),
    (r"hewlett.packard|hp inc|epson|canon|ricoh|xerox|lexmark|konica|kyocera|brother|samsung.*print",
     DeviceType.PRINTER, OSFingerprint.EMBEDDED, 75),
    (r"samsung electronics|xiaomi|huawei|motorola|lg electronics|oneplus|oppo|vivo|zte|realme|nothing technology",
     DeviceType.ANDROID_DEVICE, OSFingerprint.ANDROID, 70),
    (r"apple",
     DeviceType.IOS_DEVICE, OSFingerprint.IOS, 75),
    (r"samsung.*tv|lg.*display|sony.*visual|roku|amazon.*fire|nvidia.*shield|google.*cast|tcl|hisense|vizio",
     DeviceType.SMART_TV, OSFingerprint.LINUX, 65),
    (r"grandstream|yealink|polycom|cisco.*phone|avaya|snom|fanvil",
     DeviceType.VOIP_PHONE, OSFingerprint.EMBEDDED, 75),
    (r"intel.*corp|supermicro|dell.*inc|hewlett.*packard.*enterprise|synology|qnap|buffalo",
     DeviceType.LINUX_SERVER, OSFingerprint.LINUX, 55),
    # Virtualização — OUIs bem conhecidos
    (r"vmware|virtualbox|virtual box|cadmus.*computer|virt|parallels|xen source",
     DeviceType.VIRTUALIZED, OSFingerprint.LINUX, 85),
    (r"qemu|kvm|proxmox",
     DeviceType.VIRTUALIZED, OSFingerprint.LINUX, 85),
    (r"espressif|tuya|shelly|sonoff|tasmota|particle|arduino|raspberry",
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
    8888: (DeviceType.SMART_TV,       OSFingerprint.LINUX,     "Smart TV control (8888)",             30),
    1883: (DeviceType.IOT_SENSOR,     OSFingerprint.EMBEDDED,  "MQTT (1883) — IoT",                   55),
    8883: (DeviceType.IOT_SENSOR,     OSFingerprint.EMBEDDED,  "MQTT TLS (8883) — IoT",               50),
    502:  (DeviceType.IOT_SENSOR,     OSFingerprint.EMBEDDED,  "Modbus (502) — ICS/SCADA",            60),
    8443: (DeviceType.ROUTER_GATEWAY, OSFingerprint.EMBEDDED,  "HTTPS mgmt (8443) — gateway/AP",      35),
}

_HTTP_PROBE_PORTS = [80, 8080, 443, 8443, 8000, 81, 4200, 8888, 8081]

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
                capture_output=True, text=True, timeout=timeout_s + 1,
                creationflags=0x08000000
            )
        else:
            result = subprocess.run(
                ["ping", "-c", "1", "-W", str(int(max(1, timeout_s))), ip],
                capture_output=True, text=True, timeout=timeout_s + 2
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


def _resolve_hostname(ip: str, timeout_s: float = 1.0) -> Optional[str]:
    try:
        socket.setdefaulttimeout(timeout_s)
        name, _, _ = socket.gethostbyaddr(ip)
        return name if name and name != ip else None
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


def _ssdp_query(ip: str, timeout_s: float = 2.0) -> Optional[str]:
    """UPnP SSDP unicast M-SEARCH (UDP 1900)."""
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
            response = data.decode("utf-8", errors="ignore").lower()
            m = re.search(r"server:\s*(.+)", response)
            if m:
                return m.group(1).strip()[:120]
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
        (r"android|pixel|galaxy|moto|redmi|poco|oneplus",
         DeviceType.ANDROID_DEVICE, OSFingerprint.ANDROID,  70),
        (r"iphone|ipad|macbook|macmini|imac|apple|airtunes",
         DeviceType.IOS_DEVICE,     OSFingerprint.IOS,      72),
        (r"desktop|workstation|win|pc\b|laptop",
         DeviceType.WINDOWS_PC,     OSFingerprint.WINDOWS,  58),
        (r"server|srv|nas|storage|synology|qnap",
         DeviceType.LINUX_SERVER,   OSFingerprint.LINUX,    52),
        (r"voip|sip|phone|pbx|asterisk",
         DeviceType.VOIP_PHONE,     OSFingerprint.EMBEDDED, 58),
        (r"tv\b|smarttv|chromecast|firetv|roku|shield",
         DeviceType.SMART_TV,       OSFingerprint.LINUX,    58),
        (r"vm\b|virt|docker|proxmox|esxi",
         DeviceType.VIRTUALIZED,    OSFingerprint.LINUX,    65),
        (r"iot|sensor|esp|arduino|tasmota|shelly",
         DeviceType.IOT_SENSOR,     OSFingerprint.EMBEDDED, 65),
    ]
    for pattern, dev_type, os_fp, confidence in patterns:
        if re.search(pattern, h):
            fp._update_if_better(dev_type, os_fp, confidence,
                                  f"L5 Hostname '{hostname}' → '{pattern}'")
            return


def _classify_ssdp(ssdp_resp: str, fp: DeviceFingerprint):
    r = ssdp_resp.lower()
    sigs = [
        (r"camera|cam|ipcam|cctv",        DeviceType.CCTV_CAMERA,    OSFingerprint.EMBEDDED, 72),
        (r"nvr|dvr",                       DeviceType.NVR_DVR,        OSFingerprint.EMBEDDED, 70),
        (r"router|gateway|modem",          DeviceType.ROUTER_GATEWAY, OSFingerprint.EMBEDDED, 65),
        (r"printer|mfp|ipp",              DeviceType.PRINTER,         OSFingerprint.EMBEDDED, 68),
        (r"tv|television|mediarenderer|dlna",DeviceType.SMART_TV,     OSFingerprint.LINUX,    65),
        (r"nas|storage|diskstation|qnap",  DeviceType.LINUX_SERVER,   OSFingerprint.LINUX,    68),
        (r"phone|voip|sip",               DeviceType.VOIP_PHONE,      OSFingerprint.EMBEDDED, 65),
    ]
    for pattern, dev_type, os_fp, confidence in sigs:
        if re.search(pattern, r):
            fp._update_if_better(dev_type, os_fp, confidence,
                                  f"L8 SSDP/UPnP → '{pattern}': {ssdp_resp[:60]}")
            return


def _synthesis_os_mac(fp: DeviceFingerprint):
    """L11: Fusão final de evidências — inferência quando técnicas ativas não concluíram."""
    rand = fp.is_mac_randomized
    os_fp = fp.os_fingerprint
    unknown = fp.device_type == DeviceType.UNKNOWN
    has_ip = fp.ip and fp.ip not in ("0.0.0.0", "")

    if rand and os_fp == OSFingerprint.LINUX and unknown:
        fp._update_if_better(DeviceType.ANDROID_DEVICE, OSFingerprint.ANDROID, 60,
                              "L11 Síntese: MAC randomizado + TTL=64 → padrão Android")
    elif rand and os_fp == OSFingerprint.IOS and unknown:
        fp._update_if_better(DeviceType.IOS_DEVICE, OSFingerprint.IOS, 62,
                              "L11 Síntese: MAC randomizado + TTL=64 → possível iOS/iPadOS")
    elif rand and os_fp == OSFingerprint.WINDOWS:
        fp._update_if_better(DeviceType.WINDOWS_PC, OSFingerprint.WINDOWS, 62,
                              "L11 Síntese: MAC randomizado + TTL=128 → Windows 11 Wi-Fi Privacy")
    elif not rand and os_fp == OSFingerprint.CISCO_IOS and unknown:
        fp._update_if_better(DeviceType.ROUTER_GATEWAY, OSFingerprint.CISCO_IOS, 65,
                              "L11 Síntese: TTL=255 + MAC fixo → provável Cisco/Juniper")
    elif not rand and os_fp == OSFingerprint.WINDOWS and unknown:
        fp._update_if_better(DeviceType.WINDOWS_PC, OSFingerprint.WINDOWS, 55,
                              "L11 Síntese: TTL=128 + MAC fixo → Windows PC")
    elif not rand and os_fp == OSFingerprint.LINUX and unknown:
        fp._update_if_better(DeviceType.LINUX_SERVER, OSFingerprint.LINUX, 45,
                              "L11 Síntese: TTL=64 + MAC fixo → servidor Linux ou dispositivo Linux")
    elif not rand and os_fp == OSFingerprint.EMBEDDED and unknown:
        fp._update_if_better(DeviceType.IOT_SENSOR, OSFingerprint.EMBEDDED, 40,
                              "L11 Síntese: TTL atípico + MAC fixo → dispositivo embarcado/IoT")

    # — Dispositivos sem IP real (0.0.0.0) — classificação mínima garantida
    if unknown and not has_ip:
        if rand:
            # MAC randomizado sem IP = dispositivo móvel que já esteve na rede
            fp._update_if_better(DeviceType.ANDROID_DEVICE, OSFingerprint.ANDROID, 35,
                                  "L11 Síntese: MAC randomizado + sem IP → smartphone offline (já visto)")
        else:
            # MAC fixo sem IP = dispositivo inativo/offline que já passou pela rede
            fp._update_if_better(DeviceType.LINUX_SERVER, OSFingerprint.LINUX, 25,
                                  "L11 Síntese: MAC fixo + sem IP → dispositivo offline/inativo")


# ─────────────────────────────────────────────────────────────────────────────
# ENGINE PRINCIPAL
# ─────────────────────────────────────────────────────────────────────────────

class DeviceIntelligenceEngine:
    """
    Motor de fingerprinting Red Team v3.0 — 11 lentes encadeadas.
    Objetivo: Zero dispositivos 'Desconhecidos' na rede.
    """

    def __init__(
        self,
        port_probe_timeout: float = 0.55,
        http_timeout: float = 2.0,
        max_open_ports: int = 6,
        enable_netbios: bool = True,
        enable_ssdp: bool = True,
    ):
        self.port_probe_timeout = port_probe_timeout
        self.http_timeout = http_timeout
        self.max_open_ports = max_open_ports
        self.enable_netbios = enable_netbios
        self.enable_ssdp = enable_ssdp

    def analyze(self, ip: str, mac: str, vendor: str = "") -> DeviceFingerprint:
        """Pipeline Red Team — 11 lentes encadeadas de identificação."""
        fp = DeviceFingerprint(ip=ip, mac=mac)
        has_ip = ip and ip not in ("0.0.0.0", "IP Indisponível", "")

        # ── L0: MACs Especiais ─────────────────────────────────────────────────
        special = _check_special_mac(mac)
        if special:
            dev_type, os_fp, confidence, desc = special
            fp.device_type = dev_type
            fp.os_fingerprint = os_fp
            fp.confidence_score = confidence
            fp.evidence.append(f"L0 MAC Especial: {desc}")
            return fp  # early exit — não probar endereços de protocolo

        # ── L1: OUI Vendor Hint ────────────────────────────────────────────────
        hint = _oui_vendor_hint(vendor)
        if hint:
            dev_type, os_fp, confidence = hint
            fp._update_if_better(dev_type, os_fp, confidence,
                                  f"L1 OUI '{vendor}' → {dev_type.value}")

        # ── L2: MAC Randomization Detection ───────────────────────────────────
        fp.is_mac_randomized = _is_mac_randomized(mac)
        if fp.is_mac_randomized:
            fp.evidence.append("L2 MAC randomizado (Wi-Fi Privacy ativo)")

        if not has_ip:
            # Sem IP — síntese parcial com o que foi coletado
            _synthesis_os_mac(fp)
            return fp

        # ── L3: TTL Fingerprinting ─────────────────────────────────────────────
        with track_action(action="ttl_fp", target=ip):
            ttl, os_fp, ttl_ev = _ttl_fingerprint(ip)
            if ttl and ttl_ev:
                fp.os_fingerprint = os_fp
                fp.evidence.append(f"L3 {ttl_ev}")
                if fp.confidence_score < 15:
                    fp.confidence_score = 15

        # ── L4: PTR Hostname Resolution ────────────────────────────────────────
        with track_action(action="ptr", target=ip):
            hostname = _resolve_hostname(ip)
            if hostname:
                fp.hostname = hostname
                fp.evidence.append(f"L4 PTR → {hostname}")

        # ── L5: Hostname Pattern ────────────────────────────────────────────────
        if fp.hostname:
            _classify_hostname(fp.hostname, fp)

        # ── L6: NetBIOS Name Query (UDP 137) ───────────────────────────────────
        if self.enable_netbios:
            with track_action(action="netbios", target=ip):
                nbname = _netbios_query(ip)
                if nbname:
                    if not fp.hostname:
                        fp.hostname = nbname
                    fp._update_if_better(DeviceType.WINDOWS_PC, OSFingerprint.WINDOWS, 75,
                                          f"L6 NetBIOS Name: '{nbname}' → Windows/Samba")

        # ── L8: UPnP SSDP Discovery (UDP 1900) ────────────────────────────────
        if self.enable_ssdp:
            with track_action(action="ssdp", target=ip):
                ssdp_resp = _ssdp_query(ip)
                if ssdp_resp:
                    _classify_ssdp(ssdp_resp, fp)

        # ── L9: Port Probing Seletivo ──────────────────────────────────────────
        with track_action(action="port_scan", target=ip):
            for port, (dev_type, os_fp, evidence_msg, weight) in _PORT_DEVICE_MAP.items():
                if len(fp.open_ports) >= self.max_open_ports:
                    break
                if _probe_port(ip, port, timeout_s=self.port_probe_timeout):
                    fp.open_ports.append(port)
                    fp._update_if_better(dev_type, os_fp, weight,
                                          f"L9 TCP/{port} aberto → {evidence_msg}")

        # ── L10: HTTP Banner Grabbing ──────────────────────────────────────────
        http_candidates = [p for p in fp.open_ports if p in _HTTP_PROBE_PORTS]
        if not http_candidates:
            http_candidates = [80, 8080, 443]
        for port in http_candidates[:3]:
            with track_action(action="http_banner", target=f"{ip}:{port}"):
                banner = _grab_http_banner(ip, port, timeout_s=self.http_timeout)
                if banner:
                    fp.http_banner = banner[:250]
                    _classify_banner(banner, fp)
                    if fp.confidence_score >= 70:
                        break

        # ── L11: Síntese Final de Evidências ──────────────────────────────────
        _synthesis_os_mac(fp)

        log.info(
            "Intel[%s|%s] → %s (%s) score=%d%% ev=%d",
            ip, mac, fp.device_type.value, fp.os_fingerprint.value,
            fp.confidence_score, len(fp.evidence),
        )
        return fp
