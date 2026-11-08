"""
Bastion Audit v2.0 Enterprise - Native High-Performance Web Server & REST API
Zero Dependências Externas: Construído sobre a biblioteca padrão do Python com ThreadingHTTPServer.
"""
from __future__ import annotations

import base64
import csv
import io
import ipaddress
import json
import mimetypes
import os
import posixpath
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional

from adapters.device_intelligence import translate_hardware_model
from config.settings import get_base_dir
from core.engine import BastionCoreEngine
from core.models import DeviceStatus
from telemetry.killcam_logger import clear_system_log, get_logger, record_killcam, track_action

log = get_logger("BastionWebServer")


class BastionAPIHandler(BaseHTTPRequestHandler):
    """Handler HTTP customizado com suporte a arquivos estáticos e rotas RESTful."""

    server_version = "BastionWebServer/2.0"

    @property
    def engine(self) -> BastionCoreEngine:
        return self.server.engine  # type: ignore

    def _send_json(self, data: Any, status: int = 200):
        """Envia resposta JSON com headers de segurança e CORS."""
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Accept-CH", "Sec-CH-UA-Model, Sec-CH-UA-Platform, Sec-CH-UA-Platform-Version, Sec-CH-UA-Full-Version-List")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        """Suporte a Preflight CORS."""
        self.send_response(HTTPStatus.NO_CONTENT)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()

    def _check_web_access_allowed(self) -> bool:
        """Bloqueia na camada HTTP (403 Forbidden) qualquer IP que esteja na lista de bloqueio do Bastion."""
        client_ip = self.client_address[0] if self.client_address else ""
        if client_ip and client_ip not in ("127.0.0.1", "::1") and self.engine.defense.is_ip_blocked(client_ip):
            log.warning("🚫 [WEB BLOCK] Acesso HTTP negado (403) para o IP bloqueado: %s -> %s", client_ip, self.path)
            self._send_json(
                {
                    "error": "ACESSO WEB BLOQUEADO PELO ADMINISTRADOR DA REDE (BASTION HOST ARMOR)",
                    "blocked_ip": client_ip,
                    "status": 403,
                },
                status=403,
            )
            return False
        return True

    def _passive_enrich_caller_device(self):
        """
        Inspeção Passiva de HTTP Client-Hints (Sec-CH-UA-Model) e User-Agent:
        Se um celular/PC da LAN acessar qualquer página do Bastion, extrai o código OEM
        (ex: SM-G780G -> Samsung Galaxy S20 FE) e grava no ativo correspondente ao IP.
        """
        try:
            client_ip = self.client_address[0] if self.client_address else ""
            if not client_ip or client_ip in ("127.0.0.1", "::1"):
                return
            ch_model = (self.headers.get("Sec-CH-UA-Model") or "").strip().strip('"')
            ua = self.headers.get("User-Agent") or ""
            raw_clue = f"{ch_model} {ua}".strip()
            if not raw_clue:
                return
            exact = translate_hardware_model(raw_clue)
            model_str = exact[0] if exact else (ch_model if len(ch_model) >= 3 else "")
            if not model_str:
                return

            devices = self.engine.storage.get_all_devices()
            target_dev = next((d for d in devices if d.ip == client_ip), None)
            if target_dev:
                cur_model = (target_dev.metadata or {}).get("hardware_model") or ""
                if cur_model != model_str:
                    self.engine.storage.update_device_metadata(
                        mac=target_dev.mac,
                        meta_updates={"hardware_model": model_str},
                        device_type=exact[1].value if exact else None,
                        os_hint=exact[2].value if exact else None,
                        confidence_score=98,
                    )
        except Exception:
            pass

    def do_GET(self):
        if not self._check_web_access_allowed():
            return
        self._passive_enrich_caller_device()
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        # ─── ROTAS REST API ───────────────────────────────────────────────────
        if path in ("/id", "/identificar"):
            self._handle_get_mobile_probe_page()
        elif path == "/api/status":
            self._handle_get_status()
        elif path == "/api/devices":
            self._handle_get_devices()
        elif path == "/api/audit-trail":
            self._handle_get_audit_trail()
        elif path == "/api/verify-audit":
            self._handle_get_verify_audit()
        elif path == "/api/logs":
            self._handle_get_logs()
        elif path == "/api/defense/status":
            self._handle_get_defense_status()
        elif path == "/api/camera/snapshot":
            self._handle_get_camera_snapshot(parsed.query)
        elif path == "/api/export/report":
            self._handle_get_export_report(parsed.query)
        else:
            # ─── ARQUIVOS ESTÁTICOS ───────────────────────────────────────────
            self._serve_static_file(path)

    def do_POST(self):
        if not self._check_web_access_allowed():
            return
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/api/scan":
            self._handle_post_scan()
        elif path == "/api/devices/reclassify":
            self._handle_post_reclassify()
        elif path == "/api/device/status":
            self._handle_post_device_status()
        elif path == "/api/device/delete":
            self._handle_post_device_delete()
        elif path == "/api/device/deep-scan":
            self._handle_post_device_deep_scan()
        elif path == "/api/device/handshake":
            self._handle_post_device_handshake()
        elif path == "/api/device/update-meta":
            self._handle_post_device_update_meta()
        elif path == "/api/device/wol":
            self._handle_post_device_wol()
        elif path == "/api/camera/probe":
            self._handle_post_camera_probe()
        elif path == "/api/purge-legacy":
            self._handle_post_purge_legacy()
        elif path == "/api/defense/block":
            self._handle_post_defense_block()
        elif path == "/api/defense/unblock":
            self._handle_post_defense_unblock()
        elif path == "/api/defense/lock-gateway":
            self._handle_post_defense_lock_gateway()
        elif path == "/api/defense/honeyport":
            self._handle_post_defense_honeyport()
        elif path == "/api/defense/elevate-uac":
            self._handle_post_defense_elevate_uac()
        elif path == "/api/device/identify-self":
            self._handle_post_device_identify_self()
        elif path == "/api/logs/clear":
            self._handle_post_logs_clear()
        else:
            self._send_json({"error": "Endpoint não encontrado", "path": path}, 404)

    # ─── IMPLEMENTAÇÃO DOS HANDLERS DE API ────────────────────────────────────

    def _handle_get_status(self):
        engine = self.engine
        summary = engine.storage.get_audit_summary()

        # Mede ping rápido para o alvo para telemetria de latência
        start_t = time.time()
        is_online = engine.network_probe.ping(engine.config.agent.target_ip, timeout_ms=1000)
        latency_ms = round((time.time() - start_t) * 1000, 1) if is_online else -1

        data = {
            "version": engine.config.agent.version,
            "status": "active",
            "wan_target": engine.config.agent.target_ip,
            "wan_online": is_online,
            "wan_latency_ms": latency_ms,
            "local_ip": engine.active_interface.ip_address if engine.active_interface else "127.0.0.1",
            "active_subnet": engine.active_interface.cidr_subnet if engine.active_interface else engine.config.agent.base_subnet,
            "total_oui_vendors": engine.oui_resolver.total_vendors,
            "metrics": summary,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        self._send_json(data)

    def _handle_get_devices(self):
        devices = self.engine.storage.get_all_devices()
        device_list = [d.to_dict() for d in devices]
        self._send_json({"devices": device_list, "count": len(device_list)})

    def _handle_post_scan(self):
        def _async_scan():
            try:
                self.engine.perform_radar_audit()
            except Exception as e:
                record_killcam(e, custom_msg="Erro ao disparar varredura via Web API")

        t = threading.Thread(target=_async_scan, name="ManualWebScan", daemon=True)
        t.start()
        self._send_json({"message": "Varredura de radar iniciada em background com sucesso."})

    def _handle_post_device_status(self):
        try:
            content_len = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_len)
            payload = json.loads(body.decode("utf-8"))
        except Exception:
            self._send_json({"error": "Payload JSON inválido"}, 400)
            return

        mac = payload.get("mac")
        status_str = payload.get("status")
        if not mac or not status_str:
            self._send_json({"error": "Parâmetros 'mac' e 'status' são obrigatórios"}, 400)
            return

        try:
            status = DeviceStatus(status_str)
        except ValueError:
            self._send_json({"error": f"Status inválido. Permitidos: {[s.value for s in DeviceStatus]}"}, 400)
            return

        dev = self.engine.storage.get_device(mac)
        if not dev:
            self._send_json({"error": "Dispositivo não encontrado no inventário"}, 404)
            return

        with self.engine.storage.transaction() as cur:
            cur.execute("UPDATE devices SET status = ? WHERE mac = ?", (status.value, mac))

        self.engine.audit_ledger.record_event(
            event_type="DEVICE_STATUS_MODIFIED",
            source="WebDashboard",
            severity="AUDIT",
            payload={"mac": mac, "old_status": dev.status.value, "new_status": status.value},
        )

        self._send_json({"message": "Status atualizado com sucesso", "mac": mac, "status": status.value})

    def _handle_post_device_delete(self):
        try:
            content_len = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_len)
            payload = json.loads(body.decode("utf-8"))
        except Exception:
            self._send_json({"error": "Payload JSON inválido"}, 400)
            return

        mac = payload.get("mac")
        if not mac:
            self._send_json({"error": "Parâmetro 'mac' é obrigatório"}, 400)
            return

        deleted = self.engine.storage.delete_device(mac)
        if not deleted:
            self._send_json({"error": "Dispositivo não encontrado ou não pôde ser removido"}, 404)
            return

        self.engine.audit_ledger.record_event(
            event_type="DEVICE_REMOVED",
            source="WebDashboard",
            severity="AUDIT",
            payload={"mac": mac},
        )
        self._send_json({"message": f"Ativo {mac} removido com sucesso do inventário", "mac": mac})

    def _handle_post_purge_legacy(self):
        purged_count = self.engine.storage.purge_legacy_devices()
        self.engine.audit_ledger.record_event(
            event_type="LEGACY_BASELINE_PURGED",
            source="WebDashboard",
            severity="AUDIT",
            payload={"purged_count": purged_count},
        )
        self._send_json({
            "message": f"Expurgo concluído: {purged_count} registros legados removidos.",
            "purged_count": purged_count,
        })


    def _handle_get_defense_status(self):
        status_data = self.engine.defense.get_defense_status()
        self._send_json(status_data)

    def _handle_post_defense_block(self):
        try:
            content_len = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_len)
            payload = json.loads(body.decode("utf-8"))
        except Exception:
            self._send_json({"error": "Payload JSON inválido"}, 400)
            return

        ip = payload.get("ip", "")
        mac = payload.get("mac", "")
        reason = payload.get("reason", "Bloqueio manual via Dashboard")

        if not ip and not mac:
            self._send_json({"error": "Informe pelo menos 'ip' ou 'mac' para bloqueio"}, 400)
            return

        blocked = self.engine.defense.block_threat(ip=ip, mac=mac, reason=reason)
        if blocked:
            # Registra no ledger criptográfico
            self.engine.audit_ledger.record_event(
                event_type="FIREWALL_THREAT_BLOCKED",
                source="WebDashboard",
                severity="AUDIT",
                payload={"ip": ip, "mac": mac, "reason": reason},
            )
            self._send_json({"message": f"Alvo {ip or mac} bloqueado no firewall com sucesso.", "success": True})
        else:
            self._send_json({"error": f"Não foi possível bloquear o alvo {ip or mac} (pode estar na Whitelist protegida)", "success": False}, 400)

    def _handle_post_defense_unblock(self):
        try:
            content_len = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_len)
            payload = json.loads(body.decode("utf-8"))
        except Exception:
            self._send_json({"error": "Payload JSON inválido"}, 400)
            return

        ip = payload.get("ip", "")
        mac = payload.get("mac", "")

        unblocked = self.engine.defense.unblock_threat(ip=ip, mac=mac)
        self.engine.audit_ledger.record_event(
            event_type="FIREWALL_THREAT_UNBLOCKED",
            source="WebDashboard",
            severity="AUDIT",
            payload={"ip": ip, "mac": mac},
        )
        self._send_json({"message": f"Regra de bloqueio para {ip or mac} removida com sucesso.", "success": unblocked})

    def _handle_post_defense_lock_gateway(self):
        gateway_ip = self.engine.active_interface.gateway if self.engine.active_interface else None
        gateway_mac = self.engine.defense.known_gateway_mac

        if not gateway_ip or not gateway_mac:
            self._send_json({"error": "Gateway IP ou MAC não resolvido no momento. Execute um radar sweep primeiro.", "success": False}, 400)
            return

        locked = self.engine.defense.lock_gateway_arp(gateway_ip, gateway_mac)
        if locked:
            self.engine.audit_ledger.record_event(
                event_type="GATEWAY_ARP_LOCKED",
                source="WebDashboard",
                severity="AUDIT",
                payload={"gateway_ip": gateway_ip, "gateway_mac": gateway_mac},
            )
            self._send_json({"message": f"Escudo Gateway ARP travado permanentemente: {gateway_ip} -> {gateway_mac}", "success": True})
        else:
            self._send_json({"error": "Falha ao travar entrada ARP estática no sistema operacional.", "success": False}, 500)

    def _handle_post_defense_elevate_uac(self):
        elevated = self.engine.defense.elevate_windows_firewall_rules()
        if elevated:
            self.engine.audit_ledger.record_event(
                event_type="FIREWALL_UAC_KERNEL_ENFORCED",
                source="WebDashboard",
                severity="AUDIT",
                payload={"action": "elevate_windows_firewall_rules"},
            )
            self._send_json({
                "success": True,
                "message": "Janela UAC do Windows disparada! As regras de bloqueio foram aplicadas diretamente no Windows Defender Firewall.",
            })
        else:
            self._send_json({
                "success": False,
                "error": "Adicione pelo menos 1 IP à lista de bloqueio primeiro antes de solicitar a elevação UAC do Firewall.",
            }, 400)


    def _handle_get_audit_trail(self):
        audit_file = self.engine.config.storage.audit_log_path
        events = []
        if os.path.exists(audit_file):
            try:
                with open(audit_file, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            events.append(json.loads(line))
            except Exception as e:
                log.error("Erro ao ler audit trail: %s", e)

        # Retorna os últimos 50 eventos (mais recentes primeiro)
        events.reverse()
        self._send_json({"events": events[:50], "total_events": len(events)})

    def _handle_get_verify_audit(self):
        valid, err, count = self.engine.audit_ledger.verify_integrity()
        self._send_json({
            "is_valid": valid,
            "error_message": err,
            "verified_entries_count": count,
            "checked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        })

    def _handle_get_logs(self):
        log_file = self.engine.config.storage.system_log_path
        lines = []
        if os.path.exists(log_file):
            try:
                with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
                    all_lines = f.readlines()
                    lines = all_lines[-80:]
            except Exception:
                pass
        self._send_json({"logs": [l.strip() for l in lines if l.strip()]})

    def _handle_post_logs_clear(self):
        log_file = self.engine.config.storage.system_log_path
        ok = clear_system_log(log_file)
        self._send_json({"success": ok, "message": "Logs de telemetria limpos com sucesso."})

    def _handle_get_mobile_probe_page(self):
        """
        Serve uma página leve (/id) que extrai Client-Hints de alta entropia (Sec-CH-UA-Model no Android)
        e resolução/GPU WebGL (Apple iPhone 11/12/13/14/15 no iOS) para gravar o modelo comercial exato.
        """
        client_ip = self.client_address[0] if self.client_address else "Desconhecido"
        html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Bastion Audit · Identificador Profundo de Hardware</title>
  <style>
    body {{
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #f8fafc; color: #0f172a; margin: 0; padding: 24px;
      display: flex; align-items: center; justify-content: center; min-height: 90vh;
    }}
    .card {{
      background: #fff; border: 2px solid #cbd5e1; border-radius: 18px;
      padding: 28px; max-width: 480px; width: 100%;
      box-shadow: 0 15px 35px rgba(15,23,42,0.08); text-align: center;
    }}
    h1 {{ font-size: 1.45rem; margin: 0 0 8px; color: #0284c7; }}
    p {{ font-size: 1.02rem; color: #475569; line-height: 1.5; }}
    .result-box {{
      margin: 20px 0; padding: 18px; background: #f0f9ff;
      border: 2px solid #7dd3fc; border-radius: 12px; font-size: 1.15rem; font-weight: 700;
    }}
    input, button {{
      width: 100%; padding: 13px; border-radius: 10px; font-size: 1.05rem;
      margin-top: 10px; box-sizing: border-box;
    }}
    input {{ border: 1px solid #94a3b8; }}
    button {{
      background: #0284c7; color: #fff; border: none; font-weight: 700; cursor: pointer;
    }}
  </style>
</head>
<body>
  <div class="card">
    <h1>📱 Sonda de Identidade Bastion</h1>
    <p>Seu IP na rede: <strong>{client_ip}</strong></p>
    <div id="probeStatus" class="result-box">🔍 Analisando assinatura de hardware...</div>
    <input type="text" id="customOwnerInput" placeholder="Opcional: Seu nome / apelido (ex: Celular do Welzo)">
    <button onclick="sendIdentity()">✅ Confirmar Identidade na Rede</button>
  </div>
  <script>
    let detectedData = {{ model: '', platform: '', platformVersion: '', gpu: '', screen: '' }};

    function inferAppleModel() {{
      const w = Math.min(window.screen.width, window.screen.height);
      const h = Math.max(window.screen.width, window.screen.height);
      const dpr = window.devicePixelRatio || 1;
      const sig = `${{w}}x${{h}}@${{dpr}}`;
      const map = {{
        '390x844@3': 'Apple iPhone 13 / 14 / 13 Pro',
        '393x852@3': 'Apple iPhone 14 Pro / 15 / 15 Pro',
        '428x926@3': 'Apple iPhone 12 Pro Max / 13 Pro Max / 14 Plus',
        '430x932@3': 'Apple iPhone 14 Pro Max / 15 Plus / 15 Pro Max',
        '375x812@3': 'Apple iPhone X / XS / 11 Pro / 12 mini / 13 mini',
        '414x896@2': 'Apple iPhone 11 / XR',
        '414x896@3': 'Apple iPhone XS Max / 11 Pro Max',
        '375x667@2': 'Apple iPhone SE (2ª/3ª Geração) / iPhone 8'
      }};
      return map[sig] || `Apple iPhone (${{sig}})`;
    }}

    async function detectHardware() {{
      detectedData.screen = `${{window.screen.width}}x${{window.screen.height}}@${{window.devicePixelRatio || 1}}`;
      try {{
        const canvas = document.createElement('canvas');
        const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
        if (gl) {{
          const dbg = gl.getExtension('WEBGL_debug_renderer_info');
          if (dbg) detectedData.gpu = gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) || '';
        }}
      }} catch (e) {{}}

      if (navigator.userAgentData && navigator.userAgentData.getHighEntropyValues) {{
        try {{
          const ua = await navigator.userAgentData.getHighEntropyValues(['model', 'platform', 'platformVersion']);
          detectedData.model = ua.model || '';
          detectedData.platform = ua.platform || '';
          detectedData.platformVersion = ua.platformVersion || '';
        }} catch (e) {{}}
      }}

      const uaStr = navigator.userAgent || '';
      if (!detectedData.model && /iPhone|iPad/i.test(uaStr)) {{
        detectedData.model = inferAppleModel();
        detectedData.platform = 'iOS';
      }}

      await sendIdentity(true);
    }}

    async function sendIdentity(auto = false) {{
      const customName = document.getElementById('customOwnerInput').value.trim();
      const res = await fetch('/api/device/identify-self', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{
          ...detectedData,
          userAgent: navigator.userAgent,
          custom_name: customName
        }})
      }});
      const data = await res.json();
      const box = document.getElementById('probeStatus');
      if (data.hardware_model) {{
        box.innerHTML = `✅ Identificado: <span style="color:#0284c7">${{data.hardware_model}}</span><br><small style="font-weight:500;color:#475569">MAC: ${{data.mac || 'Vinculado ao IP'}}</small>`;
      }} else {{
        box.textContent = data.message || 'Dispositivo registrado!';
      }}
    }}

    detectHardware();
  </script>
</body>
</html>"""
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Accept-CH", "Sec-CH-UA-Model, Sec-CH-UA-Platform, Sec-CH-UA-Platform-Version, Sec-CH-UA-Full-Version-List")
        self.send_header("Critical-CH", "Sec-CH-UA-Model")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _handle_post_device_identify_self(self):
        """Recebe telemetria de alta entropia do próprio aparelho (/id) e grava o modelo comercial exato."""
        try:
            content_len = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_len)
            payload = json.loads(body.decode("utf-8"))
        except Exception:
            self._send_json({"error": "Payload JSON inválido"}, 400)
            return

        client_ip = payload.get("ip") or (self.client_address[0] if self.client_address else "")
        raw_model = (payload.get("model") or "").strip()
        ua_str = (payload.get("userAgent") or self.headers.get("User-Agent") or "").strip()
        platform = (payload.get("platform") or "").strip()
        platform_ver = (payload.get("platformVersion") or "").strip()
        gpu = (payload.get("gpu") or "").strip()
        custom_name = (payload.get("custom_name") or "").strip()

        combined = f"{raw_model} {ua_str}".strip()
        exact = translate_hardware_model(combined)
        if exact:
            friendly_model, dev_type_enum, os_enum = exact
            dev_type_val = dev_type_enum.value
            os_val = os_enum.value
        else:
            friendly_model = raw_model or ("Windows PC" if "Windows" in ua_str else "Smartphone / Dispositivo Verificado")
            dev_type_val = None
            os_val = f"{platform} {platform_ver}".strip() if platform else None

        if gpu and "Apple" in friendly_model and "GPU" not in friendly_model:
            friendly_model = f"{friendly_model} ({gpu})"

        devices = self.engine.storage.get_all_devices()
        target_dev = next((d for d in devices if d.ip == client_ip), None)
        if target_dev:
            meta_up: Dict[str, Any] = {"hardware_model": friendly_model}
            if custom_name:
                meta_up["custom_name"] = custom_name
            self.engine.storage.update_device_metadata(
                mac=target_dev.mac,
                meta_updates=meta_up,
                device_type=dev_type_val,
                os_hint=os_val,
                confidence_score=99,
                evidence_list=[
                    f"L12 Sonda Direta Client-Hints (/id) → Modelo Exato: '{friendly_model}'",
                    f"User-Agent / GPU: {ua_str[:90]} | {gpu}",
                ],
            )
            self._send_json({
                "success": True,
                "ip": client_ip,
                "mac": target_dev.mac,
                "hardware_model": friendly_model,
                "message": f"Identidade confirmada: {friendly_model}",
            })
        else:
            self._send_json({
                "success": True,
                "ip": client_ip,
                "mac": None,
                "hardware_model": friendly_model,
                "message": f"Modelo detectado: {friendly_model} (IP {client_ip})",
            })

    def _handle_post_reclassify(self):
        """Reprocessa OUI e heurística imediata + dispara sondagem ativa em background."""
        fast_count = self.engine.reclassify_all_devices(active_network_probe=False)

        def _bg_deep_reclassify():
            try:
                self.engine.reclassify_all_devices(active_network_probe=True)
            except Exception as e:
                log.error("Erro na reclassificação ativa em background: %s", e)

        threading.Thread(target=_bg_deep_reclassify, name="DeepReclassifyThread", daemon=True).start()
        self._send_json({
            "success": True,
            "updated_count": fast_count,
            "message": "Dispositivos atualizados! Enviando handshakes aos aparelhos conectados...",
        })

    def _handle_post_device_handshake(self):
        """Executa Handshake de Identidade Ativo sob demanda (botão '📡 Identificar')."""
        try:
            content_len = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_len)
            payload = json.loads(body.decode("utf-8"))
        except Exception:
            self._send_json({"error": "Payload JSON inválido"}, 400)
            return

        mac = payload.get("mac", "")
        ip = payload.get("ip", "")
        if not mac and not ip:
            self._send_json({"error": "Informe 'mac' ou 'ip' para enviar o handshake"}, 400)
            return

        dev = self.engine.storage.get_device(mac) if mac else None
        effective_ip = ip or (dev.ip if dev else "")
        effective_mac = mac or (dev.mac if dev else "")
        vendor = self.engine.oui_resolver.lookup(effective_mac)

        hs_res = self.engine.intelligence.perform_identity_handshake(
            ip=effective_ip, mac=effective_mac, vendor=vendor
        )
        fp_dict = hs_res["fingerprint"]
        eff_host = fp_dict.get("hostname") or (dev.hostname if dev else None)
        eff_model = fp_dict.get("hardware_model") or ""
        if eff_host and eff_model in ("", "Celular / Aparelho Wi-Fi (MAC Privado)", "Smartphone Android"):
            if fp_dict.get("device_type") == "Smartphone/Tablet Android":
                eff_model = f"Celular Android (ID: {eff_host})"

        if effective_mac:
            meta_up = {
                "open_ports": fp_dict.get("open_ports") or [],
                "http_banner": fp_dict.get("http_banner") or "",
                "last_handshake": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }
            if hs_res.get("latency_ms") is not None:
                meta_up["latency_ms"] = hs_res["latency_ms"]
            if eff_model:
                meta_up["hardware_model"] = eff_model

            self.engine.storage.update_device_metadata(
                mac=effective_mac,
                meta_updates=meta_up,
                device_type=fp_dict.get("device_type"),
                os_hint=fp_dict.get("os_fingerprint"),
                hostname=eff_host,
                vendor=vendor if vendor != "Fabricante desconhecido" else None,
                confidence_score=fp_dict.get("confidence_score"),
                evidence_list=fp_dict.get("evidence"),
            )

        lat_str = f"{int(hs_res['latency_ms'])}ms" if hs_res.get("latency_ms") is not None else "modo economia"
        display_identity = eff_host or eff_model or fp_dict.get("device_type") or effective_ip
        msg = f"Handshake concluído ({lat_str}): {display_identity}"
        if eff_model and eff_host and eff_model != eff_host:
            msg = f"Handshake ({lat_str}) → {eff_host} · {eff_model}"

        self._send_json({
            "success": True,
            "reachable": hs_res["reachable"],
            "latency_ms": hs_res["latency_ms"],
            "hostname": eff_host,
            "hardware_model": eff_model,
            "device_type": fp_dict.get("device_type"),
            "open_ports": fp_dict.get("open_ports") or [],
            "evidence": fp_dict.get("evidence") or [],
            "message": msg,
        })

    def _handle_post_device_deep_scan(self):
        try:
            content_len = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_len)
            payload = json.loads(body.decode("utf-8"))
        except Exception:
            self._send_json({"error": "Payload JSON inválido"}, 400)
            return

        mac = payload.get("mac", "")
        ip = payload.get("ip", "")
        if not mac and not ip:
            self._send_json({"error": "Informe 'mac' ou 'ip' para a auditoria profunda"}, 400)
            return

        dev = self.engine.storage.get_device(mac) if mac else None
        effective_ip = ip or (dev.ip if dev else "")
        effective_mac = mac or (dev.mac if dev else "")
        vendor = self.engine.oui_resolver.lookup(effective_mac)

        scan_res = self.engine.intelligence.deep_scan_device(
            ip=effective_ip, mac=effective_mac, vendor=vendor
        )
        fp_dict = scan_res["fingerprint"]

        if effective_mac:
            meta_up = {
                "open_ports": scan_res["open_ports"],
                "http_banner": fp_dict.get("http_banner") or "",
                "risk_score": scan_res["risk_score"],
                "risk_level": scan_res["risk_level"],
                "risk_findings": scan_res["risk_findings"],
                "is_camera_capable": scan_res["is_camera_capable"],
                "last_deep_scan": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }
            if fp_dict.get("hardware_model"):
                meta_up["hardware_model"] = fp_dict["hardware_model"]
            self.engine.storage.update_device_metadata(
                mac=effective_mac,
                meta_updates=meta_up,
                device_type=fp_dict.get("device_type"),
                os_hint=fp_dict.get("os_fingerprint"),
                hostname=fp_dict.get("hostname"),
                vendor=vendor if vendor != "Fabricante desconhecido" else None,
                confidence_score=fp_dict.get("confidence_score"),
                evidence_list=fp_dict.get("evidence"),
            )

        self.engine.audit_ledger.record_event(
            event_type="DEVICE_DEEP_SCAN_COMPLETED",
            source="WebDashboard",
            severity="AUDIT",
            payload={
                "mac": effective_mac,
                "ip": effective_ip,
                "open_ports": scan_res["open_ports"],
                "risk_level": scan_res["risk_level"],
                "risk_score": scan_res["risk_score"],
            },
        )
        self._send_json({"success": True, "result": scan_res})

    def _handle_post_device_update_meta(self):
        try:
            content_len = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_len)
            payload = json.loads(body.decode("utf-8"))
        except Exception:
            self._send_json({"error": "Payload JSON inválido"}, 400)
            return

        mac = payload.get("mac", "")
        if not mac:
            self._send_json({"error": "Parâmetro 'mac' é obrigatório"}, 400)
            return

        custom_name = payload.get("custom_name")
        device_type = payload.get("device_type")
        hardware_model = payload.get("hardware_model")
        notes = payload.get("notes")
        camera_url = payload.get("camera_url")
        camera_user = payload.get("camera_user")
        camera_pass = payload.get("camera_pass")

        meta_updates: Dict[str, Any] = {}
        if custom_name is not None:
            meta_updates["custom_name"] = custom_name.strip()
        if hardware_model is not None:
            meta_updates["hardware_model"] = hardware_model.strip()
        if notes is not None:
            meta_updates["notes"] = notes.strip()
        if camera_url is not None:
            meta_updates["camera_url"] = camera_url.strip()
        if camera_user is not None:
            meta_updates["camera_user"] = camera_user.strip()
        if camera_pass is not None:
            meta_updates["camera_pass"] = camera_pass
        if device_type:
            meta_updates["manual_override"] = True

        ok = self.engine.storage.update_device_metadata(
            mac=mac,
            meta_updates=meta_updates,
            device_type=device_type if device_type else None,
        )
        if not ok:
            self._send_json({"error": "Dispositivo não encontrado"}, 404)
            return

        self.engine.audit_ledger.record_event(
            event_type="DEVICE_METADATA_UPDATED",
            source="WebDashboard",
            severity="AUDIT",
            payload={"mac": mac, "custom_name": custom_name, "device_type": device_type},
        )
        self._send_json({"success": True, "message": "Identificação e metadados do ativo atualizados."})

    def _handle_post_device_wol(self):
        try:
            content_len = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_len)
            payload = json.loads(body.decode("utf-8"))
        except Exception:
            self._send_json({"error": "Payload JSON inválido"}, 400)
            return

        mac = payload.get("mac", "")
        if not mac:
            self._send_json({"error": "Parâmetro 'mac' é obrigatório"}, 400)
            return

        sent = self.engine.defense.send_wake_on_lan(mac=mac)
        if sent:
            self.engine.audit_ledger.record_event(
                event_type="WAKE_ON_LAN_DISPATCHED",
                source="WebDashboard",
                severity="AUDIT",
                payload={"mac": mac},
            )
            self._send_json({"success": True, "message": f"Pacote mágico Wake-on-LAN disparado na rede para {mac}."})
        else:
            self._send_json({"error": "Falha ao enviar pacote Wake-on-LAN. Verifique o endereço MAC."}, 400)

    def _handle_post_camera_probe(self):
        try:
            content_len = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_len)
            payload = json.loads(body.decode("utf-8"))
        except Exception:
            self._send_json({"error": "Payload JSON inválido"}, 400)
            return

        ip = payload.get("ip", "").strip()
        username = payload.get("username", "admin").strip() or "admin"
        password = payload.get("password", "")
        if not ip or ip == "0.0.0.0":
            self._send_json({"error": "IP da câmera inválido ou indisponível"}, 400)
            return

        probe_data = self.engine.intelligence.probe_camera_capabilities(
            ip=ip, username=username, password=password
        )
        self._send_json({"success": True, "camera": probe_data})

    def _handle_get_camera_snapshot(self, query_string: str):
        """
        Proxy seguro para capturar Snapshot JPEG ou MJPEG de câmeras na rede local (LAN),
        contornando bloqueios de CORS, Mixed-Content e certificados autoassinados.
        """
        params = urllib.parse.parse_qs(query_string)
        target_url = (params.get("url", [""])[0]).strip()
        username = (params.get("user", [""])[0]).strip()
        password = params.get("pass", [""])[0]

        if not target_url:
            self._send_json({"error": "Parâmetro 'url' é obrigatório"}, 400)
            return

        parsed_target = urllib.parse.urlparse(target_url)
        host = parsed_target.hostname or ""
        try:
            ip_obj = ipaddress.ip_address(host)
            if not (ip_obj.is_private or ip_obj.is_loopback):
                self._send_json({"error": "Proxy permitido apenas para dispositivos na rede privada (LAN)"}, 403)
                return
        except ValueError:
            self._send_json({"error": "Host da câmera deve ser um endereço IP privado válido"}, 400)
            return

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        req = urllib.request.Request(target_url, headers={"User-Agent": "BastionCyberHUD/2.0"})
        if username:
            creds = f"{username}:{password}".encode("utf-8")
            req.add_header("Authorization", "Basic " + base64.b64encode(creds).decode("ascii"))

        try:
            with urllib.request.urlopen(req, timeout=3.5, context=ctx if parsed_target.scheme == "https" else None) as resp:
                ctype = resp.headers.get("Content-Type", "image/jpeg")
                data = resp.read(5 * 1024 * 1024)  # máx 5MB por frame
                self.send_response(200)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(data)
        except urllib.error.HTTPError as he:
            self._send_json({"error": f"Câmera retornou HTTP {he.code} (Verifique usuário/senha ou caminho do snapshot)", "code": he.code}, he.code)
        except Exception as e:
            self._send_json({"error": f"Não foi possível obter frame da câmera: {e}"}, 502)

    def _handle_post_defense_honeyport(self):
        try:
            content_len = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_len)
            payload = json.loads(body.decode("utf-8"))
        except Exception:
            self._send_json({"error": "Payload JSON inválido"}, 400)
            return

        enabled = payload.get("enabled", True)
        auto_block = payload.get("auto_block", False)
        ports = payload.get("ports")

        if enabled:
            state = self.engine.defense.start_honeyport_traps(ports=ports, auto_block=auto_block)
            msg = f"Sensores Honeyport ativos nas portas {state['active_ports']} (Auto-Block: {'ATIVADO' if auto_block else 'INTERATIVO'})."
        else:
            self.engine.defense.stop_honeyport_traps()
            state = {"enabled": False, "active_ports": [], "auto_block": False}
            msg = "Sensores Honeyport desativados temporariamente."

        self.engine.audit_ledger.record_event(
            event_type="HONEYPORT_CONFIG_CHANGED",
            source="WebDashboard",
            severity="AUDIT",
            payload=state,
        )
        self._send_json({"success": True, "message": msg, "honeyport": state})

    def _handle_get_export_report(self, query_string: str):
        params = urllib.parse.parse_qs(query_string)
        fmt = (params.get("format", ["csv"])[0]).lower()
        devices = self.engine.storage.get_all_devices()

        if fmt == "json":
            valid, err, count = self.engine.audit_ledger.verify_integrity()
            report = {
                "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "agent_version": self.engine.config.agent.version,
                "subnet": self.engine.active_interface.cidr_subnet if self.engine.active_interface else self.engine.config.agent.base_subnet,
                "audit_ledger_integrity": {"is_valid": valid, "verified_events": count},
                "defense_status": self.engine.defense.get_defense_status(),
                "devices": [d.to_dict() for d in devices],
            }
            body = json.dumps(report, indent=2, ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Disposition", 'attachment; filename="bastion_audit_report.json"')
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        # Exportação CSV padrão compatível com Excel (UTF-8 BOM)
        output = io.StringIO()
        output.write("\ufeff")
        writer = csv.writer(output, delimiter=";")
        writer.writerow([
            "MAC Address", "IP", "Apelido / Hostname", "Tipo de Dispositivo", "Sistema Operacional",
            "Fabricante OUI", "Status", "MAC Randomizado", "Confianca (%)", "Portas Abertas",
            "Nivel de Risco", "Primeiro Visto", "Ultimo Visto"
        ])
        for d in devices:
            meta = d.metadata or {}
            writer.writerow([
                d.mac,
                d.ip,
                meta.get("custom_name") or d.hostname or "",
                meta.get("device_type") or "Dispositivo Desconhecido",
                meta.get("os_hint") or "",
                d.vendor,
                d.status.value,
                "Sim" if meta.get("is_mac_randomized") else "Nao",
                meta.get("confidence_score", 0),
                ",".join(str(p) for p in (meta.get("open_ports") or [])),
                meta.get("risk_level") or "NORMAL",
                d.first_seen or "",
                d.last_seen or "",
            ])
        csv_bytes = output.getvalue().encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/csv; charset=utf-8")
        self.send_header("Content-Disposition", 'attachment; filename="bastion_inventario_lgpd.csv"')
        self.send_header("Content-Length", str(len(csv_bytes)))
        self.end_headers()
        self.wfile.write(csv_bytes)

    # ─── SERVIÇO DE ARQUIVOS ESTÁTICOS ────────────────────────────────────────

    def _serve_static_file(self, path: str):
        # Resolve diretório static
        base_dir = get_base_dir()
        static_dir = os.path.join(base_dir, "web", "static")
        if not os.path.isdir(static_dir):
            static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")

        if path in ("", "/"):
            path = "/index.html"

        clean_path = posixpath.normpath(urllib.parse.unquote(path)).lstrip("/")
        full_path = os.path.join(static_dir, clean_path)

        if not os.path.isfile(full_path):
            self.send_error(404, "Arquivo não encontrado")
            return

        ctype, _ = mimetypes.guess_type(full_path)
        if not ctype:
            ctype = "application/octet-stream"

        try:
            with open(full_path, "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", f"{ctype}; charset=utf-8" if "text" in ctype or "javascript" in ctype or "json" in ctype else ctype)
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Cache-Control", "no-cache, must-revalidate")
            self.end_headers()
            self.wfile.write(content)
        except Exception as e:
            self.send_error(500, f"Erro interno ao ler arquivo: {e}")

    def log_message(self, format, *args):
        # Redireciona logs internos do HTTP para o nosso logger
        log.debug("[HTTP] %s - - [%s] %s", self.address_string(), self.log_date_time_string(), format % args)


class BastionWebServer(ThreadingHTTPServer):
    """Servidor HTTP multithread acoplado ao motor do Bastion."""

    def __init__(self, server_address, RequestHandlerClass, engine: BastionCoreEngine):
        self.engine = engine
        super().__init__(server_address, RequestHandlerClass)


def start_web_server(engine: BastionCoreEngine, host: str = "0.0.0.0", port: int = 5055) -> BastionWebServer:
    """Inicia o servidor web em background ou de forma síncrona."""
    server_address = (host, port)
    httpd = BastionWebServer(server_address, BastionAPIHandler, engine=engine)
    log.info("Servidor Web Bastion iniciado em http://%s:%d", host, port)
    return httpd
