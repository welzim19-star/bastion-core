"""
Testes de Integração para o Servidor Web e Endpoints da REST API.
"""
import json
import os
import shutil
import tempfile
import threading
import time
import unittest
import urllib.request

from config.settings import BastionConfig, AgentSettings, SecuritySettings, NotificationSettings, StorageSettings
from core.engine import BastionCoreEngine
from core.models import Device, DeviceStatus
from web.server import start_web_server


class TestWebServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.test_dir = tempfile.mkdtemp()
        config = BastionConfig(
            agent=AgentSettings(
                target_ip="127.0.0.1",
                base_subnet="127.0.0.0/24",
                ping_interval_seconds=1,
            ),
            security=SecuritySettings(enable_immutable_audit_log=True),
            notifications=NotificationSettings(webhook_url=""),
            storage=StorageSettings(
                base_dir=cls.test_dir,
                db_filename="test_web_db.db",
                audit_log_filename="test_web_audit.jsonl",
                system_log_filename="test_web_sys.log",
            ),
        )
        cls.engine = BastionCoreEngine(config)
        # Insere um dispositivo de teste
        cls.engine.storage.upsert_device(
            Device(mac="00:12:12:34:56:78", ip="192.168.1.99", vendor="Intelbras", status=DeviceStatus.UNKNOWN)
        )

        cls.port = 5099
        cls.server = start_web_server(cls.engine, host="127.0.0.1", port=cls.port)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        time.sleep(0.5)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        shutil.rmtree(cls.test_dir, ignore_errors=True)

    def _get(self, path: str):
        url = f"http://127.0.0.1:{self.port}{path}"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=3) as resp:
            return resp.status, resp.read()

    def _post(self, path: str, payload: dict):
        url = f"http://127.0.0.1:{self.port}{path}"
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            return resp.status, resp.read()

    def test_static_index_html(self):
        status, content = self._get("/")
        self.assertEqual(status, 200)
        self.assertIn(b"BASTION AUDIT", content)

    def test_static_css_and_js(self):
        status, content = self._get("/css/dashboard.css")
        self.assertEqual(status, 200)
        self.assertIn(b"--neon-cyan", content)

        status, content = self._get("/js/app.js")
        self.assertEqual(status, 200)
        self.assertIn(b"CyberRadar", content)

    def test_api_status(self):
        status, content = self._get("/api/status")
        self.assertEqual(status, 200)
        data = json.loads(content.decode("utf-8"))
        self.assertEqual(data["status"], "active")
        self.assertIn("metrics", data)

    def test_api_devices(self):
        status, content = self._get("/api/devices")
        self.assertEqual(status, 200)
        data = json.loads(content.decode("utf-8"))
        self.assertGreaterEqual(data["count"], 1)
        macs = [d["mac"] for d in data["devices"]]
        self.assertIn("00:12:12:34:56:78", macs)

    def test_api_device_status_update(self):
        status, content = self._post(
            "/api/device/status", {"mac": "00:12:12:34:56:78", "status": "authorized"}
        )
        self.assertEqual(status, 200)
        data = json.loads(content.decode("utf-8"))
        self.assertEqual(data["status"], "authorized")

        # Verifica persistência no banco
        dev = self.engine.storage.get_device("00:12:12:34:56:78")
        self.assertEqual(dev.status, DeviceStatus.AUTHORIZED)

    def test_api_verify_audit(self):
        status, content = self._get("/api/verify-audit")
        self.assertEqual(status, 200)
        data = json.loads(content.decode("utf-8"))
        self.assertTrue(data["is_valid"])


if __name__ == "__main__":
    unittest.main()
