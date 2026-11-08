"""
Testes de Integração para BastionCoreEngine.
"""
import os
import shutil
import tempfile
import unittest

from config.settings import BastionConfig, AgentSettings, SecuritySettings, NotificationSettings, StorageSettings
from core.engine import BastionCoreEngine


class TestBastionEngine(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        config = BastionConfig(
            agent=AgentSettings(
                target_ip="127.0.0.1",
                base_subnet="127.0.0.0/24",
                ping_interval_seconds=1,
                arp_scan_interval_multiplier=1,
            ),
            security=SecuritySettings(
                enable_immutable_audit_log=True,
                auto_authorize_baseline_on_first_run=True,
            ),
            notifications=NotificationSettings(
                webhook_url="",
                enable_syslog=True,
            ),
            storage=StorageSettings(
                base_dir=self.test_dir,
                db_filename="test_engine_inventory.db",
                audit_log_filename="test_engine_audit.jsonl",
                system_log_filename="test_engine_system.log",
            ),
        )
        self.engine = BastionCoreEngine(config)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_single_scan_and_audit_verification(self):
        # Executa scan único
        count = self.engine.run_single_scan()
        self.assertIsInstance(count, int)

        # Valida integridade do ledger
        is_valid = self.engine.verify_ledger_integrity()
        self.assertTrue(is_valid)


if __name__ == "__main__":
    unittest.main()
