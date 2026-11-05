"""
Testes Unitários para Trilha de Auditoria Criptográfica SHA-256 e Sanitização.
"""
import os
import shutil
import tempfile
import unittest

from core.security import AuditLedger, sanitize_ip, sanitize_mac


class TestSecurityAudit(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.ledger_file = os.path.join(self.test_dir, "test_ledger.jsonl")
        self.ledger = AuditLedger(self.ledger_file)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_sanitize_mac(self):
        self.assertEqual(sanitize_mac("00-11-22-33-44-55"), "00:11:22:33:44:55")
        self.assertEqual(sanitize_mac("AA:BB:CC:DD:EE:FF"), "aa:bb:cc:dd:ee:ff")
        self.assertIsNone(sanitize_mac("invalid_mac"))
        self.assertIsNone(sanitize_mac("00:11:22:33:44"))

    def test_sanitize_ip(self):
        self.assertEqual(sanitize_ip("192.168.1.100"), "192.168.1.100")
        self.assertEqual(sanitize_ip("10.0.0.1"), "10.0.0.1")
        self.assertIsNone(sanitize_ip("999.999.999.999"))
        self.assertIsNone(sanitize_ip("abc.def.ghi.jkl"))

    def test_immutable_ledger_integrity(self):
        # Grava 5 eventos encadeados
        for i in range(5):
            self.ledger.record_event(
                event_type=f"TEST_EVENT_{i}",
                source="UnitTests",
                severity="INFO",
                payload={"index": i, "data": f"sample_{i}"},
            )

        valid, err, count = self.ledger.verify_integrity()
        self.assertTrue(valid)
        self.assertIsNone(err)
        self.assertEqual(count, 5)

    def test_tamper_detection(self):
        # Grava 3 eventos
        for i in range(3):
            self.ledger.record_event(
                event_type=f"EVENT_{i}",
                source="UnitTests",
                severity="INFO",
                payload={"value": i},
            )

        # Simula um ataque alterando o conteúdo da 2ª linha no arquivo de log
        with open(self.ledger_file, "r", encoding="utf-8") as f:
            lines = f.readlines()

        # Altera tipo de evento da segunda linha para forçar erro de integridade de hash
        self.assertIn("EVENT_1", lines[1])
        lines[1] = lines[1].replace("EVENT_1", "EVENT_TAMPERED")

        with open(self.ledger_file, "w", encoding="utf-8") as f:
            f.writelines(lines)

        # Verificação deve falhar e alertar adulteração
        valid, err, count = self.ledger.verify_integrity()
        self.assertFalse(valid)
        self.assertIn("Adulteração detectada", err)


if __name__ == "__main__":
    unittest.main()
