"""
Testes Unitários para o Repositório SQLite Thread-Safe.
"""
import concurrent.futures
import os
import shutil
import tempfile
import unittest

from core.models import Device, DeviceStatus
from adapters.storage_sqlite import SQLiteDeviceRepository


class TestStorage(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, "test_inventory.db")
        self.repo = SQLiteDeviceRepository(self.db_path)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_upsert_and_retrieve(self):
        dev = Device(
            mac="00:11:22:33:44:55",
            ip="192.168.1.50",
            vendor="Intelbras",
            status=DeviceStatus.AUTHORIZED,
        )
        is_new = self.repo.upsert_device(dev)
        self.assertTrue(is_new)

        retrieved = self.repo.get_device("00:11:22:33:44:55")
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.ip, "192.168.1.50")
        self.assertEqual(retrieved.vendor, "Intelbras")

    def test_multithread_concurrency(self):
        """Valida que 30 threads paralelas executam escritas simultâneas sem falhas de lock."""
        def worker(thread_id: int):
            mac = f"00:11:22:33:44:{thread_id:02x}"
            dev = Device(
                mac=mac,
                ip=f"192.168.1.{thread_id}",
                vendor=f"Vendor_{thread_id}",
            )
            self.repo.upsert_device(dev)
            self.repo.mark_alert_sent(mac)

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(worker, i) for i in range(30)]
            for f in concurrent.futures.as_completed(futures):
                f.result()

        known = self.repo.get_known_macs()
        self.assertEqual(len(known), 30)

    def test_alert_deduplication(self):
        mac = "aa:bb:cc:dd:ee:ff"
        dev = Device(mac=mac, ip="192.168.1.80", status=DeviceStatus.UNKNOWN)
        self.repo.upsert_device(dev)

        self.assertTrue(self.repo.should_send_alert(mac, dedup_hours=24))
        self.repo.mark_alert_sent(mac)
        self.assertFalse(self.repo.should_send_alert(mac, dedup_hours=24))


if __name__ == "__main__":
    unittest.main()
