"""
Testes Unitários para o Adaptador NetworkProbe.
"""
import unittest
from adapters.network_probe import NetworkProbe


class TestNetworkProbe(unittest.TestCase):
    def setUp(self):
        self.probe = NetworkProbe(target_ip="127.0.0.1", ping_timeout_ms=500)

    def test_detect_active_interface(self):
        iface = self.probe.detect_active_interface()
        self.assertIsNotNone(iface.ip_address)
        self.assertIn("/", iface.cidr_subnet)

    def test_subnet_cidr_discovery(self):
        subnet = self.probe._discover_subnet_cidr("192.168.10.45")
        self.assertEqual(subnet, "192.168.10.0/24")

        subnet_class_a = self.probe._discover_subnet_cidr("10.50.1.200")
        self.assertEqual(subnet_class_a, "10.50.1.0/24")

    def test_local_ping(self):
        # Ping em localhost deve responder com sucesso
        result = self.probe.ping("127.0.0.1", timeout_ms=1000)
        self.assertTrue(result)


if __name__ == "__main__":
    unittest.main()
