"""
Testes Unitários para o Resolvedor OUI Expandido.
"""
import unittest
from adapters.oui_resolver import OUIResolver


class TestOUIResolver(unittest.TestCase):
    def setUp(self):
        self.resolver = OUIResolver()

    def test_known_cctv_vendors(self):
        self.assertEqual(self.resolver.lookup("00:12:12:ab:cd:ef"), "Intelbras")
        self.assertEqual(self.resolver.lookup("b8:a4:4f:11:22:33"), "Hikvision")
        self.assertEqual(self.resolver.lookup("3c:ef:8c:aa:bb:cc"), "Dahua Technology")
        self.assertEqual(self.resolver.lookup("00:40:8c:01:02:03"), "Axis Communications")

    def test_known_networking_vendors(self):
        self.assertEqual(self.resolver.lookup("00:00:0c:99:88:77"), "Cisco")
        self.assertEqual(self.resolver.lookup("00:0c:42:55:66:77"), "MikroTik")
        self.assertEqual(self.resolver.lookup("00:27:22:11:22:33"), "Ubiquiti Networks")
        self.assertEqual(self.resolver.lookup("00:09:0f:44:55:66"), "Fortinet")

    def test_unknown_vendor_fallback(self):
        self.assertEqual(self.resolver.lookup("ff:00:11:22:33:44"), "Fabricante desconhecido")
        self.assertEqual(self.resolver.lookup(""), "Fabricante desconhecido")


if __name__ == "__main__":
    unittest.main()
