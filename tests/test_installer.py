import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
TEXT = (ROOT / 'install.sh').read_text()

class InstallerStaticTests(unittest.TestCase):
    def test_interactive_proto_and_port(self):
        self.assertIn("OpenVPN protocol: udp or tcp", TEXT)
        self.assertIn("OpenVPN external port", TEXT)
        self.assertIn("SERVER_PROTO='tcp-server'", TEXT)
        self.assertIn("SERVER_PROTO='udp4'", TEXT)
    def test_split_tunnel(self):
        self.assertIn('push "route $LAN_IP $LAN_MASK"', TEXT)
        self.assertIn('ip daddr != $LAN drop', TEXT)
        self.assertIn('ip daddr $LAN masquerade', TEXT)
        self.assertNotIn('redirect-gateway', TEXT)
    def test_admin_tls_port(self):
        self.assertIn('PANEL_PORT=8989', TEXT)
        self.assertIn('NoNewPrivileges=true', TEXT)
        self.assertIn('https://$BIND_IP:$PANEL_PORT', TEXT)
    def test_existing_vpn_not_overwritten(self):
        self.assertIn('Existing OpenVPN installation found. Refusing to overwrite.', TEXT)

if __name__ == '__main__': unittest.main()
