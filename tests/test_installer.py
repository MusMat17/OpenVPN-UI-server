import pathlib,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
SCRIPT=(ROOT/"install.sh").read_text()
class InstallerTests(unittest.TestCase):
 def test_choices(self):
  self.assertIn('OpenVPN protocol (udp/tcp)',SCRIPT)
  self.assertIn('OpenVPN port',SCRIPT)
  self.assertIn('SERVER_PROTO=tcp-server',SCRIPT)
  self.assertIn('SERVER_PROTO=udp4',SCRIPT)
 def test_routes(self):
  self.assertIn('push "route $LAN_IP $LAN_MASK"',SCRIPT)
  self.assertIn('ip daddr != $LAN drop',SCRIPT)
  self.assertIn('ip daddr $LAN masquerade',SCRIPT)
  self.assertNotIn('redirect-gateway',SCRIPT)
 def test_panel(self):
  self.assertIn('tcp dport 8989',SCRIPT)
  self.assertIn('NoNewPrivileges=true',SCRIPT)
 def test_no_overwrite(self):
  self.assertIn('Existing OpenVPN installation detected',SCRIPT)
if __name__=="__main__":unittest.main()
