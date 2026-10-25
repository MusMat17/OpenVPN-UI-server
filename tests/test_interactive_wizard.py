"""Regression: installer must re-prompt rather than abort on wrong answers."""
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
TEXT = (ROOT / 'install.sh').read_text()


@unittest.skipUnless(shutil.which('script'), 'util-linux script is required for PTY test')
class WizardTests(unittest.TestCase):
    def test_invalid_entries_are_reprompted_and_tcp_is_accepted(self):
        # Execute only the validation wizard, never package installation.
        helpers = TEXT[:TEXT.index('[[ $(id -u)')]
        begin = TEXT.index("echo '=== OpenVPN Control · Setup wizard ==='")
        end = TEXT.index('export DEBIAN_FRONTEND=noninteractive', begin)
        wizard = TEXT[begin:end]
        with tempfile.TemporaryDirectory() as td:
            temp = pathlib.Path(td)
            fake_bin = temp / 'bin'
            fake_bin.mkdir()
            for executable, script_text in {
                'ip': '#!/bin/sh\necho "2: eth0 inet 192.168.40.10/24 scope global"\n',
                'ss': '#!/bin/sh\nexit 0\n',
            }.items():
                path = fake_bin / executable
                path.write_text(script_text)
                path.chmod(0o755)
            test_script = temp / 'wizard.sh'
            test_script.write_text(helpers + wizard + '\nprintf "RESULT=%s/%s\n" "$PROTO" "$VPN_PORT"\n')
            entries = [
                '',                  # server IP: default
                '',                  # LAN: default
                '192.168.40.0/24',   # invalid overlapping VPN net
                '',                  # VPN net: default
                'wrong',             # invalid protocol
                '  TCP  ',           # trim whitespace and allow uppercase
                '99999',             # invalid port
                '8989',              # reserved HTTPS port on TCP
                '443',               # valid TCP VPN port
                'vpn.example.org',
                'short',             # invalid admin password
                'longpassword1234',
                'longpassword4321',   # confirmation mismatch
                'longpassword1234',
                'longpassword1234',
                'maybe',             # invalid confirmation
                'y',
            ]
            env = dict(os.environ, PATH=f'{fake_bin}:{os.environ["PATH"]}')
            completed = subprocess.run(
                ['script', '-q', '-e', '-c', f'bash {test_script}', '/dev/null'],
                input='\n'.join(entries) + '\n', text=True,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                timeout=15, env=env,
            )
            self.assertEqual(completed.returncode, 0, completed.stdout)
            self.assertIn('RESULT=tcp/443', completed.stdout)
            self.assertGreaterEqual(completed.stdout.count('Invalid value:'), 6)


if __name__ == '__main__':
    unittest.main()
