# Update the OpenVPN Control UI

**For existing Debian 13 OpenVPN Control installations.** This command updates only the HTTPS web panel; it does **not** reinstall OpenVPN, change the VPN listening port, regenerate certificates, or modify router port forwarding.

Open a root shell (`su -`) and run:

```bash
wget -O /tmp/update-ui.sh https://raw.githubusercontent.com/MusMat17/OpenVPN-UI-server/main/update-ui.sh && bash /tmp/update-ui.sh
```

The update script downloads the current published Linux AMD64 binary, verifies its SHA-256 against the release checksum, backs up the previous panel binary and restarts **only** `openvpn-control.service`. If that service fails to restart, the script attempts to restore the previous executable.

The panel remains available at **https://YOUR_LAN_SERVER_IP:8989** (for example, `https://192.168.40.10:8989`).

The release is automatically rebuilt from `main` after UI changes. Re-run this same command to apply a later published update.

Source: [update-ui.sh](update-ui.sh) · [Releases](https://github.com/MusMat17/OpenVPN-UI-server/releases) · [Installation](README.md#installation)

Do not expose TCP/8989 directly to the internet.
