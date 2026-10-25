#!/usr/bin/env bash
# OpenVPN Control: update web UI binary only, preserve VPN service, PKI and firewall.
set -Eeuo pipefail
[[ $(id -u) -eq 0 ]] || { echo 'ERROR: run as root (su -)' >&2; exit 1; }
[[ -x /usr/local/bin/openvpn-control && -f /etc/openvpn-control/config.json ]] || {
  echo 'ERROR: OpenVPN Control is not installed on this machine.' >&2; exit 1;
}
for cmd in wget sha256sum systemctl mktemp install cp mv; do
  command -v "$cmd" >/dev/null || { echo "ERROR: missing $cmd" >&2; exit 1; }
done
BASE=https://github.com/MusMat17/OpenVPN-UI-server/releases/download/v0.1.0-alpha
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
echo 'Downloading signed-channel HTTPS build and checksum...'
wget --https-only --tries=3 --timeout=30 -nv -O "$TMP/openvpn-control-linux-amd64" "$BASE/openvpn-control-linux-amd64"
wget --https-only --tries=3 --timeout=30 -nv -O "$TMP/SHA256SUMS" "$BASE/SHA256SUMS"
(cd "$TMP" && sha256sum -c SHA256SUMS) || { echo 'ERROR: downloaded binary checksum mismatch' >&2; exit 1; }
BACKUP="/usr/local/bin/openvpn-control.bak-$(date +%Y%m%d%H%M%S)"
install -m 755 /usr/local/bin/openvpn-control "$BACKUP"
install -m 755 "$TMP/openvpn-control-linux-amd64" /usr/local/bin/openvpn-control.new
mv -f /usr/local/bin/openvpn-control.new /usr/local/bin/openvpn-control
echo 'Restarting web UI only (OpenVPN server remains running)...'
if ! systemctl restart openvpn-control.service || ! systemctl is-active --quiet openvpn-control.service; then
  echo 'ERROR: update failed; restoring previous binary...' >&2
  cp -p "$BACKUP" /usr/local/bin/openvpn-control
  systemctl restart openvpn-control.service || true
  exit 1
fi
echo "SUCCESS: UI updated. Previous binary: $BACKUP"
echo 'Open https://192.168.40.10:8989/login and reload the page.'
