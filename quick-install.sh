#!/usr/bin/env bash
# OpenVPN Control public bootstrap for clean Debian 13 (amd64).
# Usage: bash <(wget -qO- https://raw.githubusercontent.com/MusMat17/OpenVPN-UI-server/main/quick-install.sh)
set -Eeuo pipefail
umask 077
if [[ $(id -u) -ne 0 ]]; then
  echo 'ERROR: Start a root shell first: su -' >&2
  exit 1
fi
for cmd in wget tar mktemp sha256sum; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "ERROR: $cmd is required" >&2; exit 1; }
done
[[ -r /etc/os-release ]] || { echo 'ERROR: /etc/os-release not found' >&2; exit 1; }
. /etc/os-release
[[ "$ID" == debian && "$VERSION_ID" == 13 && $(uname -m) == x86_64 ]] || {
  echo 'ERROR: This installer targets Debian 13 amd64 only.' >&2
  exit 1
}
TMP_DIR=$(mktemp -d /tmp/openvpn-control.XXXXXXXX)
trap 'rm -rf "$TMP_DIR"' EXIT
ARCHIVE_URL='https://github.com/MusMat17/OpenVPN-UI-server/archive/refs/heads/main.tar.gz'
echo 'Downloading OpenVPN Control from GitHub...'
wget -q --https-only --timeout=30 --tries=3 -O "$TMP_DIR/source.tar.gz" "$ARCHIVE_URL" || {
  echo 'ERROR: Cannot download GitHub archive (check DNS/internet).' >&2
  exit 1
}
mkdir -p "$TMP_DIR/source"
tar -xzf "$TMP_DIR/source.tar.gz" --strip-components=1 -C "$TMP_DIR/source"
[[ -f "$TMP_DIR/source/install.sh" ]] || { echo 'ERROR: install.sh missing in repository.' >&2; exit 1; }
[[ -f "$TMP_DIR/source/assets/bin.part00" ]] || {
  echo 'ERROR: prebuilt panel archive missing; refusing to compile on a low-memory server.' >&2
  exit 1
}
cat "$TMP_DIR"/source/assets/bin.part* | tar -xz -C "$TMP_DIR/source"
expected='704feb747bf3faaa0602c39623f0f744d4b232cd0565fe0e08b7beece0ef7e4b'
printf '%s  %s\n' "$expected" "$TMP_DIR/source/bin/openvpn-control-linux-amd64" | sha256sum -c - >/dev/null || {
  echo 'ERROR: prebuilt binary checksum mismatch.' >&2
  exit 1
}
chmod 700 "$TMP_DIR/source/bin/openvpn-control-linux-amd64"
bash "$TMP_DIR/source/install.sh"
