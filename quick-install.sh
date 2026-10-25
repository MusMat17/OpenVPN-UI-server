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
# Always use the latest published main-branch panel build rather than old
# prebuilt parts in the source tree. Verify against the release checksum.
RELEASE='https://github.com/MusMat17/OpenVPN-UI-server/releases/download/v0.1.0-alpha'
mkdir -p "$TMP_DIR/source/bin"
echo 'Downloading published OpenVPN Control build...'
wget -q --https-only --timeout=30 --tries=3 -O "$TMP_DIR/source/bin/openvpn-control-linux-amd64" "$RELEASE/openvpn-control-linux-amd64" || {
  echo 'ERROR: Cannot download OpenVPN Control release binary.' >&2
  exit 1
}
wget -q --https-only --timeout=30 --tries=3 -O "$TMP_DIR/source/bin/SHA256SUMS" "$RELEASE/SHA256SUMS" || {
  echo 'ERROR: Cannot download release checksums.' >&2
  exit 1
}
(cd "$TMP_DIR/source/bin" && sha256sum -c SHA256SUMS) || {
  echo 'ERROR: release binary checksum mismatch.' >&2
  exit 1
}
chmod 700 "$TMP_DIR/source/bin/openvpn-control-linux-amd64"
bash "$TMP_DIR/source/install.sh"
