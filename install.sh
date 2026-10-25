#!/usr/bin/env bash
# OpenVPN Control 0.1.0-alpha - clean Debian 13 amd64 installer.
# Tested by static checks only; validate on a throwaway VM first.
set -Eeuo pipefail
umask 077
fail(){ echo "ERROR: $*" >&2; exit 1; }
ask(){ local label="$1" def="$2" var="$3" response=""; read -r -p "$label [$def]: " response </dev/tty; printf -v "$var" "%s" "$response"; if [[ -z "$response" ]]; then printf -v "$var" "%s" "$def"; fi; }
check_ip(){ python3 - "$1" <<'PY'
import ipaddress,sys
try: ipaddress.IPv4Address(sys.argv[1])
except ValueError: sys.exit(1)
PY
}
check_net(){ python3 - "$1" <<'PY'
import ipaddress,sys
try: ipaddress.IPv4Network(sys.argv[1],strict=True)
except ValueError: sys.exit(1)
PY
}
[[ "$(id -u)" == 0 ]] || fail "Run as root"
. /etc/os-release
[[ "$ID" == debian && "$VERSION_ID" == 13 ]] || fail "Only Debian 13 is supported"
[[ "$(uname -m)" == x86_64 ]] || fail "Only AMD64 is supported"
[[ ! -e /etc/openvpn/server/server.conf && ! -e /etc/openvpn-control/config.json ]] || fail "Existing OpenVPN installation detected; use fresh VM"
command -v python3 >/dev/null || fail "Python3 required"
command -v ip >/dev/null || fail "iproute2 required"
echo "OpenVPN Control · setup wizard (fresh Debian 13)"
ask "Server LAN IPv4" "192.168.40.10" BIND_IP
check_ip "$BIND_IP" || fail "Invalid IP"
NIC=$(ip -4 -o addr show | awk -v ip="$BIND_IP" '$4 ~ "^"ip"/" {print $2;exit}')
[[ -n "$NIC" && "$NIC" =~ ^[a-zA-Z0-9_.-]+$ ]] || fail "Set the server's static LAN address before installing"
ask "LAN reachable via VPN" "192.168.40.0/24" LAN
check_net "$LAN" || fail "Invalid LAN CIDR"
ask "VPN subnet" "10.8.0.0/24" VPN_NET
check_net "$VPN_NET" || fail "Invalid VPN CIDR"
python3 - "$LAN" "$VPN_NET" <<'PY' || fail "LAN overlaps VPN or invalid VPN prefix"
import ipaddress,sys
lan,vpn=(ipaddress.ip_network(n) for n in sys.argv[1:])
assert not lan.overlaps(vpn)
assert 16 <= vpn.prefixlen <= 29
assert vpn.is_private
PY
ask "OpenVPN protocol (udp/tcp)" "udp" PROTO
PROTO=$(printf "%s" "$PROTO" | tr '[:upper:]' '[:lower:]')
[[ "$PROTO" == udp || "$PROTO" == tcp ]] || fail "Choose udp or tcp"
ask "OpenVPN port" "1194" VPN_PORT
[[ "$VPN_PORT" =~ ^[0-9]{1,5}$ ]] || fail "Invalid port"
(( 10#$VPN_PORT > 0 && 10#$VPN_PORT <= 65535 )) || fail "Port out of range"
if [[ "$PROTO" == tcp && "$VPN_PORT" == 8989 ]]; then fail "8989 reserved for HTTPS panel"; fi
ask "Public IPv4 or DNS used by VPN clients" "" PUBLIC_HOST
[[ "$PUBLIC_HOST" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$ ]] || fail "Enter public IP/DNS without port"
if command -v ss >/dev/null; then
 ss -Hlnptu | awk '{print $5}' | grep -Eq "(^|:)$VPN_PORT$" && fail "VPN port in use"
 ss -Hlnt | awk '{print $4}' | grep -Eq '(^|:)8989$' && fail "HTTPS panel port in use"
fi
read -r -s -p "Admin password (minimum 12 chars): " ADMIN_PASSWORD </dev/tty; echo
[[ "$ADMIN_PASSWORD" != "" && "$(printf "%s" "$ADMIN_PASSWORD" | wc -c)" -ge 12 ]] || fail "Password too short"
read -r -s -p "Repeat password: " PASSWORD2 </dev/tty; echo
[[ "$ADMIN_PASSWORD" == "$PASSWORD2" ]] || fail "Passwords differ"
unset PASSWORD2
echo "Server: $BIND_IP ($NIC); LAN: $LAN; VPN: $VPN_NET; OpenVPN: $PROTO/$VPN_PORT"
echo "Web UI: https://$BIND_IP:8989"
read -r -p "Install on fresh VM? [y/N] " CONFIRM </dev/tty
[[ "$CONFIRM" == y || "$CONFIRM" == Y ]] || fail "Cancelled"
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends openvpn easy-rsa openssl nftables ca-certificates curl
BIN_DIR=$(cd -- "$(dirname -- "$0")" && pwd)
BIN="$BIN_DIR/bin/openvpn-control-linux-amd64"
if [[ ! -x "$BIN" ]]; then
  RELEASE="https://github.com/MusMat17/OpenVPN-UI-server/releases/download/v0.1.0-alpha"
  TMP=$(mktemp -d)
  trap 'rm -rf "$TMP"' EXIT
  curl -fL --proto '=https' --tlsv1.2 "$RELEASE/openvpn-control-linux-amd64" -o "$TMP/openvpn-control-linux-amd64" || fail "No public build available yet"
  curl -fL --proto '=https' --tlsv1.2 "$RELEASE/SHA256SUMS" -o "$TMP/SHA256SUMS"
  (cd "$TMP" && sha256sum -c SHA256SUMS) || fail "Binary checksum mismatch"
  BIN="$TMP/openvpn-control-linux-amd64"
  chmod 0700 "$BIN"
fi
install -d -m 0755 /etc/openvpn-control /etc/openvpn/server /etc/openvpn-control/easy-rsa /var/lib/openvpn-control /usr/local/libexec/openvpn-control
install -d -m 0700 /etc/openvpn-control/tls
install -m 0755 "$BIN" /usr/local/bin/openvpn-control
install -m 0644 /dev/null /var/lib/openvpn-control/disabled.list
cp -a /usr/share/easy-rsa/. /etc/openvpn-control/easy-rsa/
chmod 0755 /etc/openvpn-control/easy-rsa/easyrsa
cd /etc/openvpn-control/easy-rsa
export EASYRSA_BATCH=1 EASYRSA_PKI=/etc/openvpn-control/easy-rsa/pki EASYRSA_REQ_CN=OpenVPN-Control-CA
./easyrsa init-pki
./easyrsa build-ca nopass
./easyrsa build-server-full server nopass
./easyrsa gen-crl
install -m 0644 pki/ca.crt /etc/openvpn/server/ca.crt
install -m 0644 pki/issued/server.crt /etc/openvpn/server/server.crt
install -m 0600 pki/private/server.key /etc/openvpn/server/server.key
install -m 0644 pki/crl.pem /etc/openvpn/server/crl.pem
openvpn --genkey secret /etc/openvpn/server/ta.key
chmod 0600 /etc/openvpn/server/ta.key
openssl rand -hex 32 > /etc/openvpn-control/management.pass
chmod 0600 /etc/openvpn-control/management.pass
NET_IP=$(python3 - "$VPN_NET" <<'PY'
import ipaddress,sys
print(ipaddress.ip_network(sys.argv[1]).network_address)
PY
)
VPN_MASK=$(python3 - "$VPN_NET" <<'PY'
import ipaddress,sys
print(ipaddress.ip_network(sys.argv[1]).netmask)
PY
)
LAN_IP=$(python3 - "$LAN" <<'PY'
import ipaddress,sys
print(ipaddress.ip_network(sys.argv[1]).network_address)
PY
)
LAN_MASK=$(python3 - "$LAN" <<'PY'
import ipaddress,sys
print(ipaddress.ip_network(sys.argv[1]).netmask)
PY
)
SERVER_PROTO=udp4
if [[ "$PROTO" == tcp ]]; then SERVER_PROTO=tcp-server; fi
cat >/etc/openvpn/server/server.conf <<EOF
local $BIND_IP
port $VPN_PORT
proto $SERVER_PROTO
dev tun0
topology subnet
server $NET_IP $VPN_MASK
push "route $LAN_IP $LAN_MASK"
ca /etc/openvpn/server/ca.crt
cert /etc/openvpn/server/server.crt
key /etc/openvpn/server/server.key
crl-verify /etc/openvpn/server/crl.pem
tls-crypt /etc/openvpn/server/ta.key
dh none
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305
tls-version-min 1.2
keepalive 10 120
persist-key
persist-tun
user nobody
group nogroup
script-security 2
client-connect /usr/local/libexec/openvpn-control/client-connect.sh
management 127.0.0.1 2080 /etc/openvpn-control/management.pass
verb 3
EOF
if [[ "$PROTO" == udp ]]; then echo "explicit-exit-notify 1" >>/etc/openvpn/server/server.conf; fi
cat >/usr/local/libexec/openvpn-control/client-connect.sh <<'EOF'
#!/bin/sh
BLOCKLIST=/var/lib/openvpn-control/disabled.list
[ -r "$BLOCKLIST" ] || exit 1
[ -n "$common_name" ] || exit 1
grep -Fxq -- "$common_name" "$BLOCKLIST" && exit 1
exit 0
EOF
chmod 0755 /usr/local/libexec/openvpn-control/client-connect.sh
echo "net.ipv4.ip_forward=1" >/etc/sysctl.d/60-openvpn-control.conf
sysctl -w net.ipv4.ip_forward=1 >/dev/null
cat >/etc/openvpn-control/firewall.nft <<EOF
table ip openvpn_control {
 chain protect_panel {
  type filter hook input priority -10; policy accept;
  tcp dport 8989 iifname "lo" accept
  tcp dport 8989 iifname "tun0" ip saddr $VPN_NET accept
  tcp dport 8989 iifname "$NIC" ip saddr $LAN accept
  tcp dport 8989 drop
  iifname "tun0" drop
 }
 chain lan_only {
  type filter hook forward priority -10; policy accept;
  iifname "tun0" ip saddr != $VPN_NET drop
  iifname "tun0" ip daddr != $LAN drop
 }
 chain to_lan {
  type nat hook postrouting priority srcnat; policy accept;
  iifname "tun0" oifname "$NIC" ip saddr $VPN_NET ip daddr $LAN masquerade
 }
}
EOF
cat >/usr/local/libexec/openvpn-control/firewall-load.sh <<'EOF'
#!/bin/sh
set -eu
/usr/sbin/nft delete table ip openvpn_control 2>/dev/null || true
exec /usr/sbin/nft -f /etc/openvpn-control/firewall.nft
EOF
chmod 0755 /usr/local/libexec/openvpn-control/firewall-load.sh
cat >/etc/systemd/system/openvpn-control-firewall.service <<'EOF'
[Unit]
Description=OpenVPN Control scoped nftables firewall
After=network-online.target
Before=openvpn-server@server.service
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/local/libexec/openvpn-control/firewall-load.sh
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
EOF
mkdir -p /etc/systemd/system/openvpn-server@server.service.d
cat >/etc/systemd/system/openvpn-server@server.service.d/10-control.conf <<'EOF'
[Unit]
Requires=openvpn-control-firewall.service
After=openvpn-control-firewall.service
EOF
openssl req -newkey rsa:2048 -nodes -x509 -days 3650 -subj "/CN=$BIND_IP" -addext "subjectAltName=IP:$BIND_IP" -keyout /etc/openvpn-control/tls/server.key -out /etc/openvpn-control/tls/server.crt >/dev/null 2>&1
chmod 0600 /etc/openvpn-control/tls/server.key
chmod 0644 /etc/openvpn-control/tls/server.crt
HASH=$(printf "%s\n" "$ADMIN_PASSWORD" | /usr/local/bin/openvpn-control hash-password)
unset ADMIN_PASSWORD
cat >/etc/openvpn-control/config.json <<EOF
{
 "bind_ip":"$BIND_IP", "port":8989, "vpn_port":$VPN_PORT,
 "vpn_proto":"$PROTO", "vpn_host":"$PUBLIC_HOST",
 "lan":"$LAN", "vpn_net":"$VPN_NET",
 "cert_file":"/etc/openvpn-control/tls/server.crt",
 "key_file":"/etc/openvpn-control/tls/server.key",
 "admin_hash":"$HASH"
}
EOF
chmod 0600 /etc/openvpn-control/config.json
unset HASH
cat >/etc/systemd/system/openvpn-control.service <<'EOF'
[Unit]
Description=OpenVPN Control web admin
After=network-online.target openvpn-server@server.service
Requires=openvpn-server@server.service
[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/local/bin/openvpn-control
WorkingDirectory=/var/lib/openvpn-control
UMask=0077
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/etc/openvpn-control/easy-rsa/pki /etc/openvpn/server /var/lib/openvpn-control
ProtectHome=true
ProtectKernelTunables=true
ProtectControlGroups=true
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now openvpn-control-firewall.service
systemctl enable --now openvpn-server@server.service
systemctl enable --now openvpn-control.service
systemctl is-active --quiet openvpn-server@server.service || fail "OpenVPN failed; inspect journal"
systemctl is-active --quiet openvpn-control.service || fail "Panel failed; inspect journal"
echo "OpenVPN: $PROTO/$VPN_PORT"
echo "Web UI: https://$BIND_IP:8989 (admin)"
echo "Router: forward only selected OpenVPN port and protocol to this server"
