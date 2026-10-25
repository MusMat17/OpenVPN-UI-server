#!/usr/bin/env bash
# OpenVPN Control · Debian 13 installer · v0.1.0
# Uses only official Debian packages. Does not reconfigure the host IP or WAN router.
set -Eeuo pipefail
umask 077

fail(){ printf '\nERROR: %s\n' "$*" >&2; exit 1; }
ask(){ local prompt="$1" default="$2" var="$3" value; read -r -p "$prompt [$default]: " value < /dev/tty; printf -v "$var" '%s' "${value:-$default}"; }
valid_port(){ [[ "$1" =~ ^[0-9]{1,5}$ ]] && ((10#$1 > 0 && 10#$1 <= 65535)); }
valid_ip(){ python3 - "$1" <<'PY'
import ipaddress,sys
try: ipaddress.IPv4Address(sys.argv[1])
except ValueError: sys.exit(1)
PY
}
valid_net(){ python3 - "$1" <<'PY'
import ipaddress,sys
try: ipaddress.IPv4Network(sys.argv[1],strict=True)
except ValueError: sys.exit(1)
PY
}
valid_host(){ [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$ ]]; }

[[ $(id -u) -eq 0 ]] || fail 'Run as root: sudo bash install.sh'
[[ -r /etc/os-release ]] || fail 'Cannot identify OS'
. /etc/os-release
[[ "$ID" == debian && "$VERSION_ID" == 13 ]] || fail 'This installer targets Debian 13 only'
[[ $(uname -m) == x86_64 ]] || fail 'Precompiled distribution targets x86_64; build binary for other architectures'
[[ ! -e /etc/openvpn/server/server.conf ]] || fail 'Existing OpenVPN installation found. Refusing to overwrite. Use a fresh Debian VM.'
[[ ! -e /etc/openvpn-control/config.json ]] || fail 'OpenVPN Control already installed.'
command -v python3 >/dev/null || fail 'Python3 required for IP address validation (normally included on Debian 13)'
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
BIN="$SCRIPT_DIR/bin/openvpn-control-linux-amd64"
if [[ ! -x "$BIN" ]]; then
 command -v go >/dev/null || fail 'No prebuilt binary found in bin/. Download the distribution tar.gz or build on your workstation with go build.'
 echo 'Compiling OpenVPN Control locally...'
 (cd "$SCRIPT_DIR" && GOTOOLCHAIN=local CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o "$BIN" ./cmd/openvpn-control)
fi

echo '=== OpenVPN Control · Setup wizard ==='
echo 'Target: Debian 13, native OpenVPN, HTTPS panel'
ask 'IPv4 of this server in local network' '192.168.40.10' BIND_IP
valid_ip "$BIND_IP" || fail 'Invalid server IP'
ip -4 -o addr show | grep -q "inet $BIND_IP/" || fail "IP $BIND_IP is not configured on this server. Configure a static IP first."
NIC=$(ip -4 -o addr show | awk -v ip="$BIND_IP" '$4 ~ "^"ip"/" {print $2;exit}')
[[ -n "$NIC" && "$NIC" =~ ^[a-zA-Z0-9_.-]+$ ]] || fail 'Cannot detect network interface'
ask 'Target LAN network, routed through VPN ONLY' '192.168.40.0/24' LAN
valid_net "$LAN" || fail 'Invalid LAN network'
ask 'VPN subnet (must not overlap LAN)' '10.8.0.0/24' VPN_NET
valid_net "$VPN_NET" || fail 'Invalid VPN subnet'
python3 - "$LAN" "$VPN_NET" <<'PY' || fail 'LAN and VPN subnets overlap'
import ipaddress,sys
assert not ipaddress.ip_network(sys.argv[1]).overlaps(ipaddress.ip_network(sys.argv[2]))
PY
ask 'OpenVPN protocol: udp or tcp' 'udp' PROTO
PROTO=${PROTO,,}
[[ "$PROTO" == udp || "$PROTO" == tcp ]] || fail 'Protocol must be udp or tcp'
ask 'OpenVPN external port' '1194' VPN_PORT
valid_port "$VPN_PORT" || fail 'Invalid VPN port'
ask 'External public IP or DNS (for client .ovpn files)' '' PUBLIC_HOST
valid_host "$PUBLIC_HOST" || fail 'Invalid external address: enter IPv4 or DNS name without port'
PANEL_PORT=8989
[[ "$VPN_PORT" != "$PANEL_PORT" ]] || { [[ "$PROTO" == udp ]] || fail 'VPN TCP port and HTTPS panel TCP port cannot match'; }
if ss -Hlnptu | awk '{print $5}' | grep -Eq "(^|:)${VPN_PORT}$"; then fail "VPN port $VPN_PORT appears already in use"; fi
if ss -Hlnt | awk '{print $4}' | grep -Eq '(^|:)8989$'; then fail 'Panel TCP port 8989 is in use'; fi
read -r -s -p 'Admin password (min. 12 characters): ' ADMIN_PASSWORD < /dev/tty; echo
[[ ${#ADMIN_PASSWORD} -ge 12 ]] || fail 'Admin password is too short'
read -r -s -p 'Repeat admin password: ' ADMIN_PASSWORD2 < /dev/tty; echo
[[ "$ADMIN_PASSWORD" == "$ADMIN_PASSWORD2" ]] || fail 'Passwords do not match'
unset ADMIN_PASSWORD2

echo; echo "Network: $BIND_IP / $NIC, LAN $LAN, VPN $VPN_NET"
echo "OpenVPN: $PROTO/$VPN_PORT, public host $PUBLIC_HOST"
echo "Admin panel: https://$BIND_IP:$PANEL_PORT (LAN or via VPN)"
read -r -p 'Install on fresh server? [y/N] ' CONFIRM < /dev/tty
[[ "$CONFIRM" =~ ^[yY]$ ]] || fail 'Cancelled.'

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends openvpn easy-rsa openssl nftables ca-certificates
install -d -m 0755 /etc/openvpn-control /etc/openvpn/server /etc/openvpn-control/easy-rsa /var/lib/openvpn-control /usr/local/libexec/openvpn-control
install -d -m 0700 /etc/openvpn-control/tls
install -m 0755 "$BIN" /usr/local/bin/openvpn-control
# The app stores confidential metadata in root-only files; the blocked list needs read access by OpenVPN's 'nobody'.
install -m 0644 /dev/null /var/lib/openvpn-control/disabled.list
cp -a /usr/share/easy-rsa/. /etc/openvpn-control/easy-rsa/
chmod 0755 /etc/openvpn-control/easy-rsa/easyrsa
cd /etc/openvpn-control/easy-rsa
export EASYRSA_BATCH=1 EASYRSA_PKI=/etc/openvpn-control/easy-rsa/pki EASYRSA_REQ_CN='OpenVPN-Control-CA'
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
chmod 0700 /etc/openvpn-control/easy-rsa/pki/private

NET_IP=${VPN_NET%/*}
VPN_MASK=$(python3 - "$VPN_NET" <<'PY'
import ipaddress,sys
print(ipaddress.ip_network(sys.argv[1]).netmask)
PY
)
LAN_IP=${LAN%/*}
LAN_MASK=$(python3 - "$LAN" <<'PY'
import ipaddress,sys
print(ipaddress.ip_network(sys.argv[1]).netmask)
PY
)
# Use dev tun0 so nft rules and management are deterministic.
if [[ "$PROTO" == tcp ]]; then SERVER_PROTO='tcp-server'; else SERVER_PROTO='udp4'; fi
cat >/etc/openvpn/server/server.conf <<EOF_CONF
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
EOF_CONF
if [[ "$PROTO" == udp ]]; then printf 'explicit-exit-notify 1\n' >> /etc/openvpn/server/server.conf; fi

cat > /usr/local/libexec/openvpn-control/client-connect.sh <<'EOF_HOOK'
#!/bin/sh
# Reject revoked-by-policy clients at connect time; `disable` is reversible.
BLOCKLIST=/var/lib/openvpn-control/disabled.list
[ -r "$BLOCKLIST" ] || exit 1
[ -n "${common_name:-}" ] || exit 1
if grep -Fxq -- "$common_name" "$BLOCKLIST"; then exit 1; fi
exit 0
EOF_HOOK
chmod 0755 /usr/local/libexec/openvpn-control/client-connect.sh

cat >/etc/sysctl.d/60-openvpn-control.conf <<'EOF_SYS'
net.ipv4.ip_forward=1
EOF_SYS
sysctl -w net.ipv4.ip_forward=1 >/dev/null

# Firewall: reject other destinations; NAT only LAN subnet; allow HTTPS panel only from LAN/VPN.
cat > /etc/openvpn-control/firewall.nft <<EOF_NFT
table ip openvpn_control {
 chain protect_panel {
  type filter hook input priority -10; policy accept;
  tcp dport $PANEL_PORT iifname "lo" accept
  tcp dport $PANEL_PORT iifname "tun0" ip saddr $VPN_NET accept
  tcp dport $PANEL_PORT iifname "$NIC" ip saddr $LAN accept
  tcp dport $PANEL_PORT drop
  iifname "tun0" ip saddr $VPN_NET drop
 }
 chain lan_only {
  type filter hook forward priority -10; policy accept;
  iifname "tun0" ip saddr $VPN_NET ip daddr != $LAN drop
 }
 chain to_lan {
  type nat hook postrouting priority srcnat; policy accept;
  iifname "tun0" oifname "$NIC" ip saddr $VPN_NET ip daddr $LAN masquerade
 }
}
EOF_NFT
cat >/usr/local/libexec/openvpn-control/firewall-load.sh <<'EOF_FW'
#!/bin/sh
set -eu
/usr/sbin/nft delete table ip openvpn_control 2>/dev/null || true
exec /usr/sbin/nft -f /etc/openvpn-control/firewall.nft
EOF_FW
chmod 0755 /usr/local/libexec/openvpn-control/firewall-load.sh
cat >/etc/systemd/system/openvpn-control-firewall.service <<'EOF_SYSTEM_FW'
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
EOF_SYSTEM_FW
mkdir -p /etc/systemd/system/openvpn-server@server.service.d
cat >/etc/systemd/system/openvpn-server@server.service.d/10-control.conf <<'EOF_ORDER'
[Unit]
Requires=openvpn-control-firewall.service
After=openvpn-control-firewall.service
EOF_ORDER

openssl req -newkey rsa:2048 -nodes -x509 -days 3650 \
 -subj "/CN=$BIND_IP" -addext "subjectAltName=IP:$BIND_IP" \
 -keyout /etc/openvpn-control/tls/server.key -out /etc/openvpn-control/tls/server.crt >/dev/null 2>&1
chmod 0600 /etc/openvpn-control/tls/server.key
chmod 0644 /etc/openvpn-control/tls/server.crt
ADMIN_HASH=$(printf '%s\n' "$ADMIN_PASSWORD" | /usr/local/bin/openvpn-control hash-password)
unset ADMIN_PASSWORD
cat >/etc/openvpn-control/config.json <<EOF_JSON
{
 "bind_ip":"$BIND_IP", "port":8989, "vpn_port":$VPN_PORT,
 "vpn_proto":"$PROTO", "vpn_host":"$PUBLIC_HOST",
 "lan":"$LAN", "vpn_net":"$VPN_NET",
 "cert_file":"/etc/openvpn-control/tls/server.crt",
 "key_file":"/etc/openvpn-control/tls/server.key",
 "admin_hash":"$ADMIN_HASH"
}
EOF_JSON
chmod 0600 /etc/openvpn-control/config.json
unset ADMIN_HASH

cat >/etc/systemd/system/openvpn-control.service <<'EOF_CONTROL'
[Unit]
Description=OpenVPN Control web administration
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
LimitNOFILE=2048
[Install]
WantedBy=multi-user.target
EOF_CONTROL

systemctl daemon-reload
systemctl enable --now openvpn-control-firewall.service
systemctl enable --now openvpn-server@server.service
systemctl enable --now openvpn-control.service
systemctl is-active --quiet openvpn-server@server.service || fail 'OpenVPN service failed (journalctl -u openvpn-server@server)'
systemctl is-active --quiet openvpn-control.service || fail 'Panel service failed (journalctl -u openvpn-control)'
echo
echo '========================================='
echo "OpenVPN : $PROTO/$VPN_PORT"
echo "HTTPS UI: https://$BIND_IP:8989"
echo 'Admin   : admin'
echo 'Public router: forward selected VPN TCP/UDP port to server IP'
echo 'Browser: self-signed TLS certificate; trust only after fingerprint verification'
echo '========================================='
