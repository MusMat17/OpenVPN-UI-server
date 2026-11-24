#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
fail(){ echo "ERROR: $*" >&2; exit 1; }
[[ $(id -u) == 0 ]] || fail "Run as root"
for c in python3 openssl ss systemctl openvpn; do command -v "$c" >/dev/null || fail "Missing $c"; done
[[ $(uname -m) == x86_64 ]] || fail "Linux amd64 required"
for p in /etc/openvpn-control /var/lib/openvpn-control /usr/local/bin/openvpn-control /etc/systemd/system/openvpn-control.service; do [[ ! -e "$p" ]] || fail "Existing panel: $p"; done
base=/etc/openvpn/server
installer=/root/openvpn-install.sh
[[ -f "$installer" && ! -L "$installer" && -f "$base/server.conf" && -f "$base/client-template.txt" && -f "$base/easy-rsa/pki/index.txt" && -f "$base/easy-rsa/pki/private/ca.key" ]] || fail "Supported Angristan installation not found"
python3 - "$installer" <<'PY'
import os,sys,stat
s=os.lstat(sys.argv[1])
if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_mode & 0o022: sys.exit("Unsafe installer ownership or permissions")
PY
grep -q "github.com/angristan/openvpn-install" "$installer" || fail "Unsupported installer"
bash "$installer" client add --help | grep -- "--output" >/dev/null || fail "Unsupported CLI"
bash "$installer" client revoke --help | grep -- "--force" >/dev/null || fail "Unsupported CLI"
systemctl is-active --quiet openvpn-server@server.service || fail "OpenVPN inactive"
dir=$(cd "$(dirname "$0")" && pwd)
bin="$dir/bin/openvpn-control-linux-amd64"
[[ -x "$bin" ]] || fail "Build using bash build.sh or place CI binary in bin/"
[[ -z $(ss -Hlnt "sport = :8989") ]] || fail "TCP 8989 occupied"
mapfile -t settings < <(python3 - "$base" <<'PY'
import pathlib,sys,ipaddress,re
b=pathlib.Path(sys.argv[1])
def rows(p): return [l.split() for l in p.read_text().splitlines() if l.strip() and not l.lstrip().startswith(("#",";"))]
s=rows(b/"server.conf"); t=rows(b/"client-template.txt")
def one(rows,key):
    a=[r[1:] for r in rows if r[0]==key]
    if len(a)!=1: raise ValueError("Expected one "+key)
    return a[0]
m=one(s,"management"); remote=one(t,"remote"); proto=one(s,"proto")[0]
if len(m)!=2 or m[1]!="unix" or not m[0].startswith("/"): raise ValueError("Passwordless UNIX socket required")
if len(remote)!=2 or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}",remote[0]): raise ValueError("Unsupported remote")
if proto not in ("tcp","tcp-server","udp"): raise ValueError("Unsupported protocol")
if any(r[0] in ("auth-user-pass-verify","plugin","management-client-auth") for r in s): raise ValueError("Unsupported auth")
mode=b/"easy-rsa/AUTH_MODE_GENERATED"
if mode.exists() and mode.read_text().strip()!="pki": raise ValueError("PKI required")
net=ipaddress.IPv4Network("/".join(one(s,"server")))
print(m[0]);print(remote[0]);print(int(remote[1]));print("tcp" if proto.startswith("tcp") else "udp");print(int(one(s,"port")[0]));print(net)
PY
)
[[ ${#settings[@]} == 6 ]] || fail "Unsupported configuration"
socket=${settings[0]}
[[ -S "$socket" ]] || fail "Management socket missing"
echo "VPN configuration and firewall will remain unchanged. Panel listens on localhost only."
echo "Management socket permissions are not changed; review local access separately."
read -r -p "Directory containing existing .ovpn files (blank to skip): " source_dir </dev/tty
read -r -s -p "Panel admin password (minimum 12 characters): " pass </dev/tty; echo
(( ${#pass} >= 12 )) || fail "Password too short"
read -r -s -p "Repeat password: " again </dev/tty; echo
[[ "$pass" == "$again" ]] || fail "Passwords differ"
hash=$(printf "%s" "$pass" | "$bin" hash-password)
unset pass again
read -r -p "Install panel only? [y/N] " confirm </dev/tty
[[ "$confirm" == y || "$confirm" == Y ]] || fail "Cancelled"
install -d -m 0700 /etc/openvpn-control /etc/openvpn-control/tls /var/lib/openvpn-control /var/lib/openvpn-control/profiles
install -m 0755 "$bin" /usr/local/bin/openvpn-control
openssl req -x509 -newkey rsa:3072 -nodes -days 365 -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" -keyout /etc/openvpn-control/tls/server.key -out /etc/openvpn-control/tls/server.crt >/dev/null 2>&1
python3 - "$source_dir" "$base" <<'PY'
import pathlib,sys,re,ssl,os,stat
source,base=sys.argv[1:]
if source:
    for f in pathlib.Path(source).glob("*.ovpn"):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,47}",f.stem): continue
        st=f.lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_size>1048576: continue
        issued=pathlib.Path(base)/"easy-rsa/pki/issued"/(f.stem+".crt")
        if not issued.is_file(): continue
        a=re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",issued.read_text(),re.S)
        body=f.read_text()
        b=re.search(r"<cert>\s*(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)\s*</cert>",body,re.S)
        if not a or not b or ssl.PEM_cert_to_DER_cert(a[0])!=ssl.PEM_cert_to_DER_cert(b[1]): continue
        dest=pathlib.Path("/var/lib/openvpn-control/profiles")/f.name
        with os.fdopen(os.open(dest,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),"w") as out: out.write(body)
PY
HASH="$hash" python3 - "$installer" "$socket" "${settings[1]}" "${settings[2]}" "${settings[3]}" "${settings[4]}" "${settings[5]}" <<'PY'
import os,sys,json
installer,socket,host,external,proto,port,net=sys.argv[1:]
cfg=dict(backend="angristan",installer=installer,management_socket=socket,profile_dir="/var/lib/openvpn-control/profiles",bind_ip="127.0.0.1",port=8989,vpn_port=int(port),vpn_proto=proto,vpn_host=host,vpn_net=net,admin_hash=os.environ["HASH"],cert_file="/etc/openvpn-control/tls/server.crt",key_file="/etc/openvpn-control/tls/server.key")
with open("/etc/openvpn-control/config.json","w") as f: json.dump(cfg,f)
with open("/var/lib/openvpn-control/profile-settings.json","w") as f: json.dump(dict(external_host=host,external_port=int(external),verb=3),f)
PY
unset hash
cat >/etc/systemd/system/openvpn-control.service <<'UNIT'
[Unit]
Description=OpenVPN Control (Attach Mode)
After=network.target openvpn-server@server.service
[Service]
Type=simple
ExecStart=/usr/local/bin/openvpn-control
Restart=on-failure
UMask=0077
PrivateTmp=true
NoNewPrivileges=true
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now openvpn-control.service
systemctl is-active --quiet openvpn-control.service || fail "Panel failed; inspect journalctl -u openvpn-control"
echo "Panel installed. From workstation: ssh -L 8989:127.0.0.1:8989 user@server"
echo "Then open https://localhost:8989 (login admin). No VPN restart performed."
