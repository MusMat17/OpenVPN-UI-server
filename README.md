# OpenVPN UI Server

Open-source OpenVPN server installer and lightweight web admin panel for Debian 13.

Development is ongoing in the [`feature/openvpn-control-hyperos4`](../../tree/feature/openvpn-control-hyperos4) branch. This is experimental software: do not deploy to a production VPN server before testing.

The installer will let administrators choose UDP or TCP, the VPN port, and will provide an HTTPS admin interface on TCP port 8989. It is designed for split tunneling, certificate expiry selection, per-client notes, revocation and temporary blocking.

The web interface is HyperOS-inspired and is not affiliated with Xiaomi.
