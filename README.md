# OpenVPN Control · OpenVPN UI Server

> **ALPHA / experimental.** For a fresh Debian 13 test VM only. The clean-VM integration/security audit is not finished. Do not run over an existing OpenVPN installation. This community project is not affiliated with Xiaomi or OpenVPN Inc.

Лёгкий OpenVPN 2.6 + HTTPS-панель в современной визуальной стилистике Xiaomi HyperOS (вдохновение, без копирования логотипов и фирменных компонентов).

**Целевая ОС:** чистая Debian 13 (amd64), виртуальная машина Hyper-V. **Не запускайте поверх существующей установки OpenVPN.**

## Возможности

- Интерактивная установка: **TCP или UDP** и произвольный **порт OpenVPN 1–65535**.
- Веб-панель: **HTTPS `192.168.40.10:8989`** (адрес сервера можно выбрать).
- Split Tunnel: через VPN только `192.168.40.0/24`, интернет клиентов напрямую через их провайдера. NAT ограничен локальной сетью.
- Создание клиентских X.509-сертификатов с настраиваемым сроком действия в днях (1–3650).
- Комментарий к сертификату с возможностью последующего редактирования.
- Скачивание готового `.ovpn` с `tls-crypt`, без `tls-auth` и без `redirect-gateway`.
- Временное **отключение** клиента (запрет следующих подключений и попытка разорвать текущую сессию); **включение** обратно.
- **Удаление** клиента с отзывом сертификата, обновлением CRL и удалением приватного ключа на сервере. Это необратимо.
- Список клиентов, статус подключений из OpenVPN status-файла, журнал действий.
- TLS, серверные HTTP-сессии, CSRF-защита, ограничение попыток входа, защищённые cookies, PBKDF2-SHA256 для пароля.
- Один бинарник Go без Docker, JS-фреймворков, внешних CSS/JS CDN и постоянно работающей БД.

## Установка с GitHub на чистую Debian 13

Протестируйте сначала на новой виртуальной машине со снимком. На сервере необходимо заранее настроить статический IPv4, установить git и обеспечить интернет-доступ. Панель использует **HTTPS TCP 8989**, который **нельзя пробрасывать в интернет**.

```bash
apt-get update && apt-get install -y git
git clone --branch feature/openvpn-control-hyperos4 https://github.com/MusMat17/OpenVPN-UI-server.git
cd OpenVPN-UI-server
bash install.sh
```

Установщик спросит LAN IP, целевую сеть, VPN-сеть, **TCP или UDP**, VPN-порт (1–65535), внешний адрес сервера и пароль администратора. После подтверждения установит OpenVPN с маршрутом только в выбранную LAN, без перенаправления интернета клиентов.

При отсутствии локального бинарника скрипт скачает `v0.1.0-alpha` и `SHA256SUMS` из **GitHub Releases**, проверит контрольную сумму и только затем установит бинарник. До публикации успешного pre-release запуск установки не поддерживается. На Debian не требуется Go.

После установки: **https://LAN_IP:8989**, логин `admin`, пароль — из установщика. HTTPS-сертификат самоподписан, проверьте отпечаток:

```bash
openssl x509 -in /etc/openvpn-control/tls/server.crt -noout -fingerprint -sha256
```

На пограничном маршрутизаторе пробросьте **только выбранный порт TCP/UDP OpenVPN**, не 8989.

## Устройство и безопасность

- `/etc/openvpn/server/server.conf` — OpenVPN, один маршрут `push "route 192.168.40.0 255.255.255.0"`.
- `/etc/openvpn-control/firewall.nft` — разрешённый VPN forward только в LAN, scoped masquerade в LAN; административный веб-порт ограничен LAN/VPN.
- `/etc/openvpn-control/easy-rsa/pki` — свой CA, серверные и клиентские сертификаты, CRL. **Секретный ключ CA хранится на сервере**, чтобы панель могла выдавать сертификаты, доступ root-only.
- `/etc/openvpn/server/ta.key` — общий TLS-Crypt ключ.
- `/var/lib/openvpn-control/clients.json` — клиентские комментарии и статусы (root-only).
- `/var/lib/openvpn-control/disabled.list` — список временно заблокированных CN; скрипт `client-connect` отклоняет их новые подключения.
- `/var/lib/openvpn-control/audit.log` — журнал админ-действий.
- `/etc/openvpn-control/config.json` — параметры веб-приложения и хеш пароля (root-only).
- `/etc/openvpn-control/management.pass` — пароль управления OpenVPN (root-only).
- `openvpn-control.service`, `openvpn-control-firewall.service`, `openvpn-server@server.service` — systemd службы.

**Важно:** отзыв сертификата действует для новых подключений после обновления CRL; текущая сессия отключается через management API по возможности. При недоступности management API временно отключённый клиент может оставаться подключённым до реконнекта — проверьте Dashboard.

VPN-клиент может обращаться к LAN (например, `192.168.40.1`) и к панели на LAN IP сервера. Клиентские сети, совпадающие с целевой `192.168.40.0/24`, требуют отдельного решения конфликта маршрутов. В профили **не добавляются** публичный DNS и `redirect-gateway`. Контроль локальной Windows-брандмауэр/маршрутизации на конечных хостах необходим.

**Не применяйте проект на критическом production-сервере без стендовой проверки и аудита безопасности.** Это первая реализация, предназначенная для испытаний на новой ВМ.

## Операции

```bash
systemctl status openvpn-server@server openvpn-control --no-pager
journalctl -u openvpn-control -n 50 --no-pager
nft list table ip openvpn_control
ip -4 addr show tun0
```

Смена протокола/порта после установки требует одновременного обновления серверной конфигурации, параметров панели и проброса на маршрутизаторе; установленный протокол и порт **выбираются вручную при первичной установке**.

## Разработка и тесты

```bash
go test ./...
go vet ./...
bash -n install.sh
./build.sh
```

`./build.sh` создаёт статически собранный `bin/openvpn-control-linux-amd64`. Go нужен только при сборке, не на Debian. GitHub Actions запускает тесты и собирает Linux AMD64. Отдельный workflow публикует тестовый pre-release и SHA256SUMS после успешной сборки.

## Бэкап

Сохраните в защищённом хранилище `/etc/openvpn-control`, `/etc/openvpn/server` и `/var/lib/openvpn-control`. Не публикуйте эти директории в GitHub; в особенности `pki/private/`, `management.pass`, `config.json` и личные `.ovpn`.
## Лицензия и участие сообщества

MIT License. Issues и Pull Requests приветствуются. Код ветки `feature/openvpn-control-hyperos4` общедоступен, поскольку сам репозиторий публичный.
