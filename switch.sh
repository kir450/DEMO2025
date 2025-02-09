#!/bin/bash
# Скрипт для настройки HQ-RTR (Debian 10) с Open vSwitch, DHCP-сервером и NAT

set -e

echo "=== Обновление списков пакетов и установка необходимых пакетов ==="
apt update
apt install -y openvswitch-switch isc-dhcp-server iptables-persistent

echo "=== Проверка имени хоста и исправление /etc/hosts (если необходимо) ==="
HOSTNAME=$(hostname)
if ! grep -q "$HOSTNAME" /etc/hosts; then
    echo "127.0.1.1 $HOSTNAME" >> /etc/hosts
    echo "Добавлена запись в /etc/hosts: 127.0.1.1 $HOSTNAME"
fi

echo "=== Включение и запуск службы Open vSwitch ==="
systemctl enable --now openvswitch-switch

echo "=== Создание виртуального моста и настройка VLAN ==="
# Создаём виртуальный мост hq-sw
ovs-vsctl add-br hq-sw

# Добавляем физические интерфейсы с тегированием:
# ens4 для VLAN 100 (подключение HQ-SRV),
# ens5 для VLAN 200 (подключение HQ-CLI),
# ens6 для VLAN 999 (подсеть управления).
ovs-vsctl add-port hq-sw ens4 tag=100
ovs-vsctl add-port hq-sw ens5 tag=200
ovs-vsctl add-port hq-sw ens6 tag=999

# Добавляем внутренние (internal) порты для участия в VLAN
ovs-vsctl add-port hq-sw vlan100 tag=100 -- set interface vlan100 type=internal
ovs-vsctl add-port hq-sw vlan200 tag=200 -- set interface vlan200 type=internal
ovs-vsctl add-port hq-sw vlan999 tag=999 -- set interface vlan999 type=internal

# Включаем мост и внутренние интерфейсы
ip link set hq-sw up
ip link set vlan100 up
ip link set vlan200 up
ip link set vlan999 up

# Назначаем IP-адреса внутренним интерфейсам:
# VLAN 100 – 192.168.100.1/26 (шлюз для HQ-SRV)
# VLAN 200 – 192.168.100.65/28 (шлюз для HQ-CLI)
# VLAN 999 – 192.168.100.81/29 (подсеть управления)
ip addr add 192.168.100.1/26 dev vlan100 || true
ip addr add 192.168.100.65/28 dev vlan200 || true
ip addr add 192.168.100.81/29 dev vlan999 || true

echo "=== Создание скрипта для восстановления настроек Open vSwitch при перезагрузке ==="
cat << 'EOF' > /usr/local/sbin/ovs-persistent.sh
#!/bin/bash
# Удаляем существующий мост (если есть) для чистой конфигурации
ovs-vsctl --if-exists del-br hq-sw
ovs-vsctl add-br hq-sw

# Добавляем физические интерфейсы с нужными тегами
ovs-vsctl add-port hq-sw ens4 tag=100
ovs-vsctl add-port hq-sw ens5 tag=200
ovs-vsctl add-port hq-sw ens6 tag=999

# Добавляем внутренние порты с тегами VLAN
ovs-vsctl add-port hq-sw vlan100 tag=100 -- set interface vlan100 type=internal
ovs-vsctl add-port hq-sw vlan200 tag=200 -- set interface vlan200 type=internal
ovs-vsctl add-port hq-sw vlan999 tag=999 -- set interface vlan999 type=internal

# Включаем мост и внутренние интерфейсы
ip link set hq-sw up
ip link set vlan100 up
ip link set vlan200 up
ip link set vlan999 up

# Назначаем IP-адреса внутренним интерфейсам
ip addr add 192.168.100.1/26 dev vlan100 || true
ip addr add 192.168.100.65/28 dev vlan200 || true
ip addr add 192.168.100.81/29 dev vlan999 || true
EOF

chmod +x /usr/local/sbin/ovs-persistent.sh

echo "=== Создание systemd-сервиса для восстановления конфигурации при загрузке ==="
cat << 'EOF' > /etc/systemd/system/ovs-persistent.service
[Unit]
Description=Restore Open vSwitch configuration on boot
After=openvswitch-switch.service
Requires=openvswitch-switch.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/ovs-persistent.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable ovs-persistent.service
systemctl start ovs-persistent.service

echo "=== Настройка DHCP-сервера для VLAN 200 ==="
# Указываем интерфейс для DHCP (vlan200)
sed -i 's/^INTERFACES=.*/INTERFACES="vlan200"/' /etc/default/isc-dhcp-server

# Очищаем содержимое файла /etc/dhcp/dhcpd.conf и записываем новую конфигурацию
cat << 'EOF' > /etc/dhcp/dhcpd.conf
ddns-update-style none;
subnet 192.168.100.64 netmask 255.255.255.240 {
    range 192.168.100.66 192.168.100.78;
    option routers 192.168.100.65;
    option subnet-mask 255.255.255.240;
    option domain-name-servers 77.88.8.8, 8.8.8.8;
    option broadcast-address 192.168.100.79;
    default-lease-time 600;
    max-lease-time 7200;
}
EOF

systemctl restart isc-dhcp-server
systemctl enable isc-dhcp-server

echo "=== Включение IP-форвардинга ==="
if ! grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf; then
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
fi
sysctl -p

echo "=== Настройка NAT (MASQUERADE) для внешнего интерфейса ens3 ==="
iptables -t nat -A POSTROUTING -o ens3 -j MASQUERADE

echo "=== Установка iptables-persistent завершена ==="
echo "Настройка завершена."
echo "Не забудьте настроить HQ-SRV с статическим IP 192.168.100.2/26 и шлюзом 192.168.100.1."
