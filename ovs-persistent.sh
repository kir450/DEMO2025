#!/bin/bash
# Удаляем существующий мост, если он есть, для чистой конфигурации
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
