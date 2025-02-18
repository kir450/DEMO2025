# Офис HQ
Имя подсети | Количество адресов | IP адрес подсети  | Маска подсети      | Префикс маски | Диапазон адресов
----------- | ------------------ | ----------------- | ------------------ | ------------- | -------------------------------------
VLAN100     | 64                 | 192.168.100.0     | 255.255.255.192    | /26           | 192.168.100.1 - 192.168.100.62
VLAN200     | 16                 | 192.168.100.64    | 255.255.255.240    | /28           | 192.168.100.65 - 192.168.100.78
VLAN999     | 8                  | 192.168.100.80    | 255.255.255.248    | /29           | 192.168.100.81 - 192.168.100.86

# Офис BR
Имя подсети | Количество адресов | IP адрес подсети  | Маска подсети      | Префикс маски | Диапазон адресов
----------- | ------------------ | ----------------- | ------------------ | ------------- | -------------------------------------
HQ          | 32                 | 192.168.200.0     | 255.255.255.224    | /27           | 192.168.200.1 - 192.168.200.30

# Таблица адресации устройств
| Имя устройства | Интерфейс | IP-адрес          | Шлюз по умолчанию | Сеть                          |
|----------------|-----------|-------------------|-------------------|-------------------------------|
| ISP            | ens3      | DHCP              | -                 | Internet                      |
| ISP            | ens4      | 172.16.4.1/28     | -                 | ISP_HQ-RTR                    |
| ISP            | ens5      | 172.16.5.1/28     | -                 | ISP_BR-RTR                    |
| HQ-RTR         | ens3      | 172.16.4.2/28     | 172.16.4.1        | ISP_HQ-RTR                    |
| HQ-RTR         | ens4      | 192.168.100.1/26  | -                 | HQ-RTR_HQ-SRV (VLAN100)       |
| HQ-RTR         | ens5      | 192.168.100.65/28 | -                 | HQ-RTR_HQ-CLI (VLAN200)       |
| HQ-RTR         | ens6      | 192.168.100.81/29 | -                 | VLAN999                       |
| HQ-SRV         | ens3      | 192.168.100.2/26  | 192.168.100.1     | HQ-RTR_HQ-SRV                 |
| HQ-CLI         | ens3      | DHCP              | 192.168.100.65    | HQ-RTR_HQ-CLI                 |
| BR-RTR         | ens3      | 172.16.5.2/28     | 172.16.5.1        | ISP_BR-RTR                    |
| BR-RTR         | ens4      | 192.168.200.1/27  | -                 | BR-RTR_BR-SRV                 |
| BR-SRV         | ens3      | 192.168.200.2/27  | 192.168.200.1     | BR-RTR_BR-SRV                 |


# 1. Настройка имен устройств.

  1.1. Изменение файла /etc/hostname
*     sudo nano /etc/hostname

 
*     isp.au-team.irpo
*     hq-rtr.au-team.irpo
*     br-rtr.au-team.irpo
*     hq-srv.au-team.irpo
*     hq-cli.au-team.irpo
*     br-srv.au-team.irpo

  1.2. Изменение файла /etc/hosts

*     sudo nano /etc/hosts

*     127.0.1.1       isp.au-team.irpo
*     127.0.1.1       hq-rtr.au-team.irpo
*     127.0.1.1       hq-srv.au-team.irpo
*     127.0.1.1       hq-cli.au-team.irpo
*     127.0.1.1       br-rtr.au-team.irpo
*     127.0.1.1       br-srv.au-team.irpo

# 2. Задаем IP адреса сетевым интерфейсам согласно таблицы адресации, nmtui.

Настройка ISP

Internet-ISP ens3 auto
![image](https://github.com/user-attachments/assets/e012e0d8-bca7-4fe3-adcd-38017815dd89)

ISP_HQ-RTR ens4 172.16.4.1/28
![image](https://github.com/user-attachments/assets/7af6319a-6305-4a24-b929-16a23785aab2)

ISP_BR-RTR ens5 172.16.5.1/28
![image](https://github.com/user-attachments/assets/07e3d94e-56ac-418b-8c2b-aa2c48651acd)

Настройка HQ-RTR

ISP_HQ-RTR ens3 172.16.4.2/28 Шлюз 172.16.4.1 Серверы DNS 77.88.8.8
![image](https://github.com/user-attachments/assets/5e7d56e3-e297-4d39-a903-6f47030121fd)

Настройка ens4, ens5, ens6 будет произведена при настройке VLAN

Настройка HQ-SRV

HQ-RTR_HQ-SRV ens3 192.168.100.2/26 Шлюз 192.168.100.1 Серверы DNS 77.88.8.8
![image](https://github.com/user-attachments/assets/9d175cba-ea1b-4b82-82ff-760767cf0edb)


Настройка HQ-CLI

Получает IP – адрес по DHCP
![image](https://github.com/user-attachments/assets/b658b1f5-3131-4959-855f-11508b948bd7)


Настройка BR-RTR

ISP-BR-RTR ens3 172.16.5.2/28 Шлюз 172.16.5.1 Серверы DNS 77.88.8.8
![image](https://github.com/user-attachments/assets/fd020c4c-97a9-4134-b3b1-29a23fdaa1a6)

BR-RTR-BR-SRV ens4 192.168.200.1/27
![image](https://github.com/user-attachments/assets/b4d39c1d-2e3e-4525-99a9-5328e1ab0599)

Настройка BR-SRV
BR-RTR_BR-SRV ens3 192.168.200.2/27 Шлюз 192.168.200.1
![image](https://github.com/user-attachments/assets/fde2d2d3-d96d-4dfa-a8ab-54ade00a5f00)


Проверить результат настройки IP-адресов можно с помощью команд на выбор:
*     ip –c a
*     ip –c –br a

# Маршрутизация транзитных IP-пакетов

Включить пересылку пакетов между интерфейсами на ISP, HQ-RTR, BR-RTR.
*     nano /etc/sysctl.conf
net.ipv4.ip_forward=1
*     sysctl -p

# Настройка доступа в интернет с помощью iptables на ISP, HQ-RTR, BR-RTR.

*     iptables -t nat -A POSTROUTING -o ens3 -j MASQUERADE

Сохранение iptables‑правил

*     apt update

*     apt install iptables-persistent

Если впоследствии потребуется сохранить изменённые правила:

*     sudo iptables-save | sudo tee /etc/iptables/rules.v4

Проверка iptables‑правил:

*     sudo iptables -t nat -L -n -v

# Создание локальных учетных записей

Создание локальных учетных записей на серверах HQ-SRV и BR-SRV.

*     sudo useradd sshuser -u 1010 -U
*     sudo passwd sshuser
*     P@ssw0rd

Предоставление прав sudo без запроса пароля

*     sudo usermod -aG sudo sshuser

*     sudo visudo

*     sshuser ALL=(ALL) NOPASSWD: ALL

Создание пользователя net_admin на маршрутизаторах HQ‑RTR и BR‑RTR

*     sudo useradd net_admin -U

*     sudo passwd net_admin

*     P@$$word

Предоставление привилегий sudo без запроса пароля

*     sudo usermod -aG sudo net_admin

*     sudo visudo

*     net_admin ALL=(ALL) NOPASSWD: ALL


# Настройка на интерфейсе HQ-RTR в сторону офиса HQ виртуального коммутатора:

1. Установка необходимых пакетов

*     sudo apt update

*     sudo apt install -y openvswitch-switch isc-dhcp-server

2. Запуск и автозапуск службы Open vSwitch

*     sudo systemctl enable --now openvswitch-switch

3. Создание виртуального коммутатора (моста) и настройка VLAN

*     sudo ovs-vsctl add-br hq-sw

Добавляем физические интерфейсы с VLAN-тегированием:

*     sudo ovs-vsctl add-port hq-sw ens4 tag=100

*     sudo ovs-vsctl add-port hq-sw ens5 tag=200

*     sudo ovs-vsctl add-port hq-sw ens6 tag=999

3.2. Добавление внутренних портов (internal) для управления VLAN

*     sudo ovs-vsctl add-port hq-sw vlan100 tag=100 -- set interface vlan100 type=internal

*     sudo ovs-vsctl add-port hq-sw vlan200 tag=200 -- set interface vlan200 type=internal

*     sudo ovs-vsctl add-port hq-sw vlan999 tag=999 -- set interface vlan999 type=internal

3.3. Включение моста и внутренних интерфейсов

*     sudo ip link set hq-sw up

*     sudo ip link set vlan100 up

*     sudo ip link set vlan200 up

*     sudo ip link set vlan999 up

3.4. Назначение IP-адресов внутренним портам

*     sudo ip addr add 192.168.100.1/26 dev vlan100

*     sudo ip addr add 192.168.100.65/28 dev vlan200

*     sudo ip addr add 192.168.100.81/29 dev vlan999

4. Автоматизация сохранения настроек Open vSwitch после перезагрузки
   
4.1. Скрипт восстановления конфигурации
*     cd /usr/local/sbin
*     wget https://raw.githubusercontent.com/kir450/D/main/ovs-persistent.sh

Сохраните файл и сделайте его исполняемым:

*      sudo chmod +x ovs-persistent.sh

4.2. Создание systemd‑сервиса

/etc/systemd/system

*      wget https://raw.githubusercontent.com/kir450/D/main/ovs-persistent.service

Сохраните файл, затем выполните:

*      sudo systemctl daemon-reload

*      sudo systemctl enable ovs-persistent.service

*      sudo systemctl start ovs-persistent.service

Теперь при каждой загрузке системы скрипт автоматически восстановит нужную конфигурацию.

5. Настройка DHCP-сервера для VLAN 200 (для HQ‑CLI)

5.1. Указание интерфейса для DHCP

*      sudo nano /etc/default/isc-dhcp-server

INTERFACES="vlan200"

5.2. Конфигурация файла dhcpd.conf

*      sudo nano /etc/dhcp/dhcpd.conf

*      subnet 192.168.100.64 netmask 255.255.255.240 {
           range 192.168.100.66 192.168.100.78;
           option routers 192.168.100.65;
           option subnet-mask 255.255.255.240;
           option domain-name-servers 8.8.8.8, 8.8.4.4;
           option broadcast-address 192.168.100.79;
           default-lease-time 600;
           max-lease-time 7200;
      }

5.3. Перезапуск DHCP-сервера

*     sudo systemctl restart isc-dhcp-server

*     sudo systemctl enable isc-dhcp-server


# Настройка безопасного удаленного доступа на серверах HQ-SRV и BR-SRV

1. Настройка SSH-сервера на HQ-SRV и BR-SRV.
   
1.1. Редактирование файла конфигурации SSH

*     sudo nano /etc/ssh/sshd_config

Port 2024

Разрешение подключения только для пользователя sshuser:

AllowUsers sshuser

Ограничение количества попыток авторизации:

MaxAuthTries 2

Настройка баннера:

*     Banner /etc/ssh-banner

*     sudo nano /etc/ssh-banner
  
Впишите строку:
  
    ********************************************
    *                                          *
    *          Authorized access only          *
    *                                          *
    ********************************************
    
    
1.3. Перезапуск SSH-сервера

*     sudo systemctl restart sshd


Проверка настроек:

С другого устройства (например, с HQ‑CLI) выполните подключение к серверу по порту 2024:

ssh -p 2024 sshuser@<IP_адрес_сервера>


# GRE-туннель между HQ-RTR и BR-RTR

Настройка HQ-RTR

nmtui
![image](https://github.com/user-attachments/assets/91dae2e8-518d-46cd-ba7d-78894d895776)


Для корректной работы протокола динамической маршрутизации требуется увеличить параметр TTL на интерфейсе туннеля:

*     nmcli connection modify tun1 ip-tunnel.ttl 64

Активируем (перезагружаем) интерфейс tun1

Настройка BR-RTR
![image](https://github.com/user-attachments/assets/bf1c59f4-6f7d-4082-976e-6d4f4c0401b4)



