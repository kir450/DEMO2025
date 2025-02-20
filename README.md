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
|                | ens4      | 172.16.4.1/28     | -                 | ISP_HQ-RTR                    |
|                | ens5      | 172.16.5.1/28     | -                 | ISP_BR-RTR                    |
| HQ-RTR         | ens3      | 172.16.4.2/28     | 172.16.4.1        | ISP_HQ-RTR                    |
|                | ens4      | 192.168.100.1/26  | -                 | HQ-RTR_HQ-SRV (VLAN100)       |
|                | ens5      | 192.168.100.65/28 | -                 | HQ-RTR_HQ-CLI (VLAN200)       |
|                | ens6      | 192.168.100.81/29 | -                 | VLAN999                       |
| HQ-SRV         | ens3      | 192.168.100.2/26  | 192.168.100.1     | HQ-RTR_HQ-SRV                 |
| HQ-CLI         | ens3      | DHCP              | 192.168.100.65    | HQ-RTR_HQ-CLI                 |
| BR-RTR         | ens3      | 172.16.5.2/28     | 172.16.5.1        | ISP_BR-RTR                    |
|                | ens4      | 192.168.200.1/27  | -                 | BR-RTR_BR-SRV                 |
| BR-SRV         | ens3      | 192.168.200.2/27  | 192.168.200.1     | BR-RTR_BR-SRV                 |


# 1. Настройка имен устройств.

  1.1. Изменение файла /etc/hostname
*     sudo nano /etc/hostname

*     isp.au-team.irpo
*     hq-rtr.au-team.irpo
*     hq-srv.au-team.irpo
*     hq-cli.au-team.irpo
*     br-rtr.au-team.irpo
*     br-srv.au-team.irpo

  1.2. Изменение файла /etc/hosts
  
*     sudo nano /etc/hosts

*     127.0.1.1       isp.au-team.irpo
*     127.0.1.1       hq-rtr.au-team.irpo
*     127.0.1.1       hq-srv.au-team.irpo
*     127.0.1.1       hq-cli.au-team.irpo
*     127.0.1.1       br-rtr.au-team.irpo
*     127.0.1.1       br-srv.au-team.irpo

 1.3. Задаем IP адреса сетевым интерфейсам согласно таблицы адресации, nmtui.

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

Проверить результат настройки IP-адресов можно с помощью команд:

*     ip –c a
*     ip –c –br a


# 1.4 Маршрутизация транзитных IP-пакетов

Включить пересылку пакетов между интерфейсами на ISP, HQ-RTR, BR-RTR.
*     nano /etc/sysctl.conf
net.ipv4.ip_forward=1
*     sysctl -p

# 2,8. Настройка доступа в интернет с помощью iptables на ISP, HQ-RTR, BR-RTR.

*     iptables -t nat -A POSTROUTING -o ens3 -j MASQUERADE

Сохранение iptables‑правил

*     apt update

*     apt install iptables-persistent

Если впоследствии потребуется сохранить изменённые правила:

*     sudo iptables-save | sudo tee /etc/iptables/rules.v4

Проверка iptables‑правил:

*     sudo iptables -t nat -L -n -v

# 3. Создание локальных учетных записей на HQ-SRV и BR-SRV, HQ‑RTR и BR‑RTR

Создание локальных учетных записей на серверах HQ-SRV и BR-SRV.

*     sudo useradd sshuser -u 1010 -U
*     sudo passwd sshuser
*     P@ssw0rd

Предоставление прав sudo без запроса пароля

*     sudo usermod -aG sudo sshuser

*     sudo visudo

*     sshuser ALL=(ALL) NOPASSWD: ALL

Выполняем вход под пользователем sshuser и выполняем sudo -i

Создание пользователя net_admin на маршрутизаторах HQ‑RTR и BR‑RTR

*     sudo useradd net_admin -U

*     sudo passwd net_admin

*     P@$$word

Предоставление привилегий sudo без запроса пароля

*     sudo usermod -aG sudo net_admin

*     sudo visudo

*     net_admin ALL=(ALL) NOPASSWD: ALL


# 4. Настройка на интерфейсе HQ-RTR в сторону офиса HQ виртуального коммутатора:

4.1. Установка необходимых пакетов

*     sudo apt update

*     sudo apt install -y openvswitch-switch isc-dhcp-server

4.2. Запуск и автозапуск службы Open vSwitch

*     sudo systemctl enable --now openvswitch-switch

4.3. Создание виртуального коммутатора (моста) и настройка VLAN

*     sudo ovs-vsctl add-br hq-sw

Добавляем физические интерфейсы с VLAN-тегированием:

*     sudo ovs-vsctl add-port hq-sw ens4 tag=100

*     sudo ovs-vsctl add-port hq-sw ens5 tag=200

*     sudo ovs-vsctl add-port hq-sw ens6 tag=999

4.4. Добавление внутренних портов (internal) для управления VLAN

*     sudo ovs-vsctl add-port hq-sw vlan100 tag=100 -- set interface vlan100 type=internal

*     sudo ovs-vsctl add-port hq-sw vlan200 tag=200 -- set interface vlan200 type=internal

*     sudo ovs-vsctl add-port hq-sw vlan999 tag=999 -- set interface vlan999 type=internal

4.5. Включение моста и внутренних интерфейсов

*     sudo ip link set hq-sw up

*     sudo ip link set vlan100 up

*     sudo ip link set vlan200 up

*     sudo ip link set vlan999 up

4.6. Назначение IP-адресов внутренним портам

*     sudo ip addr add 192.168.100.1/26 dev vlan100

*     sudo ip addr add 192.168.100.65/28 dev vlan200

*     sudo ip addr add 192.168.100.81/29 dev vlan999

4.7. Автоматизация сохранения настроек Open vSwitch после перезагрузки
   
Скрипт восстановления конфигурации
*     cd /usr/local/sbin
*     wget https://raw.githubusercontent.com/kir450/D/main/ovs-persistent.sh

Сохраните файл и сделайте его исполняемым:

*     sudo chmod +x ovs-persistent.sh

Создание systemd‑сервиса

*     cd /etc/systemd/system

*     wget https://raw.githubusercontent.com/kir450/D/main/ovs-persistent.service

Сохраните файл, затем выполните:

*     sudo systemctl daemon-reload

*     sudo systemctl enable ovs-persistent.service

*     sudo systemctl start ovs-persistent.service

Теперь при каждой загрузке системы скрипт автоматически восстановит нужную конфигурацию.

# 9. Настройка DHCP-сервера на HQ-RTR для VLAN 200 (для HQ‑CLI)

Указание интерфейса для DHCP

*     sudo nano /etc/default/isc-dhcp-server

INTERFACES="vlan200"

Конфигурация файла dhcpd.conf

*     sudo nano /etc/dhcp/dhcpd.conf

*     subnet 192.168.100.64 netmask 255.255.255.240 {
          range 192.168.100.66 192.168.100.78;
          option routers 192.168.100.65; 
          option subnet-mask 255.255.255.240;
          option domain-name-servers 77.88.8.8, 8.8.8.8;
          option broadcast-address 192.168.100.79;
          default-lease-time 600;
          max-lease-time 7200;
      }

Перезапуск DHCP-сервера

*     sudo systemctl restart isc-dhcp-server

Автозапуск сервиса isc-dhcp-server

*     sudo systemctl enable isc-dhcp-server


# 5. Настройка безопасного удаленного доступа на серверах HQ-SRV и BR-SRV

Редактирование файла конфигурации SSH

*     sudo nano /etc/ssh/sshd_config

Заменить порт по умолчанию:

Port 2024

Ограничение количества попыток авторизации:

MaxAuthTries 2

Настройка баннера:

Banner /etc/ssh-banner

*     /etc/ssh-banner

*     sudo nano /etc/ssh-banner
  
Впишите строку:
  
    ********************************************
    *                                          *
    *          Authorized access only          *
    *                                          *
    ********************************************
    
Разрешение подключения только для пользователя sshuser:

*     AllowUsers sshuser

Перезапуск SSH-сервера

*     sudo systemctl restart sshd


Проверка настроек:

С другого устройства (например, с HQ‑CLI) выполните подключение к серверу по порту 2024:

ssh -p 2024 sshuser@192.168.100.2


# 6. GRE-туннель между HQ-RTR и BR-RTR

Настройка HQ-RT, nmtui
![image](https://github.com/user-attachments/assets/91dae2e8-518d-46cd-ba7d-78894d895776)


Для корректной работы протокола динамической маршрутизации требуется увеличить параметр TTL на интерфейсе туннеля:

*     nmcli connection modify tun1 ip-tunnel.ttl 64

Активируем (перезагружаем) интерфейс tun1

Настройка BR-RTR
![image](https://github.com/user-attachments/assets/bf1c59f4-6f7d-4082-976e-6d4f4c0401b4)

# 7. Настройка динамической (внутренней) маршрутизации средствами FRR

*     apt update && apt install -y frr

*     sed -i 's/ospfd=no/ospfd=yes/' /etc/frr/daemons

Заменить содержимое /etc/frr/frr.conf на HQ-RTR:

    frr version 7.5.1
    frr defaults traditional
    hostname br-rtr.au-team.irpo
    log syslog informational
    no ipv6 forwarding
    service integrated-vtysh-config
    !
    interface tun1
    ip ospf authentication message-digest
    ip ospf message-digest-key 1 md5 Test123
    !
    router ospf
    network 10.10.0.0/30 area 0
    network 192.168.200.0/27 area 0
    area 0 authentication message-digest
    !
    line vty
    !

Заменить содержимое /etc/frr/frr.conf на BR-RTR:

    frr version 7.5.1
    frr defaults traditional
    hostname hq-rtr.au-team.irpo
    log syslog informational
    no ipv6 forwarding
    service integrated-vtysh-config
    !
    interface tun1
    ip ospf authentication message-digest
    ip ospf message-digest-key 1 md5 Test123
    !
    router ospf
    network 10.10.0.0/30 area 0
    network 192.168.100.0/26 area 0
    network 192.168.100.64/28 area 0
    area 0 authentication message-digest
    !
    line vty
    !


Перезагрузка:
*     systemctl restart frr

Проверка:     
*     vtysh -c "show ip ospf neighbor"
*     vtysh -c "show ip route"

Просмотр текущей конфигурации:

*     vtysh -c "show running-config"


# 10. Настройка DNS для офисов HQ и BR.


1. Установка необходимых пакетов
   
1.1. Обновите список пакетов и установите bind9, bind9utils, dnsutils:

*     sudo apt update
*     sudo apt install -y bind9 bind9utils dnsutils

2. Настройка глобальных опций BIND
   
2.1. Откройте и отредактируйте файл /etc/bind/named.conf.options:

*     sudo nano /etc/bind/named.conf.options
  
2.2. Пример содержимого:

    options {
        directory "/var/cache/bind";

        recursion yes;

        forwarders {
             77.88.8.8;
             8.8.8.8;
        };

        dnssec-validation no;

        listen-on port 53 { 
             127.0.0.1; 
             192.168.100.0/26; 
             192.168.100.64/28; 
             192.168.200.0/27; 
        };
        listen-on-v6 { none; };

        allow-query { any; };

        auth-nxdomain no;
    };


  3. Настройка зон (прямая и обратная)
     
3.1. Определение зон в named.conf.local

*     sudo nano /etc/bind/named.conf.local
  
Добавьте определения для прямой зоны au-team.irpo и обратной зоны (192.168.100.x):

    // Прямая зона для домена au-team.irpo
    zone "au-team.irpo" {
        type master;
        file "/etc/bind/master/au-team.db";
    };

    // Обратная зона для 192.168.100.x
    zone "100.168.192.in-addr.arpa" {
        type master;
        file "/etc/bind/master/au-team_rev.db";
    };

Сохраните изменения.

3.2. Создание каталога для файлов зон

*     sudo mkdir -p /etc/bind/master

3.3. Прямая зона: au-team.db

Создайте файл зоны, например, скопировав шаблон:

*     sudo cp /etc/bind/db.local /etc/bind/master/au-team.db
*     sudo nano /etc/bind/master/au-team.db

Пример содержимого (au-team.db):

    $TTL 1D
    @       IN      SOA     au-team.irpo. root.au-team.irpo. (
                            0       ; Serial
                            1D      ; Refresh
                            1H      ; Retry
                            1W      ; Expire
                            3H )    ; Minimum


    @       IN      NS      au-team.irpo.
    au-team.irpo.   IN      A       192.168.100.2
    hq-rtr          IN      A       192.168.100.1
    hq-srv          IN      A       192.168.100.2
    hq-cli          IN      A       192.168.100.66
    br-rtr          IN      A       192.168.200.1
    br-srv          IN      A       192.168.200.2
    wiki            IN      CNAME   hq-rtr.au-team.irpo.
    moodle          IN      CNAME   hq-rtr.au-team.irpo.

Сохраните файл.

3.4. Обратная зона: au-team_rev.db

Создайте (или скопируйте) файл:

*     sudo cp /etc/bind/db.127 /etc/bind/master/au-team_rev.db
*     sudo nano /etc/bind/master/au-team_rev.db

Пример содержимого (au-team_rev.db):

    $TTL 1D
    @       IN      SOA     au-team.irpo. root.au-team.irpo. (
                            0       ; Serial
                            1D      ; Refresh
                            1H      ; Retry
                            1W      ; Expire
                            3H )    ; Minimum

    @       IN      NS      au-team.irpo.
    1       IN      PTR     hq-rtr.au-team.irpo.
    2       IN      PTR     hq-srv.au-team.irpo.
    66      IN      PTR     hq-cli.au-team.irpo.



3.5. Права и владельцы

*     sudo chown -R bind:bind /etc/bind/master
*     sudo chmod 0640 /etc/bind/master/*

4.1. Проверка синтаксиса и перезапуск

*     sudo named-checkconf

Если нет ошибок, команда не выведет ничего.

Проверка зон:

*     sudo named-checkzone au-team.irpo /etc/bind/master/au-team.db
*     sudo named-checkzone 100.168.192.in-addr.arpa /etc/bind/master/au-team_rev.db

Перезапуск BIND9:

*     sudo systemctl restart bind9
*     sudo systemctl enable bind9

5. Настройка клиентов

5.1. HQ‑SRV (DNS-сервер)

Убедитесь, что сам HQ‑SRV использует свой IP как DNS-сервер (192.168.100.2).
![image](https://github.com/user-attachments/assets/1a65eafc-0233-4a9c-bca2-349770dd8074)

5.2. BR‑SRV

Укажите в настройках сетевого интерфейса (через nmtui), что DNS-сервер – 192.168.100.2.
![image](https://github.com/user-attachments/assets/84a4ef15-5927-44ed-9b55-a98fcca0ff50)

5.3. HQ‑CLI

Если HQ‑CLI получает адреса по DHCP, настройте DHCP-сервер так, чтобы он выдавал 192.168.100.2 в качестве DNS.
![image](https://github.com/user-attachments/assets/ff16bef4-8d39-42c5-8732-dc7f0e00df4c)


6. Тестирование
   
Проверяем работу DNS на HQ-SRV с BR-SRV с помощью команды host

*     ping -c4 au-team.irpo

Прямая зона

*     host hq-rtr.au-team.irpo
      host br-rtr.au-team.irpo
      host hq-srv.au-team.irpo
      host hq-cli.au-team.irpo
      host br-srv.au-team.irpo
      host moodle.au-team.irpo
      host wiki.au-team.irpo

Обратная зона

*     host 192.168.100.1
      host 192.168.100.2
      host 192.168.100.66

Проверка работоспособности DNS с помощью nslookup

*     apt update && apt install dnsutils

*     nslookup hq-rtr.au-team.irpo
      nslookup wiki.au-team.irpo

*     nslookup 192.168.100.2
      nslookup 192.168.100.66

*     ping hq-cli.au-team.irpo
      ping hq-rtr.au-team.irpo
      ping wiki.au-team.irpo


# 11. Настройте часовой пояс

Настроим Московский часовой пояс (UTC +3):

*     timedatectl set-timezone Europe/Moscow

Проверка:

*     timedatectl
  
Список доступных часовых поясов можно посмотреть командой

*     ls /usr/share/zoneinfo/

Посмотреть список регионов и городов

*     ls /usr/share/zoneinfo/Europe/

Для изменения даты и времени используется команда:

timedatectl set-time "<дата> <время>

*     timedatectl set-time "2024-01-01 00:00:00"

