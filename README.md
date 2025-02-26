# Таблицы адресации 
<details>
<summary>Показать/скрыть</summary>

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
</details>
 
# МОДУЛЬ 1. (Демо-2025 СиСА)
# 1. Настройка имен устройств.</summary>

<details>
<summary>Показать/скрыть</summary>
 
  1.1. Изменение файла /etc/hostname
*     sudo nano /etc/hostname

*     isp.au-team.irpo
      hq-rtr.au-team.irpo
      hq-srv.au-team.irpo
      hq-cli.au-team.irpo
      br-rtr.au-team.irpo
      br-srv.au-team.irpo

  1.2. Изменение файла /etc/hosts
  
*     sudo nano /etc/hosts

*     127.0.1.1       isp.au-team.irpo
      127.0.1.1       hq-rtr.au-team.irpo
      127.0.1.1       hq-srv.au-team.irpo
      127.0.1.1       hq-cli.au-team.irpo
      127.0.1.1       br-rtr.au-team.irpo
      127.0.1.1       br-srv.au-team.irpo

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

1.4 Маршрутизация транзитных IP-пакетов

Включить пересылку пакетов между интерфейсами на ISP, HQ-RTR, BR-RTR.
*     nano /etc/sysctl.conf
net.ipv4.ip_forward=1
*     sysctl -p
</details>


# 2,8. Настройка доступа в интернет с помощью iptables на ISP, HQ-RTR, BR-RTR.
<details>
<summary>Показать/скрыть</summary>

*     iptables -t nat -A POSTROUTING -o ens3 -j MASQUERADE

Сохранение iptables‑правил

*     apt update

*     apt install iptables-persistent

Если впоследствии потребуется сохранить изменённые правила:

*     sudo iptables-save | sudo tee /etc/iptables/rules.v4

Проверка iptables‑правил:

*     sudo iptables -t nat -L -n -v
</details>

# 3. Создание локальных учетных записей на HQ-SRV и BR-SRV, HQ‑RTR и BR‑RTR
<details>
<summary>Показать/скрыть</summary>
 
Создание локальных учетных записей на серверах HQ-SRV и BR-SRV.

*     sudo useradd -m -u 1010 -s /bin/bash sshuser
*     sudo passwd sshuser
*     P@ssw0rd

Предоставление прав sudo без запроса пароля

*     sudo usermod -aG sudo sshuser

*     sudo visudo

*     sshuser ALL=(ALL) NOPASSWD: ALL

Выполняем вход под пользователем sshuser и выполняем sudo -i

Создание пользователя net_admin на маршрутизаторах HQ‑RTR и BR‑RTR

*     sudo useradd -m -s /bin/bash net_admin

*     sudo passwd net_admin

*     P@$$word

Предоставление привилегий sudo без запроса пароля

*     sudo usermod -aG sudo net_admin

*     sudo visudo

*     net_admin ALL=(ALL) NOPASSWD: ALL
</details>

# 4. Настройка на интерфейсе HQ-RTR в сторону офиса HQ виртуального коммутатора:
<details>
<summary>Показать/скрыть</summary>
 
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
</details>

# 9. Настройка DHCP-сервера на HQ-RTR для VLAN 200
<details>
<summary>Показать/скрыть</summary>
 
Указание интерфейса для DHCP

*     sudo nano /etc/default/isc-dhcp-server

INTERFACES="vlan200"

Конфигурация файла dhcpd.conf

*     sudo nano /etc/dhcp/dhcpd.conf

*     subnet 192.168.100.64 netmask 255.255.255.240 {
          range 192.168.100.66 192.168.100.78;
          option routers 192.168.100.65; 
          option subnet-mask 255.255.255.240;
          option domain-name-servers 77.88.8.8 ;
          option broadcast-address 192.168.100.79;
          default-lease-time 600;
          max-lease-time 7200;
      }

Перезапуск DHCP-сервера

*     sudo systemctl restart isc-dhcp-server

Автозапуск сервиса isc-dhcp-server

*     sudo systemctl enable isc-dhcp-server
</details>

# 5. Настройка безопасного удаленного доступа по SSH на серверах HQ-SRV и BR-SRV
<details>
<summary>Показать/скрыть</summary>
 
Редактирование файла конфигурации SSH

*     sudo nano /etc/ssh/sshd_config

Заменить порт по умолчанию:

Port 2024

Ограничение количества попыток авторизации:

MaxAuthTries 2

Настройка баннера:

Banner /etc/ssh-banner

*     /etc/ssh-banner

Разрешение подключения только для пользователя sshuser:

*     AllowUsers sshuser

Впишите строку:

*     sudo nano /etc/ssh-banner

Впишите строку:
  
    ********************************************
    *                                          *
    *          Authorized access only          *
    *                                          *
    ********************************************
    

Перезапуск SSH-сервера

*     sudo systemctl restart sshd


Проверка настроек:

С другого устройства (например, с HQ‑CLI) выполните подключение к серверу по порту 2024:

ssh -p 2024 sshuser@192.168.100.2
</details>

# 6. GRE-туннель между HQ-RTR и BR-RTR
<details>
<summary>Показать/скрыть</summary>
 
Настройка HQ-RT, nmtui
![image](https://github.com/user-attachments/assets/91dae2e8-518d-46cd-ba7d-78894d895776)


Для корректной работы протокола динамической маршрутизации требуется увеличить параметр TTL на интерфейсе туннеля:

*     nmcli connection modify tun1 ip-tunnel.ttl 64

Активируем (перезагружаем) интерфейс tun1

Настройка BR-RTR
![image](https://github.com/user-attachments/assets/bf1c59f4-6f7d-4082-976e-6d4f4c0401b4)
</details>

# 7. Настройка динамической (внутренней) маршрутизации средствами FRR на HQ-RTR и BR-RTR.
<details>
<summary>Показать/скрыть</summary>
 
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
</details>

# 10. Настройка DNS для офисов HQ и BR на HQ-SRV.
<details>
<summary>Показать/скрыть</summary>

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
</details>

# 11. Настройте часовой пояс
<details>
<summary>Показать/скрыть</summary>
 
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
</details>













# МОДУЛЬ 2. (Демо-2025 СиСА)









# 1. Настройте доменный контроллер Samba на машине BR-SRV.
<details>
<summary>Показать/скрыть</summary>



</details>

# 2. Сконфигурируйте файловое хранилище на HQ-SRV 

<details>
<summary>Показать/скрыть</summary>
 
1. Создание файлов для имитации дополнительных дисков

1.1. Создайте три файла по 1 ГБ:

    sudo dd if=/dev/zero of=/root/disk1.img bs=1M count=1024
    sudo dd if=/dev/zero of=/root/disk2.img bs=1M count=1024
    sudo dd if=/dev/zero of=/root/disk3.img bs=1M count=1024

Эти команды создадут файлы /root/disk1.img, /root/disk2.img и /root/disk3.img размером по 1 ГБ каждый.

2. Подключение файлов как loop-устройства

2.1. Создайте loop-устройства из созданных файлов:

    sudo losetup -fP /root/disk1.img
    sudo losetup -fP /root/disk2.img
    sudo losetup -fP /root/disk3.img

2.2. Проверьте, какие loop-устройства появились:

    losetup -a

Вы должны увидеть, устройства /dev/loop0, /dev/loop1 и /dev/loop2, которые будут использоваться как «диски» для RAID.

3. Создание RAID5 массива с mdadm

3.1. Установка mdadm:

*     sudo apt update
*     sudo apt install -y mdadm

3.2. Создание RAID5 массива из loop-устройств:

*     sudo mdadm --create --verbose /dev/md0 --level=5 --raid-devices=3 /dev/loop0 /dev/loop1 /dev/loop2

3.3. Проверьте состояние массива:

*     cat /proc/mdstat
*     sudo mdadm -D /dev/md0

Чтобы при перезагрузке система автоматически собирала массив, сохраните конфигурацию mdadm:

*     sudo mdadm --detail --scan --verbose | sudo tee /etc/mdadm.conf

Обновите initramfs, чтобы изменения вступили в силу:

*     sudo update-initramfs -u

4. Форматирование и монтирование RAID-массива

4.1. Создайте файловую систему ext4 на массиве:

*     sudo mkfs.ext4 /dev/md0

4.2. Создайте точку монтирования:

*     sudo mkdir /raid5

4.3. Смонтируйте RAID-массив в /raid5:

*     sudo mount /dev/md0 /raid5

4.4. Проверьте монтирование:

*     lsblk -f
*     df -h

4.5. Настройте автоматическое монтирование при загрузке:

Откройте файл /etc/fstab:

*     sudo nano /etc/fstab

Добавьте строку:

*     /dev/md0    /raid5    ext4    defaults    0    0

Сохраните и выйдите.

5. Настройка NFS-сервера на HQ-SRV

5.1. Установка необходимых пакетов для NFS:

*     sudo apt update
*     sudo apt install -y nfs-kernel-server

5.2. Создайте папку для общего доступа:

*     sudo mkdir /raid5/nfs

5.3. Отредактируйте файл экспорта (/etc/exports):

*     sudo nano /etc/exports

Добавьте строку (настройте IP-сеть согласно требованиям):

*     /raid5/nfs    192.168.100.65/28(rw,sync,no_root_squash,no_subtree_check)

5.4. Примените изменения:

*     sudo exportfs -a

5.5. Запустите и включите службу NFS:

*     sudo systemctl restart nfs-kernel-server
*     sudo systemctl enable nfs-kernel-server

6. Настройка автомонтирования NFS на HQ-CLI

6.1. Установка NFS-клиента:

*     sudo apt update
*     sudo apt install -y nfs-common

6.2. Создайте точку монтирования:

*     sudo mkdir /mnt/nfs

6.3. Смонтируйте шару NFS:

*     sudo mount -t nfs 192.168.100.2:/raid5/nfs /mnt/nfs

(Замените 192.168.100.2 на IP-адрес HQ-SRV, если он отличается.)

6.4. Добавьте запись в /etc/fstab для автоматического монтирования:

Откройте файл:
*     sudo nano /etc/fstab
Добавьте строку:

*     192.168.100.2:/raid5/nfs    /mnt/nfs    nfs    defaults    0    0
Сохраните изменения.
</details>


<details>
<summary>Проверка</summary>

1. Проверка RAID5 массива
Проверьте статус RAID:
*     cat /proc/mdstat
Вы должны увидеть строку, в которой указано устройство /dev/md0 и его состояние (“active”).

Получите подробную информацию о массиве:

*     sudo mdadm -D /dev/md0

Эта команда выведет подробные сведения о RAID-массиве, его составе и состоянии каждого диска (в данном случае loop-устройств).

2. Проверка файловой системы и монтирования
Проверьте, что файловая система создана и смонтирована:

*     df -h | grep /raid5
*     lsblk -f
В выводе должно быть видно устройство /dev/md0, смонтированное в каталоге /raid5.

Проверьте, что запись добавлена в /etc/fstab:

*     cat /etc/fstab | grep md0
Строка должна выглядеть примерно так:
/dev/md0    /raid5    ext4    defaults    0    0

3. Проверка NFS-сервера
Проверьте экспортированные шары:

*     sudo exportfs -v

В выводе должно быть указано, что каталог /raid5/nfs экспортирован для сети (например, 192.168.100.65/28) с указанными параметрами (rw, sync, no_root_squash, subtree_check).

Проверьте статус службы NFS:

*     sudo systemctl status nfs-kernel-server

Убедитесь, что служба работает без ошибок.

4. Проверка работы NFS-клиента на HQ-CLI

Проверьте, что точка монтирования создана и смонтирована:

*     df -h | grep /mnt/nfs
*     mount | grep nfs

Проверьте доступ к шару:

Перейдите в каталог /mnt/nfs, создайте тестовый файл и проверьте, доступна ли запись:

*     cd /mnt/nfs
*     echo "Test NFS" | sudo tee testfile.txt
*     cat testfile.txt

Если файл успешно создаётся и читается, значит, NFS работает корректно.

Проверьте автомонтирование:

Перезагрузите клиентскую машину или размонтируйте и смонтируйте шару вручную:
*     sudo umount /mnt/nfs
*     sudo mount -a
*     df -h | grep /mnt/nfs
</details>

# 3. Настройка NTP сервера на HQ-RTR
<details>
<summary>Показать/скрыть</summary>


1. Устоновка chrony

*     apt install chrony


2. Редактирование конфигурационного файла chrony

*     sudo nano /etc/chrony/chrony.conf

Внесите следующие изменения (пример для HQ‑RTR как NTP‑сервера):

    server 127.0.0.1 iburst prefer
    local stratum 5
    allow 192.168.100.0/26
    allow 192.168.100.64/28
    allow 192.168.200.0/27


Закомментируйте внешние источники времени, если хотите работать только с локальным источником.
pool 2.debian.pool.ntp.org iburst

2. Применение изменений
Перезапустите службу chrony, чтобы новые настройки вступили в силу:

*     sudo systemctl restart chrony
      sudo systemctl enable chrony

Проверьте статус службы:
*     sudo systemctl status chrony

3. Проверка работы NTP-сервера

На HQ‑RTR выполните:

Проверка источников времени:

*     chronyc sources

В выводе вы должны увидеть, что сервер использует локальный источник (локальные часы) с заданным stratum 5.

Проверка подключённых клиентов:

Если на HQ‑RTR есть NTP-клиенты, можно выполнить:

*     chronyc clients

Это покажет, какие устройства синхронизируются с вашим сервером.

4. Настройка клиентов

На машинах-клиентах (HQ‑SRV, HQ‑CLI, BR‑RTR, BR‑SRV):

Установите chrony (если ещё не установлен):

*     sudo apt update
      sudo apt install -y chrony

Отредактируйте файл /etc/chrony/chrony.conf на клиентах:

*     nano /etc/chrony/chrony.conf

Закомментируйте или удалите существующие строки с pool ….

Добавьте строку, указывающую на HQ‑RTR как NTP‑сервер. Если IP HQ‑RTR равен 192.168.100.1, добавьте:

*     server 192.168.100.1 iburst

Примените изменения:

*     sudo systemctl restart chrony
      sudo systemctl enable chrony

Проверьте, что клиент синхронизируется с вашим NTP‑сервером:

*     chronyc sources

</details>


# 4. Сконфигурируйте ansible на сервере BR-SRV
<details>
 <summary>Показать/скрыть</summary>


1.Заходим под пользователем sshuser

*     su sshuser

2. Установка Ansible на BR‑SRV

*     sudo apt install -y ansible

2. Создание пары SSH‑ключей

*     ssh-keygen -t rsa

В результате в каталоге /home/sshuser/.ssh будут созданы файлы ключей:

*     ls -l ~/.ssh

id_rsa – закрытый ключ
id_rsa.pub – открытый ключ

3. Копирование SSH‑ключей на удалённые хосты

Для HQ‑SRV (SSH-сервер на порту 2024):
*     ssh-copy-id -p 2024 sshuser@192.168.100.2
Для HQ‑CLI:
*     ssh-copy-id user@192.168.100.66
Для HQ‑RTR:
*     ssh-copy-id net_admin@172.16.4.2
Для BR‑RTR:
*     ssh-copy-id net_admin@172.16.5.2

4. Откройте файл для редактирования:
*     sudo nano /etc/ansible/demo

Пример содержимого файла инвентаря:

*     [HQ]
      192.168.100.2 ansible_port=2024 ansible_user=sshuser
      192.168.100.66 ansible_user=user
      172.16.4.2 ansible_user=net_admin

      [BR]
      172.16.5.2 ansible_user=net_admin

5. Запуск команд с пользовательским инвентарем

*     ansible all -i /etc/ansible/demo -m ping

</details>


# 5. Развертывание приложений (MediaWiki) в Docker на сервере BR-SRV.
<details>
 <summary>Показать/скрыть</summary>

 1.1. Установка Docker CE:

*     sudo apt update
*     sudo apt install -y apt-transport-https ca-certificates curl gnupg lsb-release
*     curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
*     echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
*     sudo apt update
*     sudo apt install -y docker-ce docker-ce-cli containerd.io

1.2. Установка docker-compose:
*     sudo apt install -y docker-compose

1.3. Запуск и автозапуск Docker:
*     sudo systemctl enable --now docker

Проверьте статус:
*     sudo systemctl status docker

Для получения информации об установленном docker:
*     docker info

2. Установка MediaWiki

Для облегчения создания wiki.yml подключаемся по SSH к BR-SRV с HQ-CLI.

*     ssh sshuser@192.168.200.2 -p 2024

Для упрощения создания wiki.yml в поисковой системе (Яндекс) на HQ-CLI пишем mediawiki docker-compose и переходим по ссылке. На странице находим раздел Adding a Database Server.

*     cd /home/sshuser
*     nano wiki.yml

*     version: "3.3"

      services:
        wiki:
          container_name: wiki
          image: mediawiki:latest
          restart: always
          ports:
            - "8080:80"
          depends_on:
            - mariadb
          volumes:
            - images:/var/www/html/images
            # - ./LocalSettings.php:/var/www/html/LocalSettings.php

        mariadb:
          container_name: mariadb
          image: mariadb:latest
          restart: always
          environment:
            MYSQL_DATABASE: mediawiki
            MYSQL_USER: wiki
            MYSQL_PASSWORD: WikiP@ssw0rd
            MYSQL_RANDOM_ROOT_PASSWORD: "yes"
          volumes:
            - dbvolume:/var/lib/mariadb
      
      volumes:
         dbvolume:
           external: true
         images: {}


Чтобы отдельный volume для хранения базы данных имел правильное имя - создаём его средствами docker:
*     sudo docker volume create dbvolume

Посмотреть все тмеющиеся volume можно командой
*     sudo docker volume ls

Выполняем сборку и запуск стека контейнеров с приложением MediaWiki и базой данных описанных в файле wiki.yml:
*     sudo docker-compose -f wiki.yml up -d

Для просмотра списка контейнеров вводим команду sudo docker ps. Позволяет смотреть как запущенные контейнеры Docker, так и все контейнеры, которые есть в системе.

Переходим на HQ-CLI в браузере по адресу http://192.168.200.2:8080 (IP BR-SRV) для продолжения установки через веб-интерфейс - нажимаем set up the wiki:

![image](https://github.com/user-attachments/assets/478908b5-8e5a-407e-96cd-31699dad61e4)

Выбираем необходимый Язык - жмем Далее:

![image](https://github.com/user-attachments/assets/bdc2cf9f-3191-4290-91a4-d83c50bf30e1)

После успешной проверки внешней среды - жмем Далее:

![image](https://github.com/user-attachments/assets/62324f16-fe9a-488c-a639-038a0a84e976)

Заполняем параметры подключение к БД в соответствие с заданными переменными окружения в wiki.yml, которые соответствуют заданию:

![image](https://github.com/user-attachments/assets/6e4706a2-70b8-473f-bfee-41d1b03815a5)

Ставим галочку и жмем далее

![image](https://github.com/user-attachments/assets/4cfa818a-1c2f-47b2-9e98-cceebd3a91e1)

Вносим необходимые сведения:

![image](https://github.com/user-attachments/assets/90b93a56-e265-414f-991a-7265dd585677)

Передача LocalSettings.php на BR-SRV

*     scp -P 2024 /root/Downloads/LocalSettings.php sshuser@192.168.200.2:/home/sshuser

Раскомментируем строку # - ./LocalSettings.php:/var/www/html/LocalSettings.php в файле wiki.yml :
*     nano wiki.yml

Перезапускаем сервисы средствами docker-compose:
*     sudo docker-compose -f wiki.yml stop
*     sudo docker-compose -f wiki.yml up -d

Проверяем доступ к Wiki http://192.168.200.2:8080

![image](https://github.com/user-attachments/assets/b572adc1-3f80-4cd2-b55d-fad77040124d)

Входим под пользователя wiki с паролем WikiP@ssw0rd:

Очистка (опционально)
Чтобы удалить/очистить все данные Docker (контейнеры, образы, тома и сети), можно выполнить следующие команды:

*     sudo docker stop $(sudo docker ps -qa)
      sudo docker rm $(sudo docker ps -qa)
      sudo docker rmi -f $(sudo docker images -qa)
      sudo docker volume rm $(sudo docker volume ls -q)
      sudo docker network rm $(sudo docker network ls -q)
      sudo docker system prune -f
Команды не должны выводить какие-либо элементы:
*     docker ps -a
      docker images -a
      docker volume ls


</details>

# 6. На маршрутизаторах HQ-RTR и BR-RTR сконфигурируйте статическую трансляцию портов.
<details>
 <summary>Показать/скрыть</summary>

Проброс порта 2024 на маршрутизаторе HQ-RTR в порт 2024 на HQ-SRV

*     sudo iptables -t nat -A PREROUTING -i ens3 -p tcp --dport 2024 -j DNAT --to-destination 192.168.100.2:2024

Проверка с HQ-CLI подключаемся по ssh к HQ-RTR по порту 2024

*     ssh sshuser@172.16.4.2 -p 2024
Должны попасть на HQ-SRV

Сохранение правил после перезагрузки

*     sudo iptables-save | sudo tee /etc/iptables/rules.v4


Делаем проброс порта 80 при обращение на внешний интерфейс BR-RTR (ens3) на порт 8080 BR-SRV

*     sudo iptables -t nat -A PREROUTING -d 172.16.5.2 -p tcp --dport 80 -j DNAT --to-destination 192.168.200.2:8080

Проброс порта 2024 на маршрутизаторе BR-RTR в порт 2024 на BR-SRV

*     sudo iptables -t nat -A PREROUTING -d 172.16.5.2 -p tcp --dport 2024 -j DNAT --to-destination 192.168.200.2:2024

С HQ-CLI в браузере переходим по IP адресу (WAN) BR-RTR должны попасть на страницу MediaWiki

*     http://172.16.5.2

С HQ-CLI подключаемся по ssh к BR-RTR по порту 2024

*     ssh sshuser@172.16.5.2 -p 2024

</details>
