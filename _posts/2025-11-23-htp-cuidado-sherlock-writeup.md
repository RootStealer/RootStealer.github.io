---
title: HackTheBox Cuidado-Sherlock Writeup
authors: Shobhit
date: 2025-11-23 13:09:00 +0530
categories: [HackTheBox, Sherlock]
tags: [HTB,Blue-Teaming,SOC,Malware-Analysis,VirusTotal,Wireshark]
math: true
mermaid: true
---

![Cuidado - HTB](/assets/img/writeups/Cuidado-HTB/Cuidado-sherlock.png)

# Analyse PCAP file
## Information Gaining

By using **wireshark** tool analysing the network traffic. So download the attachment pcap file and get's ready for looking up all the traffic.


* What is the victim's IP address?

In most of the cases attacker trying to do any malicious activities from the HTTP/HTTPS type of requests.So analyse it on wireshark use the filtering the traffic by just type the **http** on it.Now it's shows only **http** traffic so on the first of the traffic it  easily shows the IP is *192.168.1.152*

* Victim IP=>192.168.1.152

![Wireshark-traffic](/assets/img/writeups/Cuidado-HTB/1.png)

* What is the IP address of the attacker from whom the files were downloaded?

find the malicious traffic in which attacker use the server for downloading the file from their own server or we can say there is the ip address of the attacker.By navigate on it we get some of their monitored activides on the stream **tcp.stream eq 10**

![Wireshark-traffic](/assets/img/writeups/Cuidado-HTB/2.png)

![Wireshark-traffic](/assets/img/writeups/Cuidado-HTB/3.png)


* Attacker IP of the server files are downloaded=>94.156.177.109

* Which malicious file appears to be the first one downloaded?

The above request endpoint of http traffic is **/sh**

* What is the name of the function that the attacker used to download the payload?

![Wireshark-traffic](/assets/img/writeups/Cuidado-HTB/4.png)

**dlr function** is used by the attacker

* Which port does the attacker's server use?

The port **80** is used for the attacker's hosted server.

* The script checks which directories it can write to by attempting to create test files. What is the size of the second test file? (Size in MB)

![Wireshark-traffic](/assets/img/writeups/Cuidado-HTB/5.png)

Size of the script is **2MB**.

* What is the full command that the script uses to identify the CPU architecture?

![Wireshark-traffic](/assets/img/writeups/Cuidado-HTB/6.png)

**uname -mp** is the command uses for identify the CPU architecture

* What is the name of the file that is downloaded after the CPU architecture is compared with reference values?

![Wireshark-traffic](/assets/img/writeups/Cuidado-HTB/7.png)

file name is **x86_64**

* What is the full command that the attacker used to disable any existing mining service?

Now by finding other http traffic on the **/clean** endpoint requested response analyse.
![Wireshark-traffic](/assets/img/writeups/Cuidado-HTB/8.png)

![Wireshark-traffic](/assets/img/writeups/Cuidado-HTB/9.png)

* The command is **systemctl disable c3pool_miner**

* Apparently, the attacker used a packer to compress the malware. Which version of this packer was used? (Format X.XX)

The various tools can be used for the malware but for decompressing/compressing used the famous and easily operatable tool **[UPX](https://github.com/upx/upx/releases/tag/v5.0.2)** for clearing the better picture about the malware.

so the version after download the tool it is **4.23** the attacker is used for it.

# Malware scaning

* What is the entropy value of unpacked malware?

NOTE= For this i recommend to into the seperate machine not on your main system 

![Wireshark-traffic](/assets/img/writeups/Cuidado-HTB/10.png)

![Wireshark-traffic](/assets/img/writeups/Cuidado-HTB/11.png)

![Wireshark-traffic](/assets/img/writeups/Cuidado-HTB/12.png)

## Malware Impact finding

Now, save the x86_64 in to the system and decompress it by the tool upx

```console

$ upx -d -o unpacked x86_64 
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2024
UPX 4.2.2       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 3rd 2024

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
   4674831 <-   1724832   36.90%   linux/amd64   unpacked

Unpacked 1 file.
```

 then go to cyberchef and select the entropy and file (In my case file name is unpacked you can named as per your choice) as input file and upload it.

![Wireshark-traffic](/assets/img/writeups/Cuidado-HTB/13.png)

Entropy value results show by cyberchef **6.488449**

* What is the file name with which the unpacked malware was submitted on VirusTotal?

Now, upload the same file that upload on cyberchef to the virustotal and it get some of the results such that

![Wireshark-traffic](/assets/img/writeups/Cuidado-HTB/14.png)

![Wireshark-traffic](/assets/img/writeups/Cuidado-HTB/15.png)

The malware one of the name is **redtail.cuidado**.


* What MITRE ATT&CK technique ID is associated with the main purpose of the malware?

The sample is cryptomining. The attacker deploys a miner on the compromised system and consumes the victim’s CPU resources to generate cryptocurrency for their own benefit.

Given this behavior, I searched for the corresponding MITRE ATT&CK technique related to unauthorized cryptomining activity. This led me to the technique: Resource hijacking

![Wireshark-traffic](/assets/img/writeups/Cuidado-HTB/16.png)

So,the technique ID is **T1496**.



SEE YOU IN THE NEXT ONE:)