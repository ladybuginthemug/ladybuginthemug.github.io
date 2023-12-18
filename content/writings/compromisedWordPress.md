---
draft: false
author: ladybuginthemug
title: Log Analysis – Compromised WordPress
description: remote code execution 
date: 2023-12-18
category:
  - blueteamlabs
---

Link: [Log Analysis – Compromised WordPress](https://blueteamlabs.online/home/challenge/log-analysis-compromised-wordpress-ce000f5b59) 

> Scenario:
> 
> One of our WordPress sites has been compromised but we're currently unsure how. The primary hypothesis is that an installed plugin was vulnerable to a remote code execution vulnerability which gave an attacker access to the underlying operating system of the server.
____________

So for this challenge we have one `access.log` file.

To investigate, at first I would lookup general stats with `goaccess` and than dive into log file if necessary to have a close look at.

```
goaccess access.log
```
![1](https://github.com/ladybuginthemug/ladybuginthemug.github.io/assets/88084724/3f10c720-4f14-4185-badf-1b85bc52e7d3)

Aha! I can instantly spot `Crawlers` that is first sign that `scanning & enumeration` stage took place.

![crawlers](https://github.com/ladybuginthemug/ladybuginthemug.github.io/assets/88084724/c633e888-2ab2-4f29-b7a7-26781e2c6206)

By looking up with 'grep' we confirm that two tools been used here `sqlmap` and `wpscan`:

![tools](https://github.com/ladybuginthemug/ladybuginthemug.github.io/assets/88084724/3d19fe31-f266-476a-b240-74295ae96da9)

By confirming tools in log file, we can instantly indicate timeframe of the first attack and malicious ips: `119.241.22.121, 168.22.54.119` 

we can see that `168.22.54.119` starts with many manual probing attempts :
* `xmlrpc.php` - this file enables data to be transmitted with HTTP acting as the transport mechanism and XML as the encoding mechanism
* `wp-content/uploads/' - is the directory where any files uploaded to the platform are stored.
![ip168](https://github.com/ladybuginthemug/ladybuginthemug.github.io/assets/88084724/7c327a8f-9572-4de6-9ad3-671fb226446c)

also, there was another attemt to access important files such as `wp-login` and `wp-includes`(that is the dir with the core files are stored): 
![wp-includes](https://github.com/ladybuginthemug/ladybuginthemug.github.io/assets/88084724/ecc28d8b-93eb-45b8-8b96-65eda3600aad)

worth noting that view plugins was discovered in the process:
![plugins](https://github.com/ladybuginthemug/ladybuginthemug.github.io/assets/88084724/c5468e4a-02f0-4d1f-9ec9-fd5e953b3177)

also file that contains information required by WordPress to connect to the database `wp-config.php`:
![wp-config](https://github.com/ladybuginthemug/ladybuginthemug.github.io/assets/88084724/47e0c709-7544-448f-9d59-ca910e916748)

up unitl `sqlmap` scan, which runs sql injections on `wp-login.php` : 
![sqlmap](https://github.com/ladybuginthemug/ladybuginthemug.github.io/assets/88084724/fd46150d-cf60-41b9-852a-5b456719758e)

all requests from this ip seems to be unsuccessful so lets move on to next ip `119.241.22.121`:

* many attempts to access various paths under `/webadmin` and `/wp-login.php` indicating a probing or scanning behavior searching for common admin or login pages.
* the request to `/wp-login.php` results in a 302 (Found) status code, indicating a redirection.
* a subsequent POST request to `/wp-login.php` with the parameter `itsec-hb-token=adminlogin` results in a 200 (OK) status code, suggesting a successful login attempt.
* user continues its attempts to log in, but all attempts result in a 403 Forbidden status, suggesting that the server is blocking access to the login page.

![admin](https://github.com/ladybuginthemug/ladybuginthemug.github.io/assets/88084724/d28a775a-4da4-4c6a-9be1-aee3d769d18d)

Taking second look at stats with go-access reveal that there was many hits with plugins in the path in combination of the previous plugins enumeration can suggest of possible plugins exploitation. 

![goaccess](https://github.com/ladybuginthemug/ladybuginthemug.github.io/assets/88084724/1c86c9bc-8524-4cb0-bfae-50ff76403041)


Next step is to follow the `/wp-content/` :

```bash
cat access.log |  uniq | grep '/wp-content/' 
```


![plugins](https://github.com/ladybuginthemug/ladybuginthemug.github.io/assets/88084724/9e0b1d11-5f0d-4d14-87eb-17d0431160ef)

Malicious user was trying to exploit vulnerability in `contact form plugin`, by uploading PHP web shell file `fr34k.php`  unsuccessfully.  Successful upload would load a web shell for remote execution .

* CVE-2020-35489 - The contact-form-7 plugin
 https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-35489)

```bash
103.69.55.212 - - [14/Jan/2021:06:21:08 +0000] "GET /wp-content/plugins/contact-form-7/uploads/fr34k.png HTTP/1.1" 404 29045 "-" "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; Tablet PC 2.0)"
```

Later we can see another similar attempt to upload with different plugin `simple-file-list`, this time with success. 

 -  WordPress Plugin Simple File List 4.2.2 - Arbitrary File Upload 
  https://www.exploit-db.com/exploits/48979

Following script exploits WP in following steps:

- The script defines the target URL, upload directory path, upload file path, and move file path.
- It generates a random PNG file containing PHP code to achieve remote code execution.
- The script then uploads the generated file to the target system using a POST request to the upload endpoint.
```bash
119.241.22.121 - - [14/Jan/2021:06:26:53 +0000] "POST /wp-content/plugins/simple-file-list/ee-upload-engine.php HTTP/1.1" 200 236 "-" "python-requests/2.24.0"
119.241.22.121 - - [14/Jan/2021:06:26:53 +0000] "GET /wp-content/uploads/simple-file-list/fr34k.png HTTP/1.1" 200 84690 "-" "python-requests/2.24.0"
119.241.22.121 - - [14/Jan/2021:06:26:53 +0000] "POST /wp-content/plugins/simple-file-list/ee-file-engine.php HTTP/1.1" 200 236 "http://172.21.0.3/wp-admin/admin.php?page=ee-simple-file-list&tab=file_list&eeListID=1" "python-requests/2.24.0"

```

- After successful upload, it sends a GET request to the uploaded file to confirm the upload.
```bash
103.69.55.212 - - [14/Jan/2021:06:27:04 +0000] "GET /wp-content/uploads/simple-file-list/fr34k.php HTTP/1.1" 200 1295 "-" "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; Tablet PC 2.0)"
```

- The script then moves the uploaded file to change its extension to ".php" using a POST request to the move endpoint.
- Finally, it sends a POST request to the moved PHP file with a payload to execute the "phpinfo();" command.
```bash
103.69.55.212 - - [14/Jan/2021:06:27:06 +0000] "POST /wp-content/uploads/simple-file-list/fr34k.php HTTP/1.1" 200 1213 "http://172.21.0.3/wp-content/uploads/simple-file-list/fr34k.php" "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; Tablet PC 2.0)"

```

we can confirm that exploit worked:
![connected](https://github.com/ladybuginthemug/ladybuginthemug.github.io/assets/88084724/0c79ddc1-4344-4cfa-a4ee-b47ee120b01f)

the last activity:
![end](https://github.com/ladybuginthemug/ladybuginthemug.github.io/assets/88084724/30115c3b-9536-4d99-ba64-a3747d37a611)



