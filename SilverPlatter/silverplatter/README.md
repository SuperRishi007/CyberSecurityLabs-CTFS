# Silver Platter / THM Personal Lab Writeup

# Overview:

This TryHackMe room, *SilverPlatter*, helped reinforce the importance of solid enumeration and not overlooking uncommon ports or services. The box involved a mix of web and SSH access, and I got hands-on practice with tools like rustscan, dirsearch, and cewl to gather intel.

It also introduced me to *Silverpeas*, a platform I hadn’t worked with before, which added a nice layer of realism and taught me how to deal with unfamiliar web apps in a pentesting context.

# Enumeration

## NMAP Scan

```bash
rustscan -a 10.10.170.183 -- -A

PORT     STATE SERVICE    REASON  VERSION
22/tcp   open  ssh        syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http       syn-ack nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Hack Smarter Security
8080/tcp open  http-proxy syn-ack
| fingerprint-strings: 
|   FourOhFourRequest, GetRequest, HTTPOptions: 
|     HTTP/1.1 404 Not Found
|     Connection: close
|     Content-Length: 74
|     Content-Type: text/html
|     Date: Fri, 17 Jan 2025 02:56:51 GMT
|     <html><head><title>Error</title></head><body>404 - Not Found</body></html>

```

## SSH (22)

- password auth is enabled

```bash
root@ip-10-10-241-14:~# ssh root@silverplatter.thm
The authenticity of host 'silverplatter.thm (10.10.170.183)' can't be established.
ECDSA key fingerprint is SHA256:uZ6ThTuXLu08VowBm/fEHAxnKn1V5P8fbm60OJ5HcE8.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'silverplatter.thm,10.10.170.183' (ECDSA) to the list of known hosts.
root@silverplatter.thm's password:
```

## HTTP(80)

Dirsearch

```bash
(myenv) root@ip-10-10-241-14:~# dirsearch -u http://silverplatter.thm

[20:59:29] 403 -  564B  - /assets/
[20:59:29] 301 -  178B  - /assets  ->  http://silverplatter.thm/assets/
[20:59:49] 301 -  178B  - /images  ->  http://silverplatter.thm/images/
[20:59:49] 403 -  564B  - /images/
[20:59:53] 200 -   17KB - /LICENSE.txt
[21:00:11] 200 -  771B  - /README.txt

```

Vhosts

```bash
#nothing interesting
```

### Website features / notes

![image.png](image.png)

- To-Do List
    - Enumerate what Silverpeas is
    - Username Enurmation: `scr1ptkiddy`
    

## HTTP(8080)

- Silvepeas instance
- Accessible at `/silverpeas`
- 

## Run Cewl

```bash
cewl http://silverplatter.thm > passwords.txt

```

- Using the password list created along with cadio we were able to find a password list that words

![image.png](image%201.png)

- once logged in we were able to locate a new meessage on the platfrom, when we clicked the new message in the URL we saw the ID=5 message, I went through all the message and was able to locate
- a possible `UserName:tim` and `Password:cm0nt!md0ntf0rg3tth!spa$$w0rdagainlol`

![image.png](20805e20-7c5e-4ddc-a66b-42ebdfd5ab56.png)

# Post-Exploitation

```bash
tim@silver-platter:~$ id
uid=1001(tim) gid=1001(tim) groups=1001(tim),4(adm)

```

## To grep recursively for the password:

```bash
tim@silver-platter:/var/log$ grep -ir password 

```

![image.png](image%202.png)

# Key Takeaways  / Learning

- **Always scan all ports -(when your unsure)** — The main vulnerability wasn’t on the default port 80, but on 8080.
- **Obscure services can be goldmines** — Silverpeas wasn’t something I knew, but digging in led to user creds and a foothold.
- **Custom wordlists matter** — Using cewl to scrape keywords helped build an effective password list for bruteforce attempts.
- **Watch for sensitive info in apps** — Found real creds hidden in internal messages, which is a common issue in the real world. (This is where learning and teaching people about cybersecurity really shines)
- **Post-exploitation basics** — Searched through logs for leftover passwords, and that actually worked.