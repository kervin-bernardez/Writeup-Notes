## Volatility Forensics

[Room Link](https://tryhackme.com/room/forensics)

1.
```
$ ./Documents/volatility/volatility_sa -f Downloads/victim.raw imageinfo  

Volatility Foundation Volatility Framework 2.6
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : Win7SP1x64, Win7SP0x64, Win2008R2SP0x64, Win2008R2SP1x64_23418, Win2008R2SP1x64, Win7SP1x64_23418
                     AS Layer1 : WindowsAMD64PagedMemory (Kernel AS)
                     AS Layer2 : FileAddressSpace (/home/kali/Downloads/victim.raw)
                      PAE type : No PAE
                           DTB : 0x187000L
                          KDBG : 0xf800028420a0L
          Number of Processors : 1
     Image Type (Service Pack) : 1
                KPCR for CPU 0 : 0xfffff80002843d00L
             KUSER_SHARED_DATA : 0xfffff78000000000L
           Image date and time : 2019-05-02 18:11:45 UTC+0000
     Image local date and time : 2019-05-02 11:11:45 -0700
```

2.
```
$ ./Documents/volatility/volatility_sa -f Downloads/victim.raw --profile=Win7SP1x64 pslist

Volatility Foundation Volatility Framework 2.6
Offset(V)          Name                    PID   PPID   Thds     Hnds   Sess  Wow64 Start                          Exit                          
------------------ -------------------- ------ ------ ------ -------- ------ ------ ------------------------------ ------------------------------
0xfffffa8001252040 System                    4      0     88      624 ------      0 2019-05-03 06:32:24 UTC+0000                                 
0xfffffa800234d8a0 smss.exe                268      4      2       29 ------      0 2019-05-03 06:32:24 UTC+0000                                 
0xfffffa8002264550 csrss.exe               360    352      9      363      0      0 2019-05-03 06:32:34 UTC+0000                                 
0xfffffa80027d67d0 csrss.exe               408    400      7      162      1      0 2019-05-03 06:32:35 UTC+0000                                 
0xfffffa8002b601c0 wininit.exe             416    352      3       76      0      0 2019-05-03 06:32:35 UTC+0000                                 
0xfffffa8002b71680 winlogon.exe            444    400      3      111      1      0 2019-05-03 06:32:35 UTC+0000                                 
0xfffffa8002c69b30 services.exe            504    416      6      184      0      0 2019-05-03 06:32:36 UTC+0000                                 
0xfffffa80027d9b30 lsass.exe               512    416      6      534      0      0 2019-05-03 06:32:37 UTC+0000                                 
0xfffffa80027d81f0 lsm.exe                 520    416     10      143      0      0 2019-05-03 06:32:37 UTC+0000                                 
0xfffffa80029cd3e0 svchost.exe             628    504      9      345      0      0 2019-05-03 06:32:48 UTC+0000                                 
0xfffffa8002d38b30 VBoxService.ex          688    504     12      135      0      0 2019-05-03 06:32:48 UTC+0000                                 
0xfffffa8002a1bb30 svchost.exe             752    504      7      235      0      0 2019-05-02 18:02:51 UTC+0000                                 
0xfffffa8002d70650 svchost.exe             852    504     22      473      0      0 2019-05-02 18:02:51 UTC+0000                                 
0xfffffa8002d9c780 svchost.exe             892    504     17      427      0      0 2019-05-02 18:02:51 UTC+0000                                 
0xfffffa8002dbe9e0 svchost.exe             920    504     29      878      0      0 2019-05-02 18:02:51 UTC+0000                                 
0xfffffa8002e3db30 svchost.exe             400    504     10      281      0      0 2019-05-02 18:02:56 UTC+0000                                 
0xfffffa8002e57890 svchost.exe            1004    504     20      379      0      0 2019-05-02 18:02:56 UTC+0000                                 
0xfffffa8002dfdab0 spoolsv.exe            1140    504     12      279      0      0 2019-05-02 18:02:57 UTC+0000                                 
0xfffffa8002f2cb30 svchost.exe            1268    504     17      297      0      0 2019-05-02 18:02:59 UTC+0000                                 
0xfffffa8002f81460 svchost.exe            1368    504     20      295      0      0 2019-05-02 18:02:59 UTC+0000                                 
0xfffffa8003148b30 taskhost.exe           1788    504      8      159      1      0 2019-05-02 18:03:09 UTC+0000                                 
0xfffffa8003172b30 explorer.exe           1860   1756     19      645      1      0 2019-05-02 18:03:09 UTC+0000                                 
0xfffffa800315eb30 dwm.exe                1896    892      3       69      1      0 2019-05-02 18:03:09 UTC+0000                                 
0xfffffa800300d700 VBoxTray.exe           1600   1860     13      141      1      0 2019-05-02 18:03:25 UTC+0000                                 
0xfffffa8003367060 SearchIndexer.         2180    504     11      629      0      0 2019-05-02 18:03:32 UTC+0000                                 
0xfffffa80033f6060 WmiPrvSE.exe           2876    628      5      113      0      0 2019-05-02 18:03:55 UTC+0000                                 
0xfffffa8003162060 svchost.exe            1820    504     11      317      0      0 2019-05-02 18:05:09 UTC+0000                                 
0xfffffa8003371540 wmpnetwk.exe           2464    504     14      440      0      0 2019-05-02 18:05:10 UTC+0000                                 
0xfffffa80014eeb30 taskhost.exe           1148    504      8      176      0      0 2019-05-02 18:09:58 UTC+0000  
```

3.
```
$ ./Documents/volatility/volatility_sa -f Downloads/victim.raw --profile=Win7SP1x64 shellbags

Volatility Foundation Volatility Framework 2.6
Scanning for registries....
Gathering shellbag items and building path tree...
***************************************************************************
Registry: \??\C:\Users\victim\ntuser.dat 
Key: Software\Microsoft\Windows\Shell\Bags\1\Desktop
Last updated: 2019-05-02 07:00:41 UTC+0000
Value                     File Name      Modified Date                  Create Date                    Access Date                    File Attr                 Unicode Name
------------------------- -------------- ------------------------------ ------------------------------ ------------------------------ ------------------------- ------------
ItemPos1366x664x96(1)     Firefox.lnk    2019-04-11 13:29:10 UTC+0000   2019-04-11 13:29:10 UTC+0000   2019-04-11 13:29:10 UTC+0000   ARC                       Firefox.lnk 
ItemPos1366x664x96(1)     HxD.lnk        2019-04-13 06:00:40 UTC+0000   2019-04-13 06:00:40 UTC+0000   2019-04-13 06:00:40 UTC+0000   ARC                       HxD.lnk 
ItemPos1366x664x96(1)     WIRESH~1.LNK   2019-04-13 06:31:06 UTC+0000   2019-04-13 06:31:06 UTC+0000   2019-04-13 06:31:06 UTC+0000   ARC                       Wireshark.lnk 
ItemPos1366x664x96(1)     LIFEVI~1       2019-04-23 06:14:40 UTC+0000   2019-04-13 07:46:36 UTC+0000   2019-04-23 06:14:40 UTC+0000   DIR                       Life Virus Samples 
ItemPos1366x664x96(1)     NEWFOL~1       2019-04-13 08:02:44 UTC+0000   2019-04-13 08:02:44 UTC+0000   2019-04-13 08:02:44 UTC+0000   DIR                       New folder 
ItemPos1366x664x96(1)     ~res-x64.txt   2019-04-13 08:19:32 UTC+0000   2019-04-13 08:19:32 UTC+0000   2019-04-13 08:19:32 UTC+0000   ARC                       ~res-x64.txt 
ItemPos1366x664x96(1)     ~RES-X~1.TXT   2019-04-27 10:37:32 UTC+0000   2019-04-27 10:37:32 UTC+0000   2019-04-27 10:37:32 UTC+0000   ARC                       ~res-x64_0000.txt 
ItemPos1366x664x96(1)     ANALYS~1.TXT   2019-04-18 01:08:50 UTC+0000   2019-04-18 00:57:28 UTC+0000   2019-04-18 00:57:28 UTC+0000   ARC                       Analysis Deatils.txt 
ItemPos1366x664x96(1)     DEPEND~1.LNK   2019-04-13 07:31:04 UTC+0000   2019-04-13 07:31:04 UTC+0000   2019-04-13 07:31:04 UTC+0000   ARC                       depends - Shortcut.lnk 
ItemPos1366x664x96(1)     emotet.txt     2019-04-27 10:30:10 UTC+0000   2019-04-27 10:30:10 UTC+0000   2019-04-27 10:30:10 UTC+0000   ARC                       emotet.txt 
ItemPos1366x664x96(1)     EMOTET~1.HIV   2019-04-27 10:31:40 UTC+0000   2019-04-27 10:31:28 UTC+0000   2019-04-27 10:31:28 UTC+0000   ARC                       emotet-regshot.hivu 
ItemPos1366x664x96(1)     IDAFRE~1.LNK   2019-04-13 08:04:10 UTC+0000   2019-04-13 06:06:32 UTC+0000   2019-04-13 06:06:32 UTC+0000   ARC                       IDA Freeware.lnk 
ItemPos1366x664x96(1)     OLLYDB~1.LNK   2019-04-11 13:33:28 UTC+0000   2019-04-11 13:33:28 UTC+0000   2019-04-11 13:33:28 UTC+0000   ARC                       OLLYDBG - Shortcut.lnk 
ItemPos1366x664x96(1)     PEVIEW~1.LNK   2019-04-13 07:30:38 UTC+0000   2019-04-13 07:30:38 UTC+0000   2019-04-13 07:30:38 UTC+0000   ARC                       PEview - Shortcut.lnk 
ItemPos1366x664x96(1)     PROCES~1.LNK   2019-04-13 08:04:10 UTC+0000   2019-04-13 07:01:52 UTC+0000   2019-04-13 07:01:52 UTC+0000   ARC                       Process Hacker 2.lnk 
ItemPos1366x664x96(1)     REGSHO~1.LNK   2019-04-13 07:41:10 UTC+0000   2019-04-13 07:41:10 UTC+0000   2019-04-13 07:41:10 UTC+0000   ARC                       Regshot-x64-Unicode - Shortcut.lnk 
ItemPos1366x664x96(1)     SAMPLE~1.HIV   2019-04-13 08:03:56 UTC+0000   2019-04-13 08:03:48 UTC+0000   2019-04-13 08:03:48 UTC+0000   ARC                       sample 1.hivu 
ItemPos1366x664x96(1)     WINPCA~1.EXE   2019-04-27 08:53:02 UTC+0000   2019-04-27 10:27:06 UTC+0000   2019-04-27 10:27:06 UTC+0000   ARC                       WinPcap_4_1_3.exe 
***************************************************************************

***************************************************************************
Registry: \??\C:\Users\victim\AppData\Local\Microsoft\Windows\UsrClass.dat 
Key: Local Settings\Software\Microsoft\Windows\Shell\BagMRU
Last updated: 2019-05-02 06:57:18 UTC+0000
Value   Mru   Entry Type     GUID                                     GUID Description     Folder IDs
------- ----- -------------- ---------------------------------------- -------------------- ----------
1       1     Folder Entry   20d04fe0-3aea-1069-a2d8-08002b30309d     My Computer          EXPLORER, MY_COMPUTER 
0       0     Folder Entry   59031a47-3f72-44a7-89c5-5595fe6b30ee     Users                EXPLORER, USERS 
3       6     Folder Entry   dfd5282d-23a3-281f-0400-000000001b28     Unknown GUID         EXPLORER 
2       5     Folder Entry   031e4825-7b94-4dc3-b131-e946b44c8dd5     Libraries            EXPLORER, LIBRARIES 

Value   Mru   File Name      Modified Date                  Create Date                    Access Date                    File Attr                 Path
------- ----- -------------- ------------------------------ ------------------------------ ------------------------------ ------------------------- ----
5       3     LIFEVI~1       2019-04-13 07:46:48 UTC+0000   2019-04-13 07:46:36 UTC+0000   2019-04-13 07:46:48 UTC+0000   DIR                       Life Virus Samples
4       4     NEWFOL~1       2019-04-13 07:46:36 UTC+0000   2019-04-13 07:46:36 UTC+0000   2019-04-13 07:46:36 UTC+0000   DIR                       New folder

Value   Mru   Entry Type     GUID                                     GUID Description     Folder IDs
------- ----- -------------- ---------------------------------------- -------------------- ----------
6       2     Folder Entry   26ee0668-a00a-44d7-9371-beb064c98683     {Unknown CSIDL}      EXPLORER, MY_COMPUTER, RECYCLE_BIN, UKNOWN 
***************************************************************************

***************************************************************************
Registry: \??\C:\Users\victim\AppData\Local\Microsoft\Windows\UsrClass.dat 
Key: Local Settings\Software\Microsoft\Windows\Shell\BagMRU\0
Last updated: 2019-04-27 10:34:04 UTC+0000
Value   Mru   Entry Type     GUID                                     GUID Description     Folder IDs
------- ----- -------------- ---------------------------------------- -------------------- ----------
0       0     Folder         374de290-123f-4565-9164-39c4925e467b     Downloads            EXPLORER 
2       2     Folder         fdd39ad0-238f-46af-adb4-6c85480369c7     Documents            EXPLORER 
***************************************************************************

***************************************************************************
Registry: \??\C:\Users\victim\AppData\Local\Microsoft\Windows\UsrClass.dat 
Key: Local Settings\Software\Microsoft\Windows\Shell\BagMRU\1
Last updated: 2019-05-02 06:57:13 UTC+0000
Value   Mru   Entry Type     Path
------- ----- -------------- ----
1       0     Volume Name    C:\ 
0       2     Volume Name    D:\ 
2       1     Volume Name    Z:\ 
***************************************************************************

***************************************************************************
Registry: \??\C:\Users\victim\AppData\Local\Microsoft\Windows\UsrClass.dat 
Key: Local Settings\Software\Microsoft\Windows\Shell\BagMRU\2
Last updated: 2019-04-13 05:57:11 UTC+0000
Value   Mru   Entry Type     GUID                                     GUID Description     Folder IDs
------- ----- -------------- ---------------------------------------- -------------------- ----------
0       0     Folder         7b0db17d-9cd2-4a93-9733-46cc89022e7c     Documents Library    EXPLORER 
***************************************************************************

***************************************************************************
Registry: \??\C:\Users\victim\AppData\Local\Microsoft\Windows\UsrClass.dat 
Key: Local Settings\Software\Microsoft\Windows\Shell\BagMRU\5
Last updated: 2019-04-23 06:54:48 UTC+0000
Value   Mru   File Name      Modified Date                  Create Date                    Access Date                    File Attr                 Path
------- ----- -------------- ------------------------------ ------------------------------ ------------------------------ ------------------------- ----
1       3     13APRI~1       2019-04-13 07:47:06 UTC+0000   2019-04-13 07:47:06 UTC+0000   2019-04-13 07:47:06 UTC+0000   DIR                       Life Virus Samples\13 April
0       2     NEWFOL~1       2019-04-13 07:47:06 UTC+0000   2019-04-13 07:47:06 UTC+0000   2019-04-13 07:47:06 UTC+0000   DIR                       Life Virus Samples\New folder
3       1     DOC            2019-04-23 06:14:36 UTC+0000   2019-04-23 06:14:36 UTC+0000   2019-04-23 06:14:36 UTC+0000   DIR                       Life Virus Samples\DOC
2       0     18APRI~1       2019-04-18 00:56:50 UTC+0000   2019-04-18 00:56:50 UTC+0000   2019-04-18 00:56:50 UTC+0000   DIR                       Life Virus Samples\18 April
***************************************************************************

***************************************************************************
Registry: \??\C:\Users\victim\AppData\Local\Microsoft\Windows\UsrClass.dat 
Key: Local Settings\Software\Microsoft\Windows\Shell\BagMRU\0\0
Last updated: 2019-04-23 07:37:46 UTC+0000
Value   Mru   File Name      Modified Date                  Create Date                    Access Date                    File Attr                 Path
------- ----- -------------- ------------------------------ ------------------------------ ------------------------------ ------------------------- ----
1       6     HxDSetup       1970-01-01 00:00:00 UTC+0000   1970-01-01 00:00:00 UTC+0000   1970-01-01 00:00:00 UTC+0000   DIR                       HxDSetup
0       3     CaptureBAT-Setup-2.0.0-5574-src 1970-01-01 00:00:00 UTC+0000   1970-01-01 00:00:00 UTC+0000   1970-01-01 00:00:00 UTC+0000   DIR                       CaptureBAT-Setup-2.0.0-5574-src
3       5     NEWFOL~1       2019-04-13 07:40:46 UTC+0000   2019-04-13 07:40:46 UTC+0000   2019-04-13 07:40:46 UTC+0000   DIR                       New folder
2       1     Malware analysis 1970-01-01 00:00:00 UTC+0000   1970-01-01 00:00:00 UTC+0000   1970-01-01 00:00:00 UTC+0000   DIR                       Malware analysis
5       2     CMDWAT~1.3     2019-04-23 05:23:44 UTC+0000   2019-04-23 05:23:44 UTC+0000   2019-04-23 05:23:44 UTC+0000   DIR                       CMDWatcher_v0.3
4       4     Rehshot        2019-04-13 07:40:46 UTC+0000   2019-04-13 07:40:46 UTC+0000   2019-04-13 07:40:46 UTC+0000   DIR                       Rehshot
6       0     OFFICE~1       2019-04-23 05:25:44 UTC+0000   2019-04-23 05:25:44 UTC+0000   2019-04-23 05:25:44 UTC+0000   DIR                       OfficeMalScanner
***************************************************************************

***************************************************************************
Registry: \??\C:\Users\victim\AppData\Local\Microsoft\Windows\UsrClass.dat 
Key: Local Settings\Software\Microsoft\Windows\Shell\BagMRU\0\1
Last updated: 2019-04-11 13:32:18 UTC+0000
Value   Mru   File Name      Modified Date                  Create Date                    Access Date                    File Attr                 Path
------- ----- -------------- ------------------------------ ------------------------------ ------------------------------ ------------------------- ----
0       0     Local          1970-01-01 00:00:00 UTC+0000   1970-01-01 00:00:00 UTC+0000   1970-01-01 00:00:00 UTC+0000   DIR                       Local
***************************************************************************

***************************************************************************
Registry: \??\C:\Users\victim\AppData\Local\Microsoft\Windows\UsrClass.dat 
Key: Local Settings\Software\Microsoft\Windows\Shell\BagMRU\0\2
Last updated: 2019-04-11 13:33:14 UTC+0000
Value   Mru   File Name      Modified Date                  Create Date                    Access Date                    File Attr                 Path
------- ----- -------------- ------------------------------ ------------------------------ ------------------------------ ------------------------- ----
0       0     odbg110        1970-01-01 00:00:00 UTC+0000   1970-01-01 00:00:00 UTC+0000   1970-01-01 00:00:00 UTC+0000   DIR                       odbg110
***************************************************************************

***************************************************************************
Registry: \??\C:\Users\victim\AppData\Local\Microsoft\Windows\UsrClass.dat 
Key: Local Settings\Software\Microsoft\Windows\Shell\BagMRU\1\1
Last updated: 2019-04-27 10:42:05 UTC+0000
Value   Mru   File Name      Modified Date                  Create Date                    Access Date                    File Attr                 Path
------- ----- -------------- ------------------------------ ------------------------------ ------------------------------ ------------------------- ----
1       2     ProgramData    1970-01-01 00:00:00 UTC+0000   1970-01-01 00:00:00 UTC+0000   1970-01-01 00:00:00 UTC+0000   DIR                       C:\ProgramData
0       0     Users          2019-04-10 15:58:54 UTC+0000   2009-07-14 03:20:10 UTC+0000   2019-04-10 15:58:54 UTC+0000   RO, DIR                   C:\Users
2       1     PROGRA~2       2019-04-27 10:27:26 UTC+0000   2009-07-14 03:20:10 UTC+0000   2019-04-27 10:27:26 UTC+0000   RO, DIR                   C:\Program Files (x86)
***************************************************************************

***************************************************************************
Registry: \??\C:\Users\victim\AppData\Local\Microsoft\Windows\UsrClass.dat 
Key: Local Settings\Software\Microsoft\Windows\Shell\BagMRU\1\2
Last updated: 2019-04-27 10:38:19 UTC+0000
Value   Mru   File Name      Modified Date                  Create Date                    Access Date                    File Attr                 Path
------- ----- -------------- ------------------------------ ------------------------------ ------------------------------ ------------------------- ----
0       0     logs           2019-04-27 10:38:22 UTC+0000   2019-04-27 10:38:22 UTC+0000   2019-04-27 10:38:22 UTC+0000   NI, DIR                   Z:\logs
***************************************************************************

***************************************************************************
Registry: \??\C:\Users\victim\AppData\Local\Microsoft\Windows\UsrClass.dat 
Key: Local Settings\Software\Microsoft\Windows\Shell\BagMRU\5\2
Last updated: 2019-04-23 06:54:48 UTC+0000
Value   Mru   File Name      Modified Date                  Create Date                    Access Date                    File Attr                 Path
------- ----- -------------- ------------------------------ ------------------------------ ------------------------------ ------------------------- ----
1       2     NEWFOL~1       2019-04-18 01:16:50 UTC+0000   2019-04-18 01:16:50 UTC+0000   2019-04-18 01:16:50 UTC+0000   DIR                       Life Virus Samples\18 April\New folder
0       0     VIRUSS~1       2019-04-18 00:59:06 UTC+0000   2019-04-18 00:59:06 UTC+0000   2019-04-18 00:59:06 UTC+0000   DIR                       Life Virus Samples\18 April\VirusShare_aa8857f2b367d3e7036e6b788d1d0c3f
2       1     Emotet         2019-04-18 01:16:50 UTC+0000   2019-04-18 01:16:50 UTC+0000   2019-04-18 01:16:50 UTC+0000   DIR                       Life Virus Samples\18 April\Emotet
***************************************************************************

***************************************************************************
Registry: \??\C:\Users\victim\AppData\Local\Microsoft\Windows\UsrClass.dat 
Key: Local Settings\Software\Microsoft\Windows\Shell\BagMRU\5\3
Last updated: 2019-04-23 06:15:54 UTC+0000
Value   Mru   File Name      Modified Date                  Create Date                    Access Date                    File Attr                 Path
------- ----- -------------- ------------------------------ ------------------------------ ------------------------------ ------------------------- ----
0       0     VIRUSS~1       2019-04-23 06:14:56 UTC+0000   2019-04-23 06:14:56 UTC+0000   2019-04-23 06:14:56 UTC+0000   DIR                       Life Virus Samples\DOC\VirusShare_edc7428ec4d6b18e2620aee95347b4fa
***************************************************************************

***************************************************************************
Registry: \??\C:\Users\victim\AppData\Local\Microsoft\Windows\UsrClass.dat 
Key: Local Settings\Software\Microsoft\Windows\Shell\BagMRU\6\0
Last updated: 2019-05-02 06:53:38 UTC+0000
Value   Mru   Entry Type     GUID                                     GUID Description     Folder IDs
------- ----- -------------- ---------------------------------------- -------------------- ----------
0       0     Control Panel  8e908fc9-becc-40f6-915b-f4ca0e70d03d     Network and Sharing Center EXPLORER, MY_GAMES 
***************************************************************************

***************************************************************************
Registry: \??\C:\Users\victim\AppData\Local\Microsoft\Windows\UsrClass.dat 
Key: Local Settings\Software\Microsoft\Windows\Shell\BagMRU\0\0\0
Last updated: 2019-04-13 05:57:48 UTC+0000
Value   Mru   File Name      Modified Date                  Create Date                    Access Date                    File Attr                 Path
------- ----- -------------- ------------------------------ ------------------------------ ------------------------------ ------------------------- ----
0       0     CAPTUR~1       2019-04-13 05:57:48 UTC+0000   2019-04-13 05:57:44 UTC+0000   2019-04-13 05:57:48 UTC+0000   DIR                       CaptureBAT-Setup-2.0.0-5574-src\capture-client
***************************************************************************

***************************************************************************
Registry: \??\C:\Users\victim\AppData\Local\Microsoft\Windows\UsrClass.dat 
Key: Local Settings\Software\Microsoft\Windows\Shell\BagMRU\0\0\2
Last updated: 2019-04-13 07:30:47 UTC+0000
Value   Mru   File Name      Modified Date                  Create Date                    Access Date                    File Attr                 Path
------- ----- -------------- ------------------------------ ------------------------------ ------------------------------ ------------------------- ----
1       0     COMPRE~1       2019-04-13 07:28:12 UTC+0000   2019-04-13 07:28:10 UTC+0000   2019-04-13 07:28:12 UTC+0000   DIR                       Malware analysis\Compressed
0       1     PEview         1970-01-01 00:00:00 UTC+0000   1970-01-01 00:00:00 UTC+0000   1970-01-01 00:00:00 UTC+0000   DIR                       Malware analysis\PEview
***************************************************************************

***************************************************************************
Registry: \??\C:\Users\victim\AppData\Local\Microsoft\Windows\UsrClass.dat 
Key: Local Settings\Software\Microsoft\Windows\Shell\BagMRU\0\0\6
Last updated: 2019-04-23 06:16:06 UTC+0000
Value   Mru   File Name      Modified Date                  Create Date                    Access Date                    File Attr                 Path
------- ----- -------------- ------------------------------ ------------------------------ ------------------------------ ------------------------- ----
0       0     VIRUSS~1       2019-04-23 06:16:06 UTC+0000   2019-04-23 06:16:06 UTC+0000   2019-04-23 06:16:06 UTC+0000   DIR                       OfficeMalScanner\VirusShare_edc7428ec4d6b18e2620aee95347b4fa
***************************************************************************

***************************************************************************
Registry: \??\C:\Users\victim\AppData\Local\Microsoft\Windows\UsrClass.dat 
Key: Local Settings\Software\Microsoft\Windows\Shell\BagMRU\0\1\0
Last updated: 2019-04-11 13:32:18 UTC+0000
Value   Mru   File Name      Modified Date                  Create Date                    Access Date                    File Attr                 Path
------- ----- -------------- ------------------------------ ------------------------------ ------------------------------ ------------------------- ----
0       0     Temp           1970-01-01 00:00:00 UTC+0000   1970-01-01 00:00:00 UTC+0000   1970-01-01 00:00:00 UTC+0000   DIR                       Local\Temp
***************************************************************************

***************************************************************************
Registry: \??\C:\Users\victim\AppData\Local\Microsoft\Windows\UsrClass.dat 
Key: Local Settings\Software\Microsoft\Windows\Shell\BagMRU\1\1\0
Last updated: 2019-04-27 10:33:47 UTC+0000
Value   Mru   File Name      Modified Date                  Create Date                    Access Date                    File Attr                 Path
------- ----- -------------- ------------------------------ ------------------------------ ------------------------------ ------------------------- ----
0       0     victim         2019-04-10 15:59:34 UTC+0000   2019-04-10 15:58:54 UTC+0000   2019-04-10 15:59:34 UTC+0000   DIR                       C:\Users\victim
***************************************************************************

***************************************************************************
Registry: \??\C:\Users\victim\AppData\Local\Microsoft\Windows\UsrClass.dat 
Key: Local Settings\Software\Microsoft\Windows\Shell\BagMRU\1\1\1
Last updated: 2019-04-27 10:34:47 UTC+0000
Value   Mru   File Name      Modified Date                  Create Date                    Access Date                    File Attr                 Path
------- ----- -------------- ------------------------------ ------------------------------ ------------------------------ ------------------------- ----
0       0     Microsoft      1970-01-01 00:00:00 UTC+0000   1970-01-01 00:00:00 UTC+0000   1970-01-01 00:00:00 UTC+0000   DIR                       C:\ProgramData\Microsoft
***************************************************************************

***************************************************************************
Registry: \??\C:\Users\victim\AppData\Local\Microsoft\Windows\UsrClass.dat 
Key: Local Settings\Software\Microsoft\Windows\Shell\BagMRU\1\1\2
Last updated: 2019-04-27 10:38:03 UTC+0000
Value   Mru   File Name      Modified Date                  Create Date                    Access Date                    File Attr                 Path
------- ----- -------------- ------------------------------ ------------------------------ ------------------------------ ------------------------- ----
0       0     Capture        2019-04-27 10:36:06 UTC+0000   2019-04-18 00:49:00 UTC+0000   2019-04-27 10:36:06 UTC+0000   DIR                       C:\Program Files (x86)\Capture
***************************************************************************

***************************************************************************
Registry: \??\C:\Users\victim\AppData\Local\Microsoft\Windows\UsrClass.dat 
Key: Local Settings\Software\Microsoft\Windows\Shell\BagMRU\1\2\0
Last updated: 2019-04-27 10:48:33 UTC+0000
Value   Mru   File Name      Modified Date                  Create Date                    Access Date                    File Attr                 Path
------- ----- -------------- ------------------------------ ------------------------------ ------------------------------ ------------------------- ----
0       0     deleted_files  2019-04-27 10:30:26 UTC+0000   2019-04-27 10:38:24 UTC+0000   2019-04-27 10:38:24 UTC+0000   NI, DIR                   Z:\logs\deleted_files
***************************************************************************

***************************************************************************
Registry: \??\C:\Users\victim\AppData\Local\Microsoft\Windows\UsrClass.dat 
Key: Local Settings\Software\Microsoft\Windows\Shell\BagMRU\5\2\2
Last updated: 2019-04-23 06:14:25 UTC+0000
Value   Mru   File Name      Modified Date                  Create Date                    Access Date                    File Attr                 Path
------- ----- -------------- ------------------------------ ------------------------------ ------------------------------ ------------------------- ----
1       0     NEWFOL~1       2019-04-23 06:14:26 UTC+0000   2019-04-23 06:14:26 UTC+0000   2019-04-23 06:14:26 UTC+0000   DIR                       Life Virus Samples\18 April\Emotet\New folder
0       1     VIRUSS~1       2019-04-18 01:17:14 UTC+0000   2019-04-18 01:17:14 UTC+0000   2019-04-18 01:17:14 UTC+0000   DIR                       Life Virus Samples\18 April\Emotet\VirusShare_05c632fe8ab2727adc9ac7b1b59c3be8
***************************************************************************

***************************************************************************
Registry: \??\C:\Users\victim\AppData\Local\Microsoft\Windows\UsrClass.dat 
Key: Local Settings\Software\Microsoft\Windows\Shell\BagMRU\6\0\0
Last updated: 2019-05-02 06:53:52 UTC+0000
Value   Mru   Entry Type     GUID                                     GUID Description     Folder IDs
------- ----- -------------- ---------------------------------------- -------------------- ----------
0       0     Folder (unsupported) This property is not yet supported                             
***************************************************************************

***************************************************************************
Registry: \??\C:\Users\victim\AppData\Local\Microsoft\Windows\UsrClass.dat 
Key: Local Settings\Software\Microsoft\Windows\Shell\BagMRU\0\0\0\0
Last updated: 2019-04-13 08:05:26 UTC+0000
Value   Mru   File Name      Modified Date                  Create Date                    Access Date                    File Attr                 Path
------- ----- -------------- ------------------------------ ------------------------------ ------------------------------ ------------------------- ----
1       0     SETUPS~1       2019-04-13 05:57:48 UTC+0000   2019-04-13 05:57:48 UTC+0000   2019-04-13 05:57:48 UTC+0000   DIR                       CaptureBAT-Setup-2.0.0-5574-src\capture-client\SetupScript
0       1     APPLIC~1       2019-04-13 05:57:46 UTC+0000   2019-04-13 05:57:46 UTC+0000   2019-04-13 05:57:46 UTC+0000   DIR                       CaptureBAT-Setup-2.0.0-5574-src\capture-client\ApplicationConfig
***************************************************************************

***************************************************************************
Registry: \??\C:\Users\victim\AppData\Local\Microsoft\Windows\UsrClass.dat 
Key: Local Settings\Software\Microsoft\Windows\Shell\BagMRU\0\0\2\1
Last updated: 2019-04-13 07:30:47 UTC+0000
Value   Mru   File Name      Modified Date                  Create Date                    Access Date                    File Attr                 Path
------- ----- -------------- ------------------------------ ------------------------------ ------------------------------ ------------------------- ----
0       0     DEPEND~1       2019-04-13 07:28:12 UTC+0000   2019-04-13 07:28:12 UTC+0000   2019-04-13 07:28:12 UTC+0000   DIR                       Malware analysis\Compressed\depends22_x86
***************************************************************************

***************************************************************************
Registry: \??\C:\Users\victim\AppData\Local\Microsoft\Windows\UsrClass.dat 
Key: Local Settings\Software\Microsoft\Windows\Shell\BagMRU\0\1\0\0
Last updated: 2019-04-27 10:33:36 UTC+0000
Value   Mru   File Name      Modified Date                  Create Date                    Access Date                    File Attr                 Path
------- ----- -------------- ------------------------------ ------------------------------ ------------------------------ ------------------------- ----
1       3     VBE            2019-04-23 07:26:08 UTC+0000   2019-04-23 07:26:08 UTC+0000   2019-04-23 07:26:08 UTC+0000   NI, DIR                   Local\Temp\VBE
0       4     odbg110.zip    1970-01-01 00:00:00 UTC+0000   1970-01-01 00:00:00 UTC+0000   1970-01-01 00:00:00 UTC+0000   ARC, RO, NI               Local\Temp\odbg110.zip
3       1     TCD9405.tmp    2019-04-27 10:33:16 UTC+0000   2019-04-27 10:33:16 UTC+0000   2019-04-27 10:33:16 UTC+0000   NI, DIR                   Local\Temp\TCD9405.tmp
2       2     Low            2019-04-11 13:20:34 UTC+0000   2019-04-10 15:59:10 UTC+0000   2019-04-11 13:20:34 UTC+0000   NI, DIR                   Local\Temp\Low
4       0     TCD9312.tmp    2019-04-27 10:33:16 UTC+0000   2019-04-27 10:33:16 UTC+0000   2019-04-27 10:33:16 UTC+0000   NI, DIR                   Local\Temp\TCD9312.tmp
***************************************************************************

***************************************************************************
Registry: \??\C:\Users\victim\AppData\Local\Microsoft\Windows\UsrClass.dat 
Key: Local Settings\Software\Microsoft\Windows\Shell\BagMRU\1\1\0\0
Last updated: 2019-04-27 10:42:05 UTC+0000
Value   Mru   File Name      Modified Date                  Create Date                    Access Date                    File Attr                 Path
------- ----- -------------- ------------------------------ ------------------------------ ------------------------------ ------------------------- ----
1       1     AppData        2019-04-10 15:59:04 UTC+0000   2019-04-10 15:59:04 UTC+0000   2019-04-10 15:59:04 UTC+0000   HID, NI, DIR              C:\Users\victim\AppData
0       0     DOWNLO~1       2019-04-13 06:05:32 UTC+0000   2019-04-10 15:59:04 UTC+0000   2019-04-13 06:05:32 UTC+0000   RO, DIR                   C:\Users\victim\Downloads
***************************************************************************

***************************************************************************
Registry: \??\C:\Users\victim\AppData\Local\Microsoft\Windows\UsrClass.dat 
Key: Local Settings\Software\Microsoft\Windows\Shell\BagMRU\1\1\1\0
Last updated: 2019-04-27 10:34:50 UTC+0000
Value   Mru   File Name      Modified Date                  Create Date                    Access Date                    File Attr                 Path
------- ----- -------------- ------------------------------ ------------------------------ ------------------------------ ------------------------- ----
0       0     Windows        1970-01-01 00:00:00 UTC+0000   1970-01-01 00:00:00 UTC+0000   1970-01-01 00:00:00 UTC+0000   DIR                       C:\ProgramData\Microsoft\Windows
***************************************************************************

***************************************************************************
Registry: \??\C:\Users\victim\AppData\Local\Microsoft\Windows\UsrClass.dat 
Key: Local Settings\Software\Microsoft\Windows\Shell\BagMRU\1\1\2\0
Last updated: 2019-04-27 10:38:03 UTC+0000
Value   Mru   File Name      Modified Date                  Create Date                    Access Date                    File Attr                 Path
------- ----- -------------- ------------------------------ ------------------------------ ------------------------------ ------------------------- ----
0       0     CAPTUR~2.ZIP   2019-04-27 10:36:06 UTC+0000   2019-04-27 10:36:06 UTC+0000   2019-04-27 10:36:06 UTC+0000   ARC                       C:\Program Files (x86)\Capture\capture_2742019_336.zip
***************************************************************************

***************************************************************************
Registry: \??\C:\Users\victim\AppData\Local\Microsoft\Windows\UsrClass.dat 
Key: Local Settings\Software\Microsoft\Windows\Shell\BagMRU\1\1\0\0\0
Last updated: 2019-04-23 06:45:21 UTC+0000
Value   Mru   File Name      Modified Date                  Create Date                    Access Date                    File Attr                 Path
------- ----- -------------- ------------------------------ ------------------------------ ------------------------------ ------------------------- ----
1       0     MICROS~1       2019-04-23 06:41:02 UTC+0000   2019-04-23 06:41:02 UTC+0000   2019-04-23 06:41:02 UTC+0000   DIR                       C:\Users\victim\Downloads\Microsoft Office Enterprise 2010 Corporate Final (full activated)
0       1     OFFICE~1       2019-04-23 05:25:44 UTC+0000   2019-04-23 05:25:44 UTC+0000   2019-04-23 05:25:44 UTC+0000   DIR                       C:\Users\victim\Downloads\OfficeMalScanner
***************************************************************************

***************************************************************************
Registry: \??\C:\Users\victim\AppData\Local\Microsoft\Windows\UsrClass.dat 
Key: Local Settings\Software\Microsoft\Windows\Shell\BagMRU\1\1\0\0\1
Last updated: 2019-04-27 10:34:40 UTC+0000
Value   Mru   File Name      Modified Date                  Create Date                    Access Date                    File Attr                 Path
------- ----- -------------- ------------------------------ ------------------------------ ------------------------------ ------------------------- ----
1       0     Local          2019-04-13 05:59:52 UTC+0000   2019-04-10 15:59:04 UTC+0000   2019-04-13 05:59:52 UTC+0000   NI, DIR                   C:\Users\victim\AppData\Local
0       2     Roaming        2019-04-13 06:00:42 UTC+0000   2019-04-10 15:59:04 UTC+0000   2019-04-13 06:00:42 UTC+0000   NI, DIR                   C:\Users\victim\AppData\Roaming
2       1     LocalLow       2019-04-11 13:29:20 UTC+0000   2019-04-10 15:59:04 UTC+0000   2019-04-11 13:29:20 UTC+0000   NI, DIR                   C:\Users\victim\AppData\LocalLow
***************************************************************************

***************************************************************************
Registry: \??\C:\Users\victim\AppData\Local\Microsoft\Windows\UsrClass.dat 
Key: Local Settings\Software\Microsoft\Windows\Shell\BagMRU\1\1\1\0\0
Last updated: 2019-04-13 07:39:46 UTC+0000
Value   Mru   File Name      Modified Date                  Create Date                    Access Date                    File Attr                 Path
------- ----- -------------- ------------------------------ ------------------------------ ------------------------------ ------------------------- ----
0       0     Start Menu     1970-01-01 00:00:00 UTC+0000   1970-01-01 00:00:00 UTC+0000   1970-01-01 00:00:00 UTC+0000   DIR                       C:\ProgramData\Microsoft\Windows\Start Menu
***************************************************************************

***************************************************************************
Registry: \??\C:\Users\victim\AppData\Local\Microsoft\Windows\UsrClass.dat 
Key: Local Settings\Software\Microsoft\Windows\Shell\BagMRU\1\1\0\0\0\1
Last updated: 2019-04-23 06:45:23 UTC+0000
Value   Mru   File Name      Modified Date                  Create Date                    Access Date                    File Attr                 Path
------- ----- -------------- ------------------------------ ------------------------------ ------------------------------ ------------------------- ----
0       0     MICROS~1       2019-04-23 06:44:46 UTC+0000   2019-04-23 06:41:02 UTC+0000   2019-04-23 06:44:46 UTC+0000   DIR                       C:\Users\victim\Downloads\Microsoft Office Enterprise 2010 Corporate Final (full activated)\Microsoft Office Enterprise 2010 Corporate Final (full activated)
***************************************************************************

***************************************************************************
Registry: \??\C:\Users\victim\AppData\Local\Microsoft\Windows\UsrClass.dat 
Key: Local Settings\Software\Microsoft\Windows\Shell\BagMRU\1\1\0\0\1\0
Last updated: 2019-04-27 10:34:26 UTC+0000
Value   Mru   File Name      Modified Date                  Create Date                    Access Date                    File Attr                 Path
------- ----- -------------- ------------------------------ ------------------------------ ------------------------------ ------------------------- ----
0       0     MICROS~1       2019-04-11 13:29:10 UTC+0000   2019-04-10 15:59:04 UTC+0000   2019-04-11 13:29:10 UTC+0000   SYS, NI, DIR              C:\Users\victim\AppData\Roaming\Microsoft
***************************************************************************

***************************************************************************
Registry: \??\C:\Users\victim\AppData\Local\Microsoft\Windows\UsrClass.dat 
Key: Local Settings\Software\Microsoft\Windows\Shell\BagMRU\1\1\0\0\1\1
Last updated: 2019-04-27 10:34:40 UTC+0000
Value   Mru   File Name      Modified Date                  Create Date                    Access Date                    File Attr                 Path
------- ----- -------------- ------------------------------ ------------------------------ ------------------------------ ------------------------- ----
0       0     Temp           2019-04-23 05:21:58 UTC+0000   2019-04-10 15:59:04 UTC+0000   2019-04-23 05:21:58 UTC+0000   NI, DIR                   C:\Users\victim\AppData\Local\Temp
***************************************************************************

***************************************************************************
Registry: \??\C:\Users\victim\AppData\Local\Microsoft\Windows\UsrClass.dat 
Key: Local Settings\Software\Microsoft\Windows\Shell\BagMRU\1\1\0\0\1\2
Last updated: 2019-04-27 10:34:35 UTC+0000
Value   Mru   File Name      Modified Date                  Create Date                    Access Date                    File Attr                 Path
------- ----- -------------- ------------------------------ ------------------------------ ------------------------------ ------------------------- ----
0       0     Mozilla        2019-04-23 07:08:44 UTC+0000   2019-04-11 13:29:20 UTC+0000   2019-04-23 07:08:44 UTC+0000   NI, DIR                   C:\Users\victim\AppData\LocalLow\Mozilla
***************************************************************************

***************************************************************************
Registry: \??\C:\Users\victim\AppData\Local\Microsoft\Windows\UsrClass.dat 
Key: Local Settings\Software\Microsoft\Windows\Shell\BagMRU\1\1\1\0\0\0
Last updated: 2019-04-13 07:39:46 UTC+0000
Value   Mru   File Name      Modified Date                  Create Date                    Access Date                    File Attr                 Path
------- ----- -------------- ------------------------------ ------------------------------ ------------------------------ ------------------------- ----
0       0     Programs       1970-01-01 00:00:00 UTC+0000   1970-01-01 00:00:00 UTC+0000   1970-01-01 00:00:00 UTC+0000   DIR                       C:\ProgramData\Microsoft\Windows\Start Menu\Programs
***************************************************************************

***************************************************************************
Registry: \??\C:\Users\victim\AppData\Local\Microsoft\Windows\UsrClass.dat 
Key: Local Settings\Software\Microsoft\Windows\Shell\BagMRU\1\1\0\0\1\0\0
Last updated: 2019-04-13 07:35:42 UTC+0000
Value   Mru   File Name      Modified Date                  Create Date                    Access Date                    File Attr                 Path
------- ----- -------------- ------------------------------ ------------------------------ ------------------------------ ------------------------- ----
0       0     Windows        2019-04-10 15:59:34 UTC+0000   2019-04-10 15:59:04 UTC+0000   2019-04-10 15:59:34 UTC+0000   NI, DIR                   C:\Users\victim\AppData\Roaming\Microsoft\Windows
***************************************************************************

***************************************************************************
Registry: \??\C:\Users\victim\AppData\Local\Microsoft\Windows\UsrClass.dat 
Key: Local Settings\Software\Microsoft\Windows\Shell\BagMRU\1\1\1\0\0\0\0
Last updated: 2019-04-13 07:39:48 UTC+0000
Value   Mru   File Name      Modified Date                  Create Date                    Access Date                    File Attr                 Path
------- ----- -------------- ------------------------------ ------------------------------ ------------------------------ ------------------------- ----
0       0     WinRAR         1970-01-01 00:00:00 UTC+0000   1970-01-01 00:00:00 UTC+0000   1970-01-01 00:00:00 UTC+0000   DIR                       C:\ProgramData\Microsoft\Windows\Start Menu\Programs\WinRAR
***************************************************************************

***************************************************************************
Registry: \??\C:\Users\victim\AppData\Local\Microsoft\Windows\UsrClass.dat 
Key: Local Settings\Software\Microsoft\Windows\Shell\BagMRU\1\1\0\0\1\0\0\0
Last updated: 2019-04-13 07:35:42 UTC+0000
Value   Mru   File Name      Modified Date                  Create Date                    Access Date                    File Attr                 Path
------- ----- -------------- ------------------------------ ------------------------------ ------------------------------ ------------------------- ----
0       0     STARTM~1       2019-04-10 16:01:04 UTC+0000   2019-04-10 15:59:04 UTC+0000   2019-04-10 15:59:34 UTC+0000   RO, DIR                   C:\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu
***************************************************************************
```



## Task2

1.
```
$ ./Documents/volatility/volatility_sa -f Downloads/victim.raw --profile=Win7SP1x64 netscan

Volatility Foundation Volatility Framework 2.6
Offset(P)          Proto    Local Address                  Foreign Address      State            Pid      Owner          Created
0x5c201ca0         UDPv4    0.0.0.0:5005                   *:*                                   2464     wmpnetwk.exe   2019-05-02 18:05:14 UTC+0000
0x5c201ca0         UDPv6    :::5005                        *:*                                   2464     wmpnetwk.exe   2019-05-02 18:05:14 UTC+0000
0x5c49cbb0         UDPv4    0.0.0.0:59471                  *:*                                   1368     svchost.exe    2019-05-02 18:03:06 UTC+0000
0x5c4a31c0         UDPv4    0.0.0.0:59472                  *:*                                   1368     svchost.exe    2019-05-02 18:03:06 UTC+0000
0x5c4a31c0         UDPv6    :::59472                       *:*                                   1368     svchost.exe    2019-05-02 18:03:06 UTC+0000
0x5c4ac630         UDPv4    0.0.0.0:3702                   *:*                                   1368     svchost.exe    2019-05-02 18:03:14 UTC+0000
0x5c4ac630         UDPv6    :::3702                        *:*                                   1368     svchost.exe    2019-05-02 18:03:14 UTC+0000
0x5c519b30         UDPv4    0.0.0.0:3702                   *:*                                   1368     svchost.exe    2019-05-02 18:03:14 UTC+0000
0x5c537ec0         UDPv4    0.0.0.0:3702                   *:*                                   1368     svchost.exe    2019-05-02 18:03:14 UTC+0000
0x5c690360         UDPv4    0.0.0.0:0                      *:*                                   1004     svchost.exe    2019-05-02 18:02:56 UTC+0000
0x5c690360         UDPv6    :::0                           *:*                                   1004     svchost.exe    2019-05-02 18:02:56 UTC+0000
0x5c6918e0         UDPv4    0.0.0.0:5355                   *:*                                   1004     svchost.exe    2019-05-02 18:02:56 UTC+0000
0x5c6918e0         UDPv6    :::5355                        *:*                                   1004     svchost.exe    2019-05-02 18:02:56 UTC+0000
0x5c692940         UDPv4    0.0.0.0:5005                   *:*                                   2464     wmpnetwk.exe   2019-05-02 18:05:14 UTC+0000
0x5c692ae0         UDPv4    0.0.0.0:5355                   *:*                                   1004     svchost.exe    2019-05-02 18:02:56 UTC+0000
0x5c7bac70         UDPv4    0.0.0.0:5004                   *:*                                   2464     wmpnetwk.exe   2019-05-02 18:05:14 UTC+0000
0x5c7bac70         UDPv6    :::5004                        *:*                                   2464     wmpnetwk.exe   2019-05-02 18:05:14 UTC+0000
0x5c7f9600         UDPv4    0.0.0.0:3702                   *:*                                   1368     svchost.exe    2019-05-02 18:03:14 UTC+0000
0x5c7f9600         UDPv6    :::3702                        *:*                                   1368     svchost.exe    2019-05-02 18:03:14 UTC+0000
0x5c44e1b0         TCPv4    0.0.0.0:5357                   0.0.0.0:0            LISTENING        4        System         
0x5c44e1b0         TCPv6    :::5357                        :::0                 LISTENING        4        System         
0x5c528010         TCPv4    0.0.0.0:445                    0.0.0.0:0            LISTENING        4        System         
0x5c528010         TCPv6    :::445                         :::0                 LISTENING        4        System         
0x5c534c60         TCPv4    0.0.0.0:49156                  0.0.0.0:0            LISTENING        504      services.exe   
0x5c534c60         TCPv6    :::49156                       :::0                 LISTENING        504      services.exe   
0x5c535010         TCPv4    0.0.0.0:49156                  0.0.0.0:0            LISTENING        504      services.exe   
0x5c6de720         TCPv4    0.0.0.0:49154                  0.0.0.0:0            LISTENING        920      svchost.exe    
0x5c6de720         TCPv6    :::49154                       :::0                 LISTENING        920      svchost.exe    
0x5c6e0df0         TCPv4    0.0.0.0:49154                  0.0.0.0:0            LISTENING        920      svchost.exe    
0x5c717460         TCPv4    0.0.0.0:49155                  0.0.0.0:0            LISTENING        512      lsass.exe      
0x5ca3ecc0         UDPv6    ::1:1900                       *:*                                   1368     svchost.exe    2019-05-02 18:05:13 UTC+0000
0x5ca452c0         UDPv6    fe80::6998:27e6:5653:fc35:1900 *:*                                   1368     svchost.exe    2019-05-02 18:05:13 UTC+0000
0x5ca4c2c0         UDPv6    fe80::1503:ac56:439f:bb6c:1900 *:*                                   1368     svchost.exe    2019-05-02 18:05:13 UTC+0000
0x5ca517c0         UDPv4    0.0.0.0:5004                   *:*                                   2464     wmpnetwk.exe   2019-05-02 18:05:14 UTC+0000
0x5ca5a7c0         UDPv4    127.0.0.1:1900                 *:*                                   1368     svchost.exe    2019-05-02 18:05:13 UTC+0000
0x5ca5d7c0         UDPv4    169.254.252.53:1900            *:*                                   1368     svchost.exe    2019-05-02 18:05:13 UTC+0000
0x5ca655a0         UDPv4    127.0.0.1:61556                *:*                                   1368     svchost.exe    2019-05-02 18:05:13 UTC+0000
0x5caa6250         UDPv4    192.168.35.2:138               *:*                                   4        System         2019-05-03 06:32:31 UTC+0000
0x5cab3010         UDPv4    192.168.35.2:137               *:*                                   4        System         2019-05-03 06:32:31 UTC+0000
0x5cab65a0         UDPv4    169.254.252.53:137             *:*                                   4        System         2019-05-03 06:32:40 UTC+0000
0x5caefec0         UDPv4    169.254.252.53:138             *:*                                   4        System         2019-05-03 06:32:40 UTC+0000
0x5c932da0         TCPv4    0.0.0.0:135                    0.0.0.0:0            LISTENING        752      svchost.exe    
0x5c948330         TCPv4    0.0.0.0:135                    0.0.0.0:0            LISTENING        752      svchost.exe    
0x5c948330         TCPv6    :::135                         :::0                 LISTENING        752      svchost.exe    
0x5c9541a0         TCPv4    0.0.0.0:49152                  0.0.0.0:0            LISTENING        416      wininit.exe    
0x5c9541a0         TCPv6    :::49152                       :::0                 LISTENING        416      wininit.exe    
0x5c954900         TCPv4    0.0.0.0:49152                  0.0.0.0:0            LISTENING        416      wininit.exe    
0x5c996bd0         TCPv4    0.0.0.0:49153                  0.0.0.0:0            LISTENING        852      svchost.exe    
0x5c996bd0         TCPv6    :::49153                       :::0                 LISTENING        852      svchost.exe    
0x5c99c180         TCPv4    0.0.0.0:49153                  0.0.0.0:0            LISTENING        852      svchost.exe    
0x5cab60e0         TCPv4    192.168.35.2:139               0.0.0.0:0            LISTENING        4        System         
0x5cab95d0         TCPv4    169.254.252.53:139             0.0.0.0:0            LISTENING        4        System         
0x5cabcdd0         TCPv4    0.0.0.0:554                    0.0.0.0:0            LISTENING        2464     wmpnetwk.exe   
0x5cdd2950         TCPv4    0.0.0.0:49155                  0.0.0.0:0            LISTENING        512      lsass.exe      
0x5cdd2950         TCPv6    :::49155                       :::0                 LISTENING        512      lsass.exe      
0x5c949290         TCPv6    -:0                            c801:b602:80fa:ffff:c801:b602:80fa:ffff:0 CLOSED           1        ?????????????? 
0x5cad94a0         TCPv6    -:49158                        ::1:2869             CLOSED           2464     wmpnetwk.exe   
0x5d5e8960         TCPv4    0.0.0.0:10243                  0.0.0.0:0            LISTENING        4        System         
0x5d5e8960         TCPv6    :::10243                       :::0                 LISTENING        4        System         
0x5d5f79c0         TCPv4    0.0.0.0:554                    0.0.0.0:0            LISTENING        2464     wmpnetwk.exe   
0x5d5f79c0         TCPv6    :::554                         :::0                 LISTENING        2464     wmpnetwk.exe   
0x5de66420         UDPv4    0.0.0.0:0                      *:*                                   688      VBoxService.ex 2019-05-02 18:11:42 UTC+0000
0x5e00dbe0         UDPv6    fe80::1503:ac56:439f:bb6c:546  *:*                                   852      svchost.exe    2019-05-02 18:10:03 UTC+0000
0x5e0e43b0         UDPv4    0.0.0.0:68                     *:*                                   852      svchost.exe    2019-05-02 18:09:56 UTC+0000
0x5e11d1b0         UDPv6    fe80::6998:27e6:5653:fc35:546  *:*                                   852      svchost.exe    2019-05-02 18:10:03 UTC+0000
0x5e2a6010         UDPv6    ::1:61555                      *:*                                   1368     svchost.exe    2019-05-02 18:05:13 UTC+0000
0x5e37e680         UDPv4    192.168.35.2:1900              *:*                                   1368     svchost.exe    2019-05-02 18:05:13 UTC+0000
0x5e354410         TCPv4    0.0.0.0:2869                   0.0.0.0:0            LISTENING        4        System         
0x5e354410         TCPv6    :::2869                        :::0                 LISTENING        4        System         
0x5e362010         TCPv6    -:2869                         ::1:49158            CLOSED           4        System  
```

2.
```
$ ./Documents/volatility/volatility_sa -f Downloads/victim.raw --profile=Win7SP1x64 malfind -D /Documents/Forensics
Volatility Foundation Volatility Framework 2.6
Process: explorer.exe Pid: 1860 Address: 0x3ee0000
Vad Tag: VadS Protection: PAGE_EXECUTE_READWRITE
Flags: CommitCharge: 1, MemCommit: 1, PrivateMemory: 1, Protection: 6

0x03ee0000  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0x03ee0010  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0x03ee0020  00 00 ee 03 00 00 00 00 00 00 00 00 00 00 00 00   ................
0x03ee0030  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................

0x03ee0000 0000             ADD [EAX], AL
0x03ee0002 0000             ADD [EAX], AL
0x03ee0004 0000             ADD [EAX], AL
0x03ee0006 0000             ADD [EAX], AL
0x03ee0008 0000             ADD [EAX], AL
0x03ee000a 0000             ADD [EAX], AL
0x03ee000c 0000             ADD [EAX], AL
0x03ee000e 0000             ADD [EAX], AL
0x03ee0010 0000             ADD [EAX], AL
0x03ee0012 0000             ADD [EAX], AL
0x03ee0014 0000             ADD [EAX], AL
0x03ee0016 0000             ADD [EAX], AL
0x03ee0018 0000             ADD [EAX], AL
0x03ee001a 0000             ADD [EAX], AL
0x03ee001c 0000             ADD [EAX], AL
0x03ee001e 0000             ADD [EAX], AL
0x03ee0020 0000             ADD [EAX], AL
0x03ee0022 ee               OUT DX, AL
0x03ee0023 0300             ADD EAX, [EAX]
0x03ee0025 0000             ADD [EAX], AL
0x03ee0027 0000             ADD [EAX], AL
0x03ee0029 0000             ADD [EAX], AL
0x03ee002b 0000             ADD [EAX], AL
0x03ee002d 0000             ADD [EAX], AL
0x03ee002f 0000             ADD [EAX], AL
0x03ee0031 0000             ADD [EAX], AL
0x03ee0033 0000             ADD [EAX], AL
0x03ee0035 0000             ADD [EAX], AL
0x03ee0037 0000             ADD [EAX], AL
0x03ee0039 0000             ADD [EAX], AL
0x03ee003b 0000             ADD [EAX], AL
0x03ee003d 0000             ADD [EAX], AL
0x03ee003f 00               DB 0x0

Process: explorer.exe Pid: 1860 Address: 0x3f90000
Vad Tag: VadS Protection: PAGE_EXECUTE_READWRITE
Flags: CommitCharge: 2, PrivateMemory: 1, Protection: 6

0x03f90000  00 00 00 00 00 00 00 00 4b 5b b2 8d 2d d2 00 01   ........K[..-...
0x03f90010  ee ff ee ff 00 00 00 00 28 01 f9 03 00 00 00 00   ........(.......
0x03f90020  28 01 f9 03 00 00 00 00 00 00 f9 03 00 00 00 00   (...............
0x03f90030  00 00 f9 03 00 00 00 00 80 00 00 00 00 00 00 00   ................

0x03f90000 0000             ADD [EAX], AL
0x03f90002 0000             ADD [EAX], AL
0x03f90004 0000             ADD [EAX], AL
0x03f90006 0000             ADD [EAX], AL
0x03f90008 4b               DEC EBX
0x03f90009 5b               POP EBX
0x03f9000a b28d             MOV DL, 0x8d
0x03f9000c 2dd20001ee       SUB EAX, 0xee0100d2
0x03f90011 ff               DB 0xff
0x03f90012 ee               OUT DX, AL
0x03f90013 ff00             INC DWORD [EAX]
0x03f90015 0000             ADD [EAX], AL
0x03f90017 0028             ADD [EAX], CH
0x03f90019 01f9             ADD ECX, EDI
0x03f9001b 0300             ADD EAX, [EAX]
0x03f9001d 0000             ADD [EAX], AL
0x03f9001f 0028             ADD [EAX], CH
0x03f90021 01f9             ADD ECX, EDI
0x03f90023 0300             ADD EAX, [EAX]
0x03f90025 0000             ADD [EAX], AL
0x03f90027 0000             ADD [EAX], AL
0x03f90029 00f9             ADD CL, BH
0x03f9002b 0300             ADD EAX, [EAX]
0x03f9002d 0000             ADD [EAX], AL
0x03f9002f 0000             ADD [EAX], AL
0x03f90031 00f9             ADD CL, BH
0x03f90033 0300             ADD EAX, [EAX]
0x03f90035 0000             ADD [EAX], AL
0x03f90037 008000000000     ADD [EAX+0x0], AL
0x03f9003d 0000             ADD [EAX], AL
0x03f9003f 00               DB 0x0

Process: svchost.exe Pid: 1820 Address: 0x24f0000
Vad Tag: VadS Protection: PAGE_EXECUTE_READWRITE
Flags: CommitCharge: 128, MemCommit: 1, PrivateMemory: 1, Protection: 6

0x024f0000  20 00 00 00 e0 ff 07 00 0c 00 00 00 01 00 05 00   ................
0x024f0010  00 42 00 50 00 30 00 70 00 60 00 00 00 00 00 00   .B.P.0.p.`......
0x024f0020  48 8b 45 28 c7 00 00 00 00 00 c7 40 04 00 00 00   H.E(.......@....
0x024f0030  00 48 8b 45 28 48 8d 40 08 48 89 c2 48 8b 45 20   .H.E(H.@.H..H.E.

0x024f0000 2000             AND [EAX], AL
0x024f0002 0000             ADD [EAX], AL
0x024f0004 e0ff             LOOPNZ 0x24f0005
0x024f0006 07               POP ES
0x024f0007 000c00           ADD [EAX+EAX], CL
0x024f000a 0000             ADD [EAX], AL
0x024f000c 0100             ADD [EAX], EAX
0x024f000e 0500004200       ADD EAX, 0x420000
0x024f0013 50               PUSH EAX
0x024f0014 0030             ADD [EAX], DH
0x024f0016 007000           ADD [EAX+0x0], DH
0x024f0019 60               PUSHA
0x024f001a 0000             ADD [EAX], AL
0x024f001c 0000             ADD [EAX], AL
0x024f001e 0000             ADD [EAX], AL
0x024f0020 48               DEC EAX
0x024f0021 8b4528           MOV EAX, [EBP+0x28]
0x024f0024 c70000000000     MOV DWORD [EAX], 0x0
0x024f002a c7400400000000   MOV DWORD [EAX+0x4], 0x0
0x024f0031 48               DEC EAX
0x024f0032 8b4528           MOV EAX, [EBP+0x28]
0x024f0035 48               DEC EAX
0x024f0036 8d4008           LEA EAX, [EAX+0x8]
0x024f0039 48               DEC EAX
0x024f003a 89c2             MOV EDX, EAX
0x024f003c 48               DEC EAX
0x024f003d 8b4520           MOV EAX, [EBP+0x20]

Process: svchost.exe Pid: 1820 Address: 0x4d90000
Vad Tag: VadS Protection: PAGE_EXECUTE_READWRITE
Flags: CommitCharge: 256, MemCommit: 1, PrivateMemory: 1, Protection: 6

0x04d90000  20 00 00 00 e0 ff 0f 00 0c 00 00 00 01 00 05 00   ................
0x04d90010  00 42 00 50 00 30 00 70 00 60 00 00 00 00 00 00   .B.P.0.p.`......
0x04d90020  ba fc ff ff ff 03 55 20 03 55 5c b9 04 00 1a 00   ......U..U\.....
0x04d90030  4c 8b c5 ff 95 e0 37 00 00 8b 4d 24 89 08 48 8d   L.....7...M$..H.

0x04d90000 2000             AND [EAX], AL
0x04d90002 0000             ADD [EAX], AL
0x04d90004 e0ff             LOOPNZ 0x4d90005
0x04d90006 0f000c00         STR WORD [EAX+EAX]
0x04d9000a 0000             ADD [EAX], AL
0x04d9000c 0100             ADD [EAX], EAX
0x04d9000e 0500004200       ADD EAX, 0x420000
0x04d90013 50               PUSH EAX
0x04d90014 0030             ADD [EAX], DH
0x04d90016 007000           ADD [EAX+0x0], DH
0x04d90019 60               PUSHA
0x04d9001a 0000             ADD [EAX], AL
0x04d9001c 0000             ADD [EAX], AL
0x04d9001e 0000             ADD [EAX], AL
0x04d90020 bafcffffff       MOV EDX, 0xfffffffc
0x04d90025 035520           ADD EDX, [EBP+0x20]
0x04d90028 03555c           ADD EDX, [EBP+0x5c]
0x04d9002b b904001a00       MOV ECX, 0x1a0004
0x04d90030 4c               DEC ESP
0x04d90031 8bc5             MOV EAX, EBP
0x04d90033 ff95e0370000     CALL DWORD [EBP+0x37e0]
0x04d90039 8b4d24           MOV ECX, [EBP+0x24]
0x04d9003c 8908             MOV [EAX], ECX
0x04d9003e 48               DEC EAX
0x04d9003f 8d               DB 0x8d

Process: wmpnetwk.exe Pid: 2464 Address: 0x280000
Vad Tag: VadS Protection: PAGE_EXECUTE_READWRITE
Flags: CommitCharge: 16, MemCommit: 1, PrivateMemory: 1, Protection: 6

0x00280000  41 ba 80 00 00 00 48 b8 38 a1 e6 ff fe 07 00 00   A.....H.8.......
0x00280010  48 ff 20 90 41 ba 81 00 00 00 48 b8 38 a1 e6 ff   H...A.....H.8...
0x00280020  fe 07 00 00 48 ff 20 90 41 ba 82 00 00 00 48 b8   ....H...A.....H.
0x00280030  38 a1 e6 ff fe 07 00 00 48 ff 20 90 41 ba 83 00   8.......H...A...

0x00280000 41               INC ECX
0x00280001 ba80000000       MOV EDX, 0x80
0x00280006 48               DEC EAX
0x00280007 b838a1e6ff       MOV EAX, 0xffe6a138
0x0028000c fe07             INC BYTE [EDI]
0x0028000e 0000             ADD [EAX], AL
0x00280010 48               DEC EAX
0x00280011 ff20             JMP DWORD [EAX]
0x00280013 90               NOP
0x00280014 41               INC ECX
0x00280015 ba81000000       MOV EDX, 0x81
0x0028001a 48               DEC EAX
0x0028001b b838a1e6ff       MOV EAX, 0xffe6a138
0x00280020 fe07             INC BYTE [EDI]
0x00280022 0000             ADD [EAX], AL
0x00280024 48               DEC EAX
0x00280025 ff20             JMP DWORD [EAX]
0x00280027 90               NOP
0x00280028 41               INC ECX
0x00280029 ba82000000       MOV EDX, 0x82
0x0028002e 48               DEC EAX
0x0028002f b838a1e6ff       MOV EAX, 0xffe6a138
0x00280034 fe07             INC BYTE [EDI]
0x00280036 0000             ADD [EAX], AL
0x00280038 48               DEC EAX
0x00280039 ff20             JMP DWORD [EAX]
0x0028003b 90               NOP
0x0028003c 41               INC ECX
0x0028003d ba               DB 0xba
0x0028003e 83               DB 0x83
0x0028003f 00               DB 0x0
```

## IOC SAGA

```
$ ./Documents/volatility/volatility_sa -f Downloads/victim.raw --profile=Win7SP1x64 memdump -p 1860,1820,2464 -D Documents/forensics 
Volatility Foundation Volatility Framework 2.6
************************************************************************
Writing explorer.exe [  1860] to 1860.dmp
************************************************************************
Writing svchost.exe [  1820] to 1820.dmp
************************************************************************
Writing wmpnetwk.exe [  2464] to 2464.dmp
```

1.
```
$ strings 1820.dmp | grep 'www.go' | grep '.ru'

www.google.ru
www.go2it.ru
www.go4win.ru
www.gocaps.ru
www.goporn.ru
www.godyaev.ru
www.goldfon.ru
www.gogo.ru
www.godvesny.ru
www.gofilm21.ru
www.gogoasia.ru
www.goldorden.ru
www.gor-tehno.ru
www.goexchange.ru
www.goldchrome.ru
www.good-server.ru
www.golden-gallery.ru
www.golden-miracle.ru
```

2.
```
$ strings 1820.dmp | grep 'www.i'  | grep '.com'

www.itau.com
www.itau.com.br
www.imdb.com
www.ika-rus.com
www.ikaka.com
www.icsalabs.com
www.icubed.com
www.icq.com
www.infobusca.com.br
www.infospyware.com
www.izle10.com
www.infos-du-net.com
www.ibookprice.com
www.irangoals.com
www.ixomodels.com
www.itaupersonnalite.com.br
www.infosecpodcast.com
www.idealpackhk.com
www.identityhit.com
www.incodesolutions.com
www.indielisboa.com
www.intsecureprof.com
www.internationalservicecheck.com
 http://www.imobile.com.cn/
 http://www.icbc.com.cn/
http://www.iask.com/s?k=%s
http://www.iciba.com/search?s=%si
http://www.ip.com.cn/idcard.php?q=%s
http://www.ip.com.cn/ip.php?q=%si
http://www.ip.com.cn/mobile.php?q=%s
http://www.ip.com.cn/tel.php?q=%s
http://www.ip2location.com/
http://www.instantmp3player.com
http://www.inet4you.com/exit/
http://www.infoaxe.com/enhancedsearchform.jsp
http://www.im-names.com/names!#HSTR:Win32/DIRECTXDHU

```

3.
```
$ strings 1820.dmp | grep 'www.ic'

www.icsalabs.com
www.icubed.com
www.icq.com
http://www.icbc.com.cn/
http://www.iciba.com/search?s=%si
&password=ewwwwic
```

4.
```
$ strings 1820.dmp | grep '202.' | grep '.233.'

202.107.233.211
```

5.
```
$ strings 1820.dmp | grep '.200.' | grep '.164' 

phttp://209.200.12.164/drm/provider_license_v7.php
7e00000200696e766f6963655f636f70792e70646600433a5c446f63756d656e747320616e642053657474696e67735c41646d696e6973747261746f725c4465736b746f705c332e69636f000000030010000000433a5c494e564f49437e312e45584500107e00004d5a90000300000004000000ffff0000b800000000000000400000000000000000000000000000000000000000000000000000000000000000000000b80000000e1fba0e00b409cd21b8014ccd21546869732070726f6772616d2063616e6e6f742062652072756e20696e20444f53206d6f64652e0d0d0a2400000000000000b71207dbf3736988f3736988f37369881a6c6488f273698852696368f3736988000000000000000000000000
{164B10B9-B200-11D0-8C61-00A0C91E29D5}
{164B10B9-B200-11D0-8C61-00A0C91E29D5}
{164B10B9-B200-11D0-8C61-00A0C91E29D5}
{164B10B9-B200-11D0-8C61-00A0C91E29D5}
{164b10b9-b200-11d0-8c61-00a0c91e29d5}
```

6.
```
$ strings 1820.dmp | grep '209.190.'      

`http://209.190.122.186/drm/license-savenow.asp
```

7.
```
$ ./Documents/volatility/volatility_sa -f Downloads/victim.raw --profile=Win7SP1x64 envars -p 2464

Volatility Foundation Volatility Framework 2.6
Pid      Process              Block              Variable                       Value
-------- -------------------- ------------------ ------------------------------ -----
    2464 wmpnetwk.exe         0x00000000002c47a0 ALLUSERSPROFILE                C:\ProgramData
    2464 wmpnetwk.exe         0x00000000002c47a0 APPDATA                        C:\Windows\ServiceProfiles\NetworkService\AppData\Roaming
    2464 wmpnetwk.exe         0x00000000002c47a0 CommonProgramFiles             C:\Program Files\Common Files
    2464 wmpnetwk.exe         0x00000000002c47a0 CommonProgramFiles(x86)        C:\Program Files (x86)\Common Files
    2464 wmpnetwk.exe         0x00000000002c47a0 CommonProgramW6432             C:\Program Files\Common Files
    2464 wmpnetwk.exe         0x00000000002c47a0 COMPUTERNAME                   VICTIM-PC
    2464 wmpnetwk.exe         0x00000000002c47a0 ComSpec                        C:\Windows\system32\cmd.exe
    2464 wmpnetwk.exe         0x00000000002c47a0 FP_NO_HOST_CHECK               NO
    2464 wmpnetwk.exe         0x00000000002c47a0 LOCALAPPDATA                   C:\Windows\ServiceProfiles\NetworkService\AppData\Local
    2464 wmpnetwk.exe         0x00000000002c47a0 NUMBER_OF_PROCESSORS           1
    2464 wmpnetwk.exe         0x00000000002c47a0 OANOCACHE                      1
    2464 wmpnetwk.exe         0x00000000002c47a0 OS                             Windows_NT
    2464 wmpnetwk.exe         0x00000000002c47a0 Path                           C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\
    2464 wmpnetwk.exe         0x00000000002c47a0 PATHEXT                        .COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC
    2464 wmpnetwk.exe         0x00000000002c47a0 PROCESSOR_ARCHITECTURE         AMD64
    2464 wmpnetwk.exe         0x00000000002c47a0 PROCESSOR_IDENTIFIER           Intel64 Family 6 Model 42 Stepping 7, GenuineIntel
    2464 wmpnetwk.exe         0x00000000002c47a0 PROCESSOR_LEVEL                6
    2464 wmpnetwk.exe         0x00000000002c47a0 PROCESSOR_REVISION             2a07
    2464 wmpnetwk.exe         0x00000000002c47a0 ProgramData                    C:\ProgramData
    2464 wmpnetwk.exe         0x00000000002c47a0 ProgramFiles                   C:\Program Files
    2464 wmpnetwk.exe         0x00000000002c47a0 ProgramFiles(x86)              C:\Program Files (x86)
    2464 wmpnetwk.exe         0x00000000002c47a0 ProgramW6432                   C:\Program Files
    2464 wmpnetwk.exe         0x00000000002c47a0 PSModulePath                   C:\Windows\system32\WindowsPowerShell\v1.0\Modules\
    2464 wmpnetwk.exe         0x00000000002c47a0 PUBLIC                         C:\Users\Public
    2464 wmpnetwk.exe         0x00000000002c47a0 SystemDrive                    C:
    2464 wmpnetwk.exe         0x00000000002c47a0 SystemRoot                     C:\Windows
    2464 wmpnetwk.exe         0x00000000002c47a0 TEMP                           C:\Windows\SERVIC~2\NETWOR~1\AppData\Local\Temp
    2464 wmpnetwk.exe         0x00000000002c47a0 TMP                            C:\Windows\SERVIC~2\NETWOR~1\AppData\Local\Temp
    2464 wmpnetwk.exe         0x00000000002c47a0 USERDOMAIN                     WORKGROUP
    2464 wmpnetwk.exe         0x00000000002c47a0 USERNAME                       VICTIM-PC$
    2464 wmpnetwk.exe         0x00000000002c47a0 USERPROFILE                    C:\Windows\ServiceProfiles\NetworkService
    2464 wmpnetwk.exe         0x00000000002c47a0 windir                         C:\Windows
    2464 wmpnetwk.exe         0x00000000002c47a0 windows_tracing_flags          3
    2464 wmpnetwk.exe         0x00000000002c47a0 windows_tracing_logfile        C:\BVTBin\Tests\installpackage\csilogfile.log
```
