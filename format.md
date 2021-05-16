Target:

## Enumeration

nmap
```

```

ffuf
```

```

![index]()



finding the attack vector

### Findings:Looking for attack vectors


essay of thought process


## Foothold:

cve/rce or getting access to www-data/apache/nginx





last part show www-data/apache/nginx
```
id 

```


## Lateral Movement:

upgrading shell
```
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

www-data/apache/nginx to user (usually finding db creds and connecting to db)





last part show user

```
id 

```

```
cat user.txt
<redacted>
```


## Priv Escalations:

user to root (enumerate)





last part show root
```
id 

```

```
cat root.txt
<redacted>
```
