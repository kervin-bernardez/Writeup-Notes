Target:

## Enumeration:

nmap
```

```

ffuf
```

```

checking 

![index]()




### Findings:Looking for attack vectors

essay of thought process


## Foothold:

cve/rce or getting access to www-data/apache/nginx






```
id 

```


## Lateral Movement:

upgrading shell
```
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

www-data/apache/nginx to user (usually finding db creds and connecting to db)






```
id 

```

```
cat user.txt

<redacted>
```


## Priv Escalations:

user to root (enumerate)






```
id 

```

```
cat root.txt

<redacted>
```
