#DNS #DNS-zone-transfer #subdomains #AXFR-zone-transfer #subdomain-enumeration
#dig #subbrute #sublist3r #subfinder #fierce  

# Attacking DNS

---

The [Domain Name System](https://www.cloudflare.com/learning/dns/what-is-dns/) (`DNS`) translates domain names (e.g., hackthebox.com) to the numerical IP addresses (e.g., 104.17.42.72). DNS is mostly `UDP/53`, but DNS will rely on `TCP/53` more heavily as time progresses. DNS has always been designed to use both UDP and TCP port 53 from the start, with UDP being the default, and falls back to using TCP when it cannot communicate on UDP, typically when the packet size is too large to push through in a single UDP packet. Since nearly all network applications use DNS, attacks against DNS servers represent one of the most prevalent and significant threats today.

---

## Enumeration

DNS holds interesting information for an organization. We can understand how a company operates and the services they provide, as well as third-party service providers like emails.

The Nmap `-sC` (default scripts) and `-sV` (version scan) options can be used to perform initial enumeration against the target DNS servers:

```
nmap -p53 -Pn -sV -sC 10.10.110.213
```


## Attacking DNS

| **Command**                                                               | **Description**                                                                                                                                   |
| ------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| `dig AXFR @ns1.inlanefreight.htb inlanefreight.htb`                       | Perform an AXFR zone transfer attempt against a specific name server.                                                                             |
| `subfinder -d inlanefreight.com -v`                                       | Brute-forcing subdomains.                                                                                                                         |
| `host support.inlanefreight.com`                                          | DNS lookup for the specified subdomain.                                                                                                           |
| `dig axfr hr.inlanefreight.htb @10.129.203.6`                             | Perform an AXFR zone transfer attempt against a specific name server.                                                                             |
| `fierce --domain zonetransfer.me`                                         | Enumerate all DNS servers of root domain (AXFR zone transfer)                                                                                     |
| `python3 subbrute.py inlanefreight.com -s ./names.txt -r ./resolvers.txt` | use self-defined resolvers and perform pure DNS brute-forcing attacks during internal penetration tests on hosts that do not have Internet access |
| `python sublist3r.py -d example.com`                                      | Enumerate subdomains of specific domain                                                                                                           |
| `python sublist3r.py -d example.com -p 80,443`                            | Enumerate subdomains of specific domain and show only subdomains which have open ports 80 and 443                                                 |
| `python sublist3r.py -b -d example.com`                                   | Enumerate subdomains and enable brute force module                                                                                                |
| `python sublist3r.py -e google,yahoo,virustotal -d example.com`           | Enumerate subdomains using specific search engines                                                                                                |
| `subfinder -d example.com`                                                | Enumerate subdomains for websites, using passive online sources                                                                                   |
|                                                                           |                                                                                                                                                   |

---

## Online Resources

| Website                                                                        | Description               |
| ------------------------------------------------------------------------------ | ------------------------- |
| https://dnsdumpster.com/                                                       | find & lookup DNS records |
| https://csbygb.gitbook.io/pentips/networking-protocols-and-network-pentest/dns | informative general resource on DNS                          |

---

## Tools

https://github.com/aboul3la/Sublist3r

https://github.com/projectdiscovery/subfinder

https://github.com/TheRook/subbrute.git


