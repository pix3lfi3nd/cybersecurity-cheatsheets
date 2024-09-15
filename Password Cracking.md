#Hashcat #JohnTheRipper  #hash-cracking #password-cracking #custom-wordlist #hashes  #NTLM #NTLMv2  #bcrypt #Microsoft-Office  

##   Online Resources

| Link                     | Description                  |
| ------------------------ | ---------------------------- |
| https://crackstation.net | Crack common password hashes |
|                          |                              |


[[Custom Word Lists and Rules]]
[[Password Reuse - Default Passwords]]


##   Password Cracking Cheat Sheet

| **Command**                                                                                       | **Description**                                                                                                           |
| ------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| `pip install hashid`                                                                              | Install the `hashid` tool                                                                                                 |
| `hashid <hash>` OR `hashid <hashes.txt>`                                                          | Identify a hash with the `hashid` tool                                                                                    |
| `hashcat --example-hashes`                                                                        | View a list of `Hashcat` hash modes and example hashes                                                                    |
| `hashcat -b -m <hash mode>`                                                                       | Perform a `Hashcat` benchmark test of a specific hash mode                                                                |
| `hashcat -b`                                                                                      | Perform a benchmark of all hash modes                                                                                     |
| `hashcat -O`                                                                                      | Optimization: Increase speed but limit potential password length                                                          |
| `hashcat -w 3`                                                                                    | Optimization: Use when Hashcat is the only thing running, use 1 if running hashcat on your desktop. Default is 2          |
| `hashcat -a 0 -m <hash type> <hash file> <wordlist>`                                              | Dictionary attack                                                                                                         |
| `hashcat -a 1 -m <hash type> <hash file> <wordlist1> <wordlist2>`                                 | Combination attack                                                                                                        |
| `hashcat -a 3 -m 0 <hash file> -1 01 'ILFREIGHT?l?l?l?l?l20?1?d'`                                 | Sample Mask attack                                                                                                        |
| `hashcat -a 7 -m 0 <hash file> -1=01 '20?1?d' rockyou.txt`                                        | Sample Hybrid attack                                                                                                      |
| `hashcat -a 0 -m 100 hash rockyou.txt -r rule.txt`                                                | Sample `Hashcat` rule syntax                                                                                              |
| `./cap2hccapx.bin input.cap output.hccapx`                                                        | `cap2hccapx` syntax                                                                                                       |
| `hcxpcaptool -z pmkidhash_corp cracking_pmkid.cap`                                                | `hcxpcaptool`syntax                                                                                                       |
| `hashcat -a 0 -m 2100 hashDCC2 /usr/share/wordlists/rockyou.txt`                                  | Crack `MS Cache 2 hash`                                                                                                   |
| `hashcat -a 0 -m 1000 1000 ntlm_example /usr/share/wordlists/rockyou.txt`                         | Crack `NTLM` hash                                                                                                         |
| `ls -l /usr/share/hashcat/rules/`                                                                 | Hashcat default rules                                                                                                     |
| `hashcat -a 0 -m 100 -g 1000 hash /usr/share/wordlists/rockyou.txt`                               | Use `Hashcat` with `random rules`                                                                                         |
| `cut -d: -f 2- ~/hashcat.potfile`                                                                 | Cut out previous cracked passwords from `hashcat.potfile`                                                                 |
| `hashcat -a 0 -m 5600 inlanefreight_ntlmv2 /usr/share/wordlists/rockyou.txt`                      | Cracking `NTLMv2` hash                                                                                                    |
| `hashcat -a 0 -m 17200 pdf_hash_to_crack /usre/share/wordlists/rockyou.txt`                       | Cracking `zip files`                                                                                                      |
| `zip2john ~/Desktop/example.zip `                                                                 | Extract crackable hash from `zip files`                                                                                   |
| `hashcat -a 1 --stdout file1 file2`                                                               | Create word list of `combinations of words from two files` with hashcat                                                   |
| `hashcat -a 1 -m <hash type> <hash file> <wordlist1> <wordlist2>`                                 | Combination attack with `two word lists`                                                                                  |
| `hashcat -a 6 -m 0 hybrid_hash /usr/share/wordlists/rockyou.txt '?d?s'`                           | Hybrid combination attack `appending words` with string                                                                   |
| `hashcat -a 7 -m 0 hybrid_hash_prefix -1 01 '20?1?d' /usr/share/wordlists/rockyou.txt`            | Hybrid combination attack `using masks`                                                                                   |
| `john --format=<hash_type> <hash or hash_file>`                                                   | `john` single crack mode                                                                                                  |
| `john --incremental <hash_file>`                                                                  | `john` incremental mode hybrid combination attack trying `all possible combinations of characters` from the character set |
| `locate *2john*`                                                                                  | locate `john scripts`                                                                                                     |


---

## Common Hashcat Hash Types

 The creators of `Hashcat` maintain a list of [example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes) most hash modes that `Hashcat` supports. Some of the most commonly seen hashes are:

|Hashmode|Hash Name|Example Hash|
|---|---|---|
|0|MD5|8743b52063cd84097a65d1633f5c74f5|
|100|SHA1|b89eaac7e61417341b710b727768294d0e6a277b|
|1000|NTLM|b4b9b02e6f09a9bd760f388b67351e2b|
|1800|sha512crypt $6$, SHA512 (Unix)|$6$52450745$k5ka2p8bFuSmoVT1tzOyyuaREkkKBcCNqoDKzYiJL9RaE8yMnPgh2XzzF0NDrUhgrcLwg78xs1w5pJiypEdFX/|
|3200|bcrypt $2*$, Blowfish (Unix)|$2a$05$LhayLxezLhK1LhWvKxCyLOj0j1u.Kj0jZ0pEmm134uzrQlFvQJLF6|
|5500|NetNTLMv1 / NetNTLMv1+ESS|u4-netntlm::kNS:338d08f8e26de93300000000000000000000000000000000:9526fb8c23a90751cdd619b6cea564742e1e4bf33006ba41:cb8086049ec4736c|
|5600|NetNTLMv2|admin::N46iSNekpT:08ca45b7d7ea58ee:88dcbe4446168966a153a0064958dac6:5c7830315c7830310000000000000b45c67103d07d7b95acd12ffa11230e0000000052920b85f78d013c31cdb3b92f5d765c783030|
|13100|Kerberos 5 TGS-REP etype 23|$krb5tgs$23$_user$realm$test/spn_$63386d22d359fe42230300d56852c9eb$ < SNIP >|

`Hashcat` supports the following hash modes for Microsoft Office documents:

|**Mode**|**Target**|
|---|---|
|`9400`|MS Office 2007|
|`9500`|MS Office 2010|
|`9600`|MS Office 2013|

`Hashcat` supports a variety of compressed file formats such as:

|**Mode**|**Target**|
|---|---|
|`11600`|7-Zip|
|`13600`|WinZip|
|`17200`|PKZIP (Compressed)|
|`17210`|PKZIP (Uncompressed)|
|`17220`|PKZIP (Compressed Multi-File)|
|`17225`|PKZIP (Mixed Multi-File)|
|`17230`|PKZIP (Compressed Multi-File Checksum-Only)|
|`23001`|SecureZIP AES-128|
|`23002`|SecureZIP AES-192|
|`23003`|SecureZIP AES-256|

---
## JohnTheRipper 

| Name                 | Description                                                                        | Link                                                                                           |
| -------------------- | ---------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| JohnTheRipper (john) | Cracking tool with scripts to `extract crackable hashes` from a variety of sources | https://github.com/magnumripper/JohnTheRipper.git                                              |
| keypass2john.py      | Extracts a john/hashcat crackable hash from `KeePass 1.x/2.X databases`            | https://gist.github.com/HarmJ0y/116fa1b559372804877e604d7d367bbc#file-keepass2john-py          |
| office2john.py       | extracts a john/hashcat crackable hash from `Microsoft Office` documents           | https://raw.githubusercontent.com/magnumripper/JohnTheRipper/bleeding-jumbo/run/office2john.py |
| zip2john.py          | extracts a john/hascat crackable hash from `zip files`                             | https://github.com/openwall/john/blob/bleeding-jumbo/src/zip2john.c                            |
|                      |                                                                                    |                                                                                                |


|**Tool**|**Description**|
|---|---|
|`pdf2john`|Converts PDF documents for John|
|`ssh2john`|Converts SSH private keys for John|
|`mscash2john`|Converts MS Cash hashes for John|
|`keychain2john`|Converts OS X keychain files for John|
|`rar2john`|Converts RAR archives for John|
|`pfx2john`|Converts PKCS#12 files for John|
|`truecrypt_volume2john`|Converts TrueCrypt volumes for John|
|`keepass2john`|Converts KeePass databases for John|
|`vncpcap2john`|Converts VNC PCAP files for John|
|`putty2john`|Converts PuTTY private keys for John|
|`zip2john`|Converts ZIP archives for John|
|`hccap2john`|Converts WPA/WPA2 handshake captures for John|
|`office2john`|Converts MS Office documents for John|
|`wpa2john`|Converts WPA/WPA2 handshakes for John|


There are also Python ports of most of these tools available that are very easy to work with. The majority of them are contained in the `JohnTheRipper` jumbo GitHub repo [here](https://github.com/magnumripper/JohnTheRipper/tree/bleeding-jumbo/run).

---

#### Cracking with John

|**Hash Format**|**Example Command**|**Description**|
|---|---|---|
|afs|`john --format=afs hashes_to_crack.txt`|AFS (Andrew File System) password hashes|
|bfegg|`john --format=bfegg hashes_to_crack.txt`|bfegg hashes used in Eggdrop IRC bots|
|bf|`john --format=bf hashes_to_crack.txt`|Blowfish-based crypt(3) hashes|
|bsdi|`john --format=bsdi hashes_to_crack.txt`|BSDi crypt(3) hashes|
|crypt(3)|`john --format=crypt hashes_to_crack.txt`|Traditional Unix crypt(3) hashes|
|des|`john --format=des hashes_to_crack.txt`|Traditional DES-based crypt(3) hashes|
|dmd5|`john --format=dmd5 hashes_to_crack.txt`|DMD5 (Dragonfly BSD MD5) password hashes|
|dominosec|`john --format=dominosec hashes_to_crack.txt`|IBM Lotus Domino 6/7 password hashes|
|EPiServer SID hashes|`john --format=episerver hashes_to_crack.txt`|EPiServer SID (Security Identifier) password hashes|
|hdaa|`john --format=hdaa hashes_to_crack.txt`|hdaa password hashes used in Openwall GNU/Linux|
|hmac-md5|`john --format=hmac-md5 hashes_to_crack.txt`|hmac-md5 password hashes|
|hmailserver|`john --format=hmailserver hashes_to_crack.txt`|hmailserver password hashes|
|ipb2|`john --format=ipb2 hashes_to_crack.txt`|Invision Power Board 2 password hashes|
|krb4|`john --format=krb4 hashes_to_crack.txt`|Kerberos 4 password hashes|
|krb5|`john --format=krb5 hashes_to_crack.txt`|Kerberos 5 password hashes|
|LM|`john --format=LM hashes_to_crack.txt`|LM (Lan Manager) password hashes|
|lotus5|`john --format=lotus5 hashes_to_crack.txt`|Lotus Notes/Domino 5 password hashes|
|mscash|`john --format=mscash hashes_to_crack.txt`|MS Cache password hashes|
|mscash2|`john --format=mscash2 hashes_to_crack.txt`|MS Cache v2 password hashes|
|mschapv2|`john --format=mschapv2 hashes_to_crack.txt`|MS CHAP v2 password hashes|
|mskrb5|`john --format=mskrb5 hashes_to_crack.txt`|MS Kerberos 5 password hashes|
|mssql05|`john --format=mssql05 hashes_to_crack.txt`|MS SQL 2005 password hashes|
|mssql|`john --format=mssql hashes_to_crack.txt`|MS SQL password hashes|
|mysql-fast|`john --format=mysql-fast hashes_to_crack.txt`|MySQL fast password hashes|
|mysql|`john --format=mysql hashes_to_crack.txt`|MySQL password hashes|
|mysql-sha1|`john --format=mysql-sha1 hashes_to_crack.txt`|MySQL SHA1 password hashes|
|NETLM|`john --format=netlm hashes_to_crack.txt`|NETLM (NT LAN Manager) password hashes|
|NETLMv2|`john --format=netlmv2 hashes_to_crack.txt`|NETLMv2 (NT LAN Manager version 2) password hashes|
|NETNTLM|`john --format=netntlm hashes_to_crack.txt`|NETNTLM (NT LAN Manager) password hashes|
|NETNTLMv2|`john --format=netntlmv2 hashes_to_crack.txt`|NETNTLMv2 (NT LAN Manager version 2) password hashes|
|NEThalfLM|`john --format=nethalflm hashes_to_crack.txt`|NEThalfLM (NT LAN Manager) password hashes|
|md5ns|`john --format=md5ns hashes_to_crack.txt`|md5ns (MD5 namespace) password hashes|
|nsldap|`john --format=nsldap hashes_to_crack.txt`|nsldap (OpenLDAP SHA) password hashes|
|ssha|`john --format=ssha hashes_to_crack.txt`|ssha (Salted SHA) password hashes|
|NT|`john --format=nt hashes_to_crack.txt`|NT (Windows NT) password hashes|
|openssha|`john --format=openssha hashes_to_crack.txt`|OPENSSH private key password hashes|
|oracle11|`john --format=oracle11 hashes_to_crack.txt`|Oracle 11 password hashes|
|oracle|`john --format=oracle hashes_to_crack.txt`|Oracle password hashes|
|pdf|`john --format=pdf hashes_to_crack.txt`|PDF (Portable Document Format) password hashes|
|phpass-md5|`john --format=phpass-md5 hashes_to_crack.txt`|PHPass-MD5 (Portable PHP password hashing framework) password hashes|
|phps|`john --format=phps hashes_to_crack.txt`|PHPS password hashes|
|pix-md5|`john --format=pix-md5 hashes_to_crack.txt`|Cisco PIX MD5 password hashes|
|po|`john --format=po hashes_to_crack.txt`|Po (Sybase SQL Anywhere) password hashes|
|rar|`john --format=rar hashes_to_crack.txt`|RAR (WinRAR) password hashes|
|raw-md4|`john --format=raw-md4 hashes_to_crack.txt`|Raw MD4 password hashes|
|raw-md5|`john --format=raw-md5 hashes_to_crack.txt`|Raw MD5 password hashes|
|raw-md5-unicode|`john --format=raw-md5-unicode hashes_to_crack.txt`|Raw MD5 Unicode password hashes|
|raw-sha1|`john --format=raw-sha1 hashes_to_crack.txt`|Raw SHA1 password hashes|
|raw-sha224|`john --format=raw-sha224 hashes_to_crack.txt`|Raw SHA224 password hashes|
|raw-sha256|`john --format=raw-sha256 hashes_to_crack.txt`|Raw SHA256 password hashes|
|raw-sha384|`john --format=raw-sha384 hashes_to_crack.txt`|Raw SHA384 password hashes|
|raw-sha512|`john --format=raw-sha512 hashes_to_crack.txt`|Raw SHA512 password hashes|
|salted-sha|`john --format=salted-sha hashes_to_crack.txt`|Salted SHA password hashes|
|sapb|`john --format=sapb hashes_to_crack.txt`|SAP CODVN B (BCODE) password hashes|
|sapg|`john --format=sapg hashes_to_crack.txt`|SAP CODVN G (PASSCODE) password hashes|
|sha1-gen|`john --format=sha1-gen hashes_to_crack.txt`|Generic SHA1 password hashes|
|skey|`john --format=skey hashes_to_crack.txt`|S/Key (One-time password) hashes|
|ssh|`john --format=ssh hashes_to_crack.txt`|SSH (Secure Shell) password hashes|
|sybasease|`john --format=sybasease hashes_to_crack.txt`|Sybase ASE password hashes|
|xsha|`john --format=xsha hashes_to_crack.txt`|xsha (Extended SHA) password hashes|
|zip|`john --format=zip hashes_to_crack.txt`|ZIP (WinZip) password hashes|


---

