#Hashcat #JohnTheRipper  #hash-cracking #password-cracking #custom-wordlist #Crunch #CeWL  #CUPP #hashes  #NTLM #NTLMv2 #keyboard-walks #pp64 #bcrypt #Microsoft-Office  


[[Password Cracking]]
[[Login Brute Forcing Cheat Sheet]]


---

##   Custom Word List Tools 

| Name             | Description                                                                                                                                                                                                                        | Link                                                |
| ---------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------- |
| CeWL             | `Scrape` words from `website` to apply basic rule sets for password spraying or brute forcing                                                                                                                                                                                        | https://github.com/digininja/CeWL                   |
| mp64.bin         |                                                                                                                                                                                                                                    |                                                     |
| pp64.bin         |                                                                                                                                                                                                                                    |                                                     |
| kwp              | Advanced `keyboard-walk` generator with configureable basechars, keymap and routes                                                                                                                                                 | https://github.com/hashcat/kwprocessor              |
| Crunch           | Generates a wordlist with `permutation` and `combination`                                                                                                                                                                          | Kali Repo                                           |
| cupp.py          | Generate wordlist by profiling the user, such as a birthday, nickname, address, name of a pet or relative, or a common word such as God, love, money or password.                                                                  | https://github.com/Mebus/cupp                                                    |
| username-anarchy | Useful for user account/password brute force guessing and username enumeration `based on the users' names`. By attempting a few weak passwords across a large set of user accounts, user account lockout thresholds can be avoided | https://github.com/urbanadventurer/username-anarchy |
| TheMentalist     | Word `mangling` and `case permutation`                                                                                                                                                                                             | https://github.com/sc0tfree/mentalist.git           |
| rsmangler        | Word `mangling` and `case permutation`                                                                                                                                                                                             | https://github.com/digininja/RSMangle               |

---

## Commands

| Command                                                                                           | Description                                                                 |
| ------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| `crunch <minimum length> <maximum length> <charset> -t <pattern> -o <output file>`                | Make a wordlist with `Crunch`                                               |     |     |
| `python3 cupp.py -i`                                                                              | Use `CUPP` interactive mode                                                 |     |     |
| `kwp -s 1 basechars/full.base keymaps/en-us.keymap routes/2-to-10-max-3-direction-changes.route`  | `Kwprocessor` example                                                       |     |     |
| `cewl -d <depth to spider> -m <minimum word length> -w <output wordlist> <url of website>`        | Sample `CeWL` command                                                       |     |     |
| `hashcat -a 0 -m 100 hash rockyou.txt -r rule.txt`                                                | Sample `Hashcat` rule syntax                                                |     |     |
| `crunch 4 8 -o wordlist`                                                                          | Create word list between 4-8 characters with default character set          |     |     |
| `crunch 17 17 -t ILFREIGHT201%@@@@ -o wordlist`                                                   | Create a word list using a pattern                                          |     |     |
| `crunch 12 12 -t 10031998@@@@ -d 1 -o wordlist`                                                   | Create a word list with specified repetition                                |     |     |
| `python3 cupp.py -i`                                                                              | Create highly `personalised` word list                                      |     |     |
| `kwp -s 1 basechars/full.base keymaps/en-us.keymap  routes/2-to-10-max-3-direction-changes.route` | Create a word list of `keyboard walks`                                      |     |     |
| `./pp64.bin --keyspace < words`                                                                   | Find the number of combinations from word list                              |     |     |
| `./pp64.bin -o wordlist.txt < words`                                                              | Create word list with `combinations of words`                               |     |     |
| `./pp64.bin --pw-min=10 --pw-max=25 -o wordlist.txt < words`                                      | Create word list with combinations of words and set password max length     |     |     |
| `./pp64.bin --elem-cnt-min=3 -o wordlist.txt < words`                                             | Create a word list with at least 3 combinations of words                    |     |     |
| `cewl -d 5 -m 8 -e http://inlanefreight.com/blog -w wordlist.txt`                                 | `Scrape website` up to 5 pages deep with words with minimum of 8 characters |     |     |
| `/mp64.bin Welcome?s`                                                                             | Append all special characters to the end of a word                          |     |     |
| `ls -l /usr/share/hashcat/rules/`                                                                 | Hashcat default rules                                                       |     |     |
| `hashcat -a 0 -m 100 -g 1000 hash /usr/share/wordlists/rockyou.txt`                               | Use `Hashcat` with `random rules`                                           |     |     |
| `cut -d: -f 2- ~/hashcat.potfile`                                                                 | Cut out previous cracked passwords from `hashcat.potfile`                   |     |     |
| `awk '(NR==FNR) { a[NR]=$0 } (NR != FNR) { for (i in a) { print $0 a[i] } }' file2 file1`         | Create word list of `combinations of words from two files`                  |     |     |
| `hashcat -a 1 --stdout file1 file2`                                                               | Create word list of `combinations of words from two files` with hashcat     |     |     |
| `hashcat -a 1 -m <hash type> <hash file> <wordlist1> <wordlist2>`                                 | Combination attack with `two word lists`                                    |     |     |
| `hashcat -a 6 -m 0 hybrid_hash /usr/share/wordlists/rockyou.txt '?d?s'`                           | Hybrid combination attack `appending words` with string                     |     |     |
| `hashcat -a 7 -m 0 hybrid_hash_prefix -1 01 '20?1?d' /usr/share/wordlists/rockyou.txt`            | Hybrid combination attack `using masks`                                     |     |     |
| `./username-anarchy -i /home/ltnbob/names.txt`                                                    | convert a list of real names into common `username` formats                 |     |     |
| `./username-anarchy Harry Potter > user_harry.txt`                                                | Create `personalised user name` word list based on individual               |     |     |
| `cewl https://www.inlanefreight.com -d 4 -m 6 --lowercase -w inlane.wordlist`                     | Generate a wordlist with custom rules with CeWL                             |     |     |
|                                                                                                   |                                                                             |     |     |


Creating mutated password list from custom rule with Hashcat 
```
hashcat --force password.list -r custom.rule --stdout | sort -u > mut_password.list`             
```

Count the number of times each hash appears (establish password reuse)
```
cat DC01.inlanefreight.local.ntds | cut -d ‘:’ -f4 | sort -rn | uniq -c
```


---
#### Existing Hashcat rules  
```shell-session
pix3lfi3nd@htb[/htb]$ ls /usr/share/hashcat/rules/

best64.rule                  specific.rule
combinator.rule              T0XlC-insert_00-99_1950-2050_toprules_0_F.rule
d3ad0ne.rule                 T0XlC-insert_space_and_special_0_F.rule
dive.rule                    T0XlC-insert_top_100_passwords_1_G.rule
generated2.rule              T0XlC.rule
generated.rule               T0XlCv1.rule
hybrid                       toggles1.rule
Incisive-leetspeak.rule      toggles2.rule
InsidePro-HashManager.rule   toggles3.rule
InsidePro-PasswordsPro.rule  toggles4.rule
leetspeak.rule               toggles5.rule
oscommerce.rule              unix-ninja-leetspeak.rule
rockyou-30000.rule
```


---
## SED

Remove passwords with no special characters
```
sed -ri '/[!-/:-@\[-`\{-~]+/!d' william.txt
```

Remove passwords with less than 8 characters
```
sed -ri '/^.{,7}$/d' william.txt
```

Remove passwords without a number
```
sed -ri '/[0-9]+/!d' william.txt
```


---

## Example `Rule Creation`

Making `L33tspeak` and rules that prepend and/or append a word with a year

  Rules
```shell-session
c so0 si1 se3 ss5 sa@ $2 $0 $1 $9
```

The first letter word is capitalized with the `c` function. Then rule uses the substitute function `s` to replace `o` with `0`, `i` with `1`, `e` with `3` and a with `@`. At the end, the year `2019` is appended to it. Copy the rule to a file so that we can debug it.


  Create a Rule File
```
echo 'c so0 si1 se3 ss5 sa@ $2 $0 $1 $9' > rule.txt
```


  Store the Password in a File
```
echo 'password_ilfreight' > test.txt
```


  Hashcat - Debugging Rules
```
hashcat -r rule.txt test.txt --stdout
```
```
P@55w0rd_1lfr31ght2019
```

We can then use the custom rule created above and the `rockyou.txt` dictionary file to crack the hash using `Hashcat`.

---
