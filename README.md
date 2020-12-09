# HTB_cheatsheet

## Recon

### nmap

Scan for open ports: `nmap <IP> -p- -T4` <br />
Scan for services and their versions: `nmap <IP> -p<PORT>,<PORT2>,<...> -T4 -A` <br />
  

### SMB

try to list available shares on smb: `smbclient -L \\\\<IP>\\` <br />
connect to smb-share: `smbclient \\\\<IP>\\<SHARE>` <br />
download file from share: `get \<FILE>` <br />

try to find out version of smb-service: use metasploit module ...smb_version TODO <br />


## Exploitation

### SMB

Try to get a reverse shell for a given user and password via psexec (impacket):
`psexec.py '\<USER>:\<PW>@\<IP>'` <br />

