# OSCP Cheatsheet
Your content here
## General
#### Port Discovery - Masscan
```
sudo masscan -p1-65535,U:1-65535 --rate=1000 -e tun0 #.#.#.#
```
#### Nmap - Mass Service Enumeration
```
sudo nmap -Pn -sC -sV -O --open -e tun0 -p 22,80 #.#.#.#
```
```
sudo nmap -Pn -sC -sV -O --open -e tun0 -sU -p 53,135 #.#.#.#
```
## Web Applications
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

#### File/Directory Enumeration
```
ffuf -u 'http://#.#.#.#/FUZZ' -w /usr/share/wordlists/dirb/big.txt
```
```
ffuf -u 'http://#.#.#.#/FUZZ.php' -w /usr/share/wordlists/dirb/big.txt
```
#### Virtual Host (subdomain) Enumeration
```
gobuster vhost -w /usr/share/wordlists/amass/subdomains-top1mil-5000.txt -u host.domain.tld -t 50 --append-domain 
```
#### Parameter Mining
- https://github.com/s0md3v/Arjun

```
arjun -u 'http://#.#.#.#?id=1'
```
```
arjun -u 'http://#.#.#.#?id=1' --stable
```
#### Bypass 403
- https://github.com/iamj0ker/bypass-403

```
bash $Tools/bypass-403/bypass-403.sh #.#.#.# index.html
```
#### Directory Traversal
- https://github.com/jcesarstef/dotdotslash
- `/etc/passwd` (readable by all users)
- `/var/www/html` (Apache2)
- `\windows\win.ini` (readable by all users) (slashes don't necessarily matter)
- `C:\inetpub\wwwroot`
- ?param=phpinfo();
- https://gist.github.com/jonlabelle/3f9aa4a5f3a2e41b7b4a81232047435c

```
python $Tools/dotdotslash/dotdotslash.py python3 --url "http://#.#.#.#/bWAPP/directory_traversal_1.php?page=/etc/passwd" --string "/etc/passwd" --cookie "PHPSESSID=<ID>; security_level=3"
```
#### Vulnerability Scanning
- https://github.com/sullo/nikto/issues/728

```
nikto -host="http://#.#.#.#" -maxtime=60s -C all
```
## Password Guessing
Your content here
#### SSH
```
patator ssh_login user='user' password='Password123!' host=#.#.#.# --csv=ssh_single.csv
```
```
patator ssh_login user=FILE0 password='Password123!' 0=/usr/share/wordlists/seclists/cirt-default-usernames.txt host=#.#.#.# --csv=ssh_user.csv
```
```
patator ssh_login user='user' password=FILE0 0=/usr/share/wordlists/rockyou.txt host=#.#.#.# --csv=ssh_pass.csv
```
#### SMB
```
patator smb_login host=#.#.#.# user='user' password='Password123!' domain=domain.tld --csv=smb_single.csv
```
```
patator smb_login host=#.#.#.# user=FILE0 password='Password123!' 0=/usr/share/wordlists/seclists/cirt-default-usernames.txt --csv=smb_user.csv
```
```
patator smb_login host=#.#.#.# user='user' password=FILE0 domain=domain.tld 0=/usr/share/wordlists/rockyou.txt --csv=smb_pass.csv
```
## Data Obfusication
Your content here
#### Base64 String Decode
```
echo 'acd==' | base64 -d
```
## Linux Privilege Escalation
Your content here
- https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/
- https://fuzzysecurity.com/tutorials/16.html
- https://pentestmonkey.net/tools/audit/unix-privesc-check

## Windows Privilege Escalation
Your content here
- 
## Active Directory
Your content here
#### DNS
```
dnsrecon -d domain.tld -a -x ./dnsrecon.xml -c ./dnsrecon.csv -n #.#.#.#
```
#### LDAP
- https://github.com/CroweCybersecurity/ad-ldap-enum

```
python $Tools/ad-ldap-enum/ad-ldap-enum.py -l #.#.#.# -d domain.tld -n
```
- https://github.com/cddmp/enum4linux-ng

```
python $Tools/enum4linux-ng/enum4linux-ng.py -A -R -Gm -C #.#.#.#
```
#### SMB
- https://github.com/crowecybersecurity/shareenum

```
$Tools/shareenum/src/shareenum #.#.#.# -o ./shareenum_anon
```
#### Kerberos
```
nmap -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='domain.tld' #.#.#.# -oA ./krb5-enum
```
```
nmap -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='active.htb',userdb='/usr/share/seclists/Usernames/Names/names.txt' #.#.#.# -oA ./krb5-enum-names
```
## Services Misc.
Your content here
#### OpenLDAP
Your content here
- https://www.n00py.io/2020/02/exploiting-ldap-server-null-bind/

## Cat File
Your content here
- Does not work with spaces

```
perl -V
perl -e '$words = `wc -w /home/kali/flag.txt`; print $words'
```
```
less file.txt
```
## Attacker Local
Your content here
#### Python Virtual Environment (>=3.11)
```
python -m venv /home/kali/Documents/HtB/Active/Active_venv
```
#### Change Python Versions
- https://github.com/pyenv/pyenv

```
pyenv versions
pyenv global #.#
exec $SHELL
```
#### SCP
```
scp local-file.txt user@#.#.#.#:/home/user
```