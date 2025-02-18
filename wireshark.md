## What is Wireshark?
- A packet sniffer & network protocol analyzer that captures and inspects traffic in real-time.
- Helps in analyzing credentials, exploits, malware traffic, and reconnaissance.


| Common Format | Description  |  
|-------|---------------------------------|  
| .pcap	| Standard Wireshark capture file |  
|.pcapng |	Enhanced capture format with extra metadata|  
| .cap |	Used in Aircrack-ng (Wireless)|  
| .pkt |	Cisco packet capture format|  

#### Capturing Traffic
- Open Wireshark and select the active network interface (e.g., eth0, wlan0).
- Click Start Capture ▶️.
- Stop capture after sufficient packets are recorded.

#### Essential Wireshark Filters
````js
  ip.addr == 192.168.1.1	//Show packets from/to a specific IP
  tcp.port == 80	//Show only HTTP traffic
  udp.port == 53	//Show only DNS traffic
  http.request.method == "POST"	//Show HTTP POST requests (login forms)
  ftp.request.command == "USER"	//Show FTP login attempts
  telnet	//Show Telnet traffic (credentials in cleartext)
  ntlmssp.auth	//Show NTLM authentication (Windows Hashes)
  dns	//Show only DNS traffic
  icmp	//Show ICMP (ping) requests
````

#### Finding Credentials & Sensitive Data
- Capture Unencrypted Credentials
````js
  http.request.method == "POST"	//HTTP Login (Login forms, sessions)
  ftp.request.command == "USER"	 //FTP
  telnet	  //Telnet (Entire session is in plaintext)
  ntlmssp.auth	     //SMB NTLM Hashes (NTLMv1/v2 Hashes)
  smtp	    // SMTP (Email)	 (Possible plaintext credentials)
  pop	      //POP3/IMAP (Email)
````
- Extract Passwords
  - Find Authentication Packets
  - Use http.request.method == "POST"
  - Right-click → Follow HTTP Stream
  - Check for Basic Authentication (Base64 Encoded)
  - Look for Authorization: Basic <BASE64_ENCODED_STRING>
  - Decode using bash: `echo "BASE64_STRING" | base64 -d`

- Extract FTP/Telnet Credentials
  - Use ftp or telnet filter
  - Right-click → Follow TCP Stream

> For encrypted logins (HTTPS, SSH), try SSL stripping attacks (ettercap, Bettercap).

- Extracting Files from PCAP
  - HTTP Files  
      Go to File → Export Objects → HTTP  
      Select Files → Save  
  - FTP Files  
      Filter: `ftp-data`  
      Go to File → Export Objects → FTP  
      Download any available files  
  - Images  
      Filter: `http contains "image"`  
      Right-click the packet → Follow HTTP Stream  
      Save and extract base64-encoded image data.  

- Identify Exploits & Attacks
  - Detect Nmap Scanning  
    SYN Scan	`tcp.flags.syn == 1 && tcp.flags.ack == 0`  
    UDP Scan	`udp && !dns`  
    Xmas Scan	`tcp.flags.fin == 1 && tcp.flags.psh == 1 && tcp.flags.urg == 1`  
  - Detect SMB Exploits (EternalBlue)  
    Filter: `smb2 || dcerpc || msrpc`  
  - Detect SQL Injection  
Filter: `http contains "UNION SELECT"`  

- Wireless Traffic Analysis (Wi-Fi)
  - Capture & Analyze Wi-Fi Traffic
  - Enable Monitor Mode in bash: `airmon-ng start wlan0`
  - Start Wireshark and select wlan0mon interface.
  - Filters for Wireless Packets:
    - Beacon Frames: `wlan.fc.type_subtype == 0x08`
    - Deauthentication Attacks: `wlan.fc.type_subtype == 0x0c`
  - Extract WPA2 Handshake (For Cracking) filter: `eapol`
  - Extract the 4-way handshake and crack it with aircrack-ng or hashcat.
    
- Export & Analyze PCAP in Kali
  - Export Packets for Offline Analysis `tshark -i eth0 -w capture.pcap`
  - Analyze with: `tcpdump -r capture.pcap`
  - Extracting Information with tshark
    - Extract all IPs: `tshark -r capture.pcap -T fields -e ip.src -e ip.dst`
    - Extract URLs: `tshark -r capture.pcap -Y "http.request" -T fields -e http.host -e http.request.u`
   
- MQTT
  - MQTT is a lightweight protocol used in IoT devices for communication over a broker (server).
  - It operates on port 1883 (unencrypted) or 8883 (TLS/SSL encrypted).
  - Used in smart home devices, sensors, industrial automation, and remote monitoring.
  - `mqtt.msgtype == 3` msgtype 3 indicates an MQTT Publish Message.
