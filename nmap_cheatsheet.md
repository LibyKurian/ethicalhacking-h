# Nmap Cheat Sheet

## About Nmap
Nmap (Network Mapper) is a powerful open-source tool for network discovery and security auditing. It is widely used for scanning networks, detecting live hosts, discovering services, and performing vulnerability assessments. 

This document provides a quick reference to important Nmap commands and their functionalities.

## Nmap Commands and Options

| Option | Command | Description |
|---------|--------------------------|---------------------------------------------|
| `-iL` | `nmap -iL targets.txt` | Scan targets from a list of files |
| `-iR` | `nmap -iR 100` | Scan 100 random hosts |
| `-sS` | `nmap -sS` | TCP SYN scan (stealthy) |
| `-sT` | `nmap -sT` | TCP Connect scan |
| `-sU` | `nmap -sU` | UDP scan |
| `-sA` | `nmap -sA` | TCP ACK scan |
| `-sW` | `nmap -sW` | TCP Window scan |
| `-sM` | `nmap -sM` | TCP Maimon scan |
| `-sn` | `nmap -sn` | Disable port scanning. Host discovery only |
| `-Pn` | `nmap -Pn` | Disable host discovery. Port scan only |
| `-n` | `nmap -n` | Never do DNS resolution |
| `-p` | `nmap -p 80` | Scan specific port (e.g., port 80) |
| `-p-` | `nmap -p-` | Scan all 65,535 ports |
| `-sV` | `nmap -sV` | Service version detection |
| `--version-intensity` | `nmap --version-intensity 8` | Set version detection intensity (0-9) |
| `-A` | `nmap -A` | Aggressive scan (OS detection, version detection, script scanning, traceroute) |
| `-O` | `nmap -O` | OS detection |
| `--osscan-guess` | `nmap --osscan-guess` | Guess OS more aggressively |
| `-F` | `nmap -F` | Fast scan (only scans 100 ports) |
| `-T0` | `nmap -T0` | Paranoid speed scan (slowest) |
| `-T5` | `nmap -T5` | Insane speed scan (fastest) |
| `-sC` | `nmap -sC` | Scan using default NSE scripts |
| `--script=banner` | `nmap --script=banner` | Run a specific script (e.g., banner grabbing) |
| `-f` | `nmap -f` | Use tiny fragmented packets (evades some firewalls) |
| `--mtu` | `nmap --mtu 32` | Set custom packet size |
| `-D <IP>` | `nmap -D 192.168.1.1` | Use decoy scan from spoofed IPs |
| `-S <IP>` | `nmap -S www.microsoft.com` | Spoof source IP address (e.g., scan Facebook from Microsoft) |
| `-g <port>` | `nmap -g 53` | Use a specific source port number (e.g., 53) |

## Usage Example
```bash
nmap -A -p 1-65535 -T4 scanme.nmap.org
```
This command performs an aggressive scan (`-A`), scans all ports (`-p 1-65535`), and uses a faster scan speed (`-T4`) on the target `scanme.nmap.org`.

---
### 🔗 References:
- [Official Nmap Documentation](https://nmap.org/book/man.html)
- [Nmap Cheat Sheet](https://nmap.org/man/)
