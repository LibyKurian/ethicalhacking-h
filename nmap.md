# Nmap

Nmap (Network Mapper) is a powerful open-source tool for network discovery and security auditing. It is widely used for scanning networks, detecting live hosts, discovering services, and performing vulnerability assessments. 

This document provides a quick reference to important Nmap commands and their functionalities.

## Nmap Commands and Options

### 1. Target Specification
| Option | Command                        | Description                                       |
|--------|--------------------------------|---------------------------------------------------|
| `-iL`  | `nmap -iL targets.txt`         | Scan targets from a list of files                 |
| `-iR`  | `nmap -iR 100`                 | Scan 100 random hosts                             |
| `-sn`  | `nmap -sn`                     | Disable port scanning; host discovery only        |
| `-Pn`  | `nmap -Pn`                     | Disable host discovery; port scan only            |
| `-n`   | `nmap -n`                      | Never do DNS resolution                           |
| `-sA` | `nmap -sA` | TCP ACK scan |
| `-sW` | `nmap -sW` | TCP Window scan |
| `-sM` | `nmap -sM` | TCP Maimon scan |

### 2. Port Scanning Methods
| Option | Command           | Description                                  |
|--------|-------------------|----------------------------------------------|
| `-sS`  | `nmap -sS`        | TCP SYN scan (stealthy)                      |
| `-sT`  | `nmap -sT`        | TCP Connect scan                             |
| `-sU`  | `nmap -sU`        | UDP scan                                     |
| `-p`   | `nmap -p 80`      | Scan a specific port (e.g., port 80)           |
| `-p-`  | `nmap -p-`        | Scan all 65,535 ports                         |

### 3. Version, OS, and Script Detection
| Option                   | Command                              | Description                                                             |
|--------------------------|--------------------------------------|-------------------------------------------------------------------------|
| `-sV`                   | `nmap -sV`                           | Service version detection                                               |
| `--version-intensity`    | `nmap --version-intensity 8`         | Set version detection intensity (0-9)                                   |
| `-A`                    | `nmap -A`                            | Aggressive scan: OS detection, version detection, NSE script scanning, traceroute |
| `-O`                    | `nmap -O`                            | OS detection                                                            |
| `--osscan-guess`         | `nmap --osscan-guess`                | Guess OS more aggressively                                              |
| `-sC`                   | `nmap -sC`                           | Scan using default NSE scripts                                          |
| `--script=banner`        | `nmap --script=banner`               | Run a specific script (e.g., banner grabbing)                           |

### 4. Advanced and Miscellaneous Options
| Option             | Command                              | Description                                                    |
|--------------------|--------------------------------------|----------------------------------------------------------------|
| `-F`               | `nmap -F`                            | Fast scan (only scans 100 ports)                               |
| `-T0`              | `nmap -T0`                           | Paranoid speed scan (slowest)                                  |
| `-T5`              | `nmap -T5`                           | Insane speed scan (fastest)                                    |
| `-f`               | `nmap -f`                            | Use tiny fragmented packets (evades some firewalls)            |
| `--mtu`            | `nmap --mtu 32`                      | Set custom packet size                                         |
| `-D <IP>`          | `nmap -D 192.168.1.1`                | Use decoy scan from spoofed IPs                                |
| `-S <IP>`          | `nmap -S www.microsoft.com`          | Spoof source IP address                                          |
| `-g <port>`        | `nmap -g 53`                         | Use a specific source port number (e.g., 53)                     |

### 5. Output Options
| Option   | Command                             | Description                                       |
|----------|-------------------------------------|---------------------------------------------------|
| `-oN`    | `nmap -oN results.txt`              | Save output in normal format                      |
| `-oX`    | `nmap -oX results.xml`              | Save output in XML format                          |
| `-oG`    | `nmap -oG results.grep`             | Save output in grepable format                     |

---


## Usage Example
```bash
nmap -A -p 1-65535 -T4 scanme.nmap.org
```
This command performs an aggressive scan (`-A`), scans all ports (`-p 1-65535`), and uses a faster scan speed (`-T4`) on the target `scanme.nmap.org`.

---
### 🔗 References:
- [Official Nmap Documentation](https://nmap.org/book/man.html)
- [Nmap Cheat Sheet](https://nmap.org/man/)
