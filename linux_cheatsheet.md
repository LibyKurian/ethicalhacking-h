## 🔥 Some Linux commands

This includes general Linux utilities, networking tools, and penetration testing commands.


| Command                     | Description |
|-----------------------------|-------------|
| `man <tool>`                | Opens man pages for the specified tool. |
| `<tool> -h`                 | Prints the help page of the tool. |
| `apropos <keyword>`         | Searches through man pages' descriptions for instances of a given keyword. |
| `cat`                       | Concatenates and prints files. |
| `whoami`                    | Displays current username. |
| `id`                        | Returns user identity. |
| `hostname`                  | Sets or prints the name of the current host system. |
| `uname`                     | Prints operating system name. |
| `pwd`                       | Returns working directory name. |
| `ifconfig`                  | Displays network interface details. |
| `ip`                        | Shows/manages network devices, routing, tunnels. |
| `netstat`                   | Displays network connections and statistics. |
| `ss`                        | Investigates sockets and network status. |
| `ps`                        | Shows process status. |
| `who`                       | Displays logged-in users. |
| `env`                       | Prints environment variables. |
| `lsblk`                     | Lists block devices. |
| `lsusb`                     | Lists USB devices. |
| `lsof`                      | Lists opened files. |
| `lspci`                     | Lists PCI devices. |
| `sudo`                      | Executes a command as another user (root). |
| `su`                        | Switches to another user account. |
| `useradd`                   | Creates a new user. |
| `userdel`                   | Deletes a user account. |
| `usermod`                   | Modifies a user account. |
| `passwd`                    | Changes user password. |
| `dpkg`                      | Debian package management. |
| `apt`                       | High-level package management. |
| `git`                       | Version control system. |
| `systemctl`                 | Manages services and systemd. |
| `kill <PID>`                | Terminates a process by ID. |
| `jobs`                      | Lists background jobs. |
| `fg <job_id>`               | Brings a background job to the foreground. |
| `curl <URL>`                | Transfers data from or to a server. |
| `wget <URL>`                | Downloads files from a server. |
| `python3 -m http.server`    | Starts a simple web server on port 8000. |
| `ls`                        | Lists directory contents. |
| `cd <dir>`                  | Changes directory. |
| `clear`                     | Clears the terminal. |
| `touch <file>`              | Creates an empty file. |
| `mkdir <dir>`               | Creates a directory. |
| `tree`                      | Displays directory contents recursively. |
| `mv <src> <dest>`           | Moves or renames files. |
| `cp <src> <dest>`           | Copies files or directories. |
| `nano <file>`               | Edits text files in terminal. |
| `find <dir> -name <file>`   | Searches for files in a directory. |
| `grep '<pattern>' <file>`   | Searches for text patterns in a file. |
| `sort <file>`               | Sorts lines in a file. |
| `chmod 777 <file>`          | Changes file permissions. |
| `chown user:group <file>`   | Changes file ownership. |

nmap (./nmap_cheatsheet.md)
sqlmap (./sqlmap_cheatsheet.md)
remaining (./notes.md)

| Command                     | Description |
|-----------------------------|-------------|
| `nmap -sS <target>`         | Stealth TCP SYN scan. | // ./nmap_cheatsheet.md
| `nmap -A <target>`          | Aggressive scan (OS, versions, scripts). |
| `sqlmap -u <URL> --dbs`     | Enumerates databases for SQL injection. |
| `hydra -l admin -P pass.txt <target> ssh` | Brute-force SSH login. |
| `john --wordlist=rockyou.txt hashfile` | Crack hashes using John the Ripper. |
| `tcpdump -i eth0`           | Captures network packets. |
| `nc -lvnp 4444`             | Starts a Netcat listener. |
| `msfconsole`                | Starts the Metasploit framework. |
| `hashcat -m 0 hash.txt wordlist.txt` | Cracks hashes with a wordlist. |
