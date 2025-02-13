# Burp Suite

Burp Suite is a **powerful web application penetration testing tool** used for **intercepting, modifying, and attacking HTTP requests**.



### Burp Suite Basics
#### Key Components
| **Component** | **Purpose** |
|--------------|------------|
| **Proxy** | Intercepts and modifies HTTP/S requests & responses |
| **Target** | Maps the application's structure (Directories, Endpoints) |
| **Repeater** | Manually modify and replay HTTP requests |
| **Intruder** | Automates attacks (Brute-force, SQLi, XSS) |
| **Decoder** | Encode/Decode Base64, URL, HTML, etc. |
| **Comparer** | Compare responses for differences |
| **Extender** | Install additional Burp plugins for advanced testing |

#### Burp Hotkeys
| **Shortcut** | **Action** |
|-------------|------------|
| `Ctrl + Shift + I` | Send request to **Intruder** |
| `Ctrl + Shift + R` | Send request to **Repeater** |
| `Ctrl + Shift + L` | Send request to **Decoder** |
| `Ctrl + Shift + U` | URL Encode selected text |

---

### Setting Up Burp Suite
#### Configure Proxy (Intercept Traffic)
1. **Open Burp Suite** → **Proxy** → **Options**
2. Ensure **127.0.0.1:8080** is **running**.
3. Set browser **proxy settings**:
   - **Firefox:** Preferences → Network Settings → Manual Proxy → **127.0.0.1:8080**.
   - **Burp's built-in browser:** Click "Open Browser" in **Proxy** tab.
4. **Turn Intercept ON/OFF** (`Proxy` → `Intercept`).

#### Bypass SSL Certificate Warnings
If HTTPS fails:
1. Visit: [`http://burp`](http://burp)
2. Download **Burp CA Certificate**.
3. Import into **Firefox**:
   - Settings → Certificates → Import **Burp CA**.

---

### Capturing & Modifying Requests
#### Intercept and Modify HTTP Traffic
1. **Turn ON Proxy Intercept** (`Proxy` → `Intercept`).
2. Perform an action in the browser (e.g., Login).
3. Modify parameters (e.g., Change `admin=false` to `admin=true`).
4. **Forward** the request and check the response.

> ***Example Attack:** Modify a price parameter to `$0.01` for **e-commerce hacking**.*

---

### Burp Repeater (Manual Testing)
#### Resend Requests with Modifications
1. **Capture request** in Proxy.
2. **Send to Repeater** (`Ctrl + Shift + R`).
3. Modify parameters (e.g., `role=user` → `role=admin`).
4. Click **Send** and analyze response.

> ***Use Case:** Test **SQLi, XSS, IDOR (Insecure Direct Object References)**.*

---

### Burp Intruder (Automated Attacks)
#### Brute Force Login Credentials
1. **Capture login request** (`POST /login`).
2. **Send to Intruder** (`Ctrl + Shift + I`).
3. **Set Attack Type** → `Sniper` or `Cluster Bomb`.
4. **Mark the username/password field** (`Add § markers`).
5. **Load wordlists**:
   - Usernames → `/usr/share/wordlists/seclists/Usernames.txt`
   - Passwords → `/usr/share/wordlists/rockyou.txt`
6. **Start Attack** and find valid credentials.

> ***Use Case:** Crack **admin passwords** or **2FA bypass**.*

---

### Exploiting Vulnerabilities
#### SQL Injection (SQLi)
1. Capture a request containing a **user input field**.
2. Modify **parameters**:
   ```sql
   ' OR 1=1 --
   ```
3. **Send to Repeater** and analyze response.
4. **If successful**, dump database using SQLMap:
   ```bash
   sqlmap -r request.txt --dbs
   ```

> ***Use Case:** Extract sensitive data from databases.*

---

#### Cross-Site Scripting (XSS)
1. Capture a request with **user input**.
2. Modify input with:
   ```html
   <script>alert('XSS')</script>
   ```
3. **Send** and check if it executes.

> ***Use Case:** Steal cookies, session hijacking.*

---

#### Broken Authentication (Bypass Login)
Modify the request:
```bash
admin' -- 
```
or
```json
{ "username": "admin", "password": "wrongpass", "isAdmin": "true" }
```
> ***Use Case:** Gain admin access without valid credentials.*

---

### Extracting Hidden Data
#### Discover Hidden Directories (Forced Browsing)
1. **Spider the Target** (`Target` → `Site Map` → `Spider this host`).
2. **Look for sensitive endpoints**:
   - `/admin`
   - `/backup`
   - `/config.php`
   - `/robots.txt`
   - `/debug.log`

> ***Use Case:** Find **hidden admin panels, API keys, and credentials**.*

---

### Burp Suite Extensions
| **Extension** | **Function** |
|--------------|-------------|
| **Autorize** | Detect **IDOR & privilege escalation** |
| **SQLMap API** | Automates **SQL Injection** |
| **Hackvertor** | Encodes/decodes payloads for **WAF bypass** |
| **J2EEScan** | Scans **Java-based web apps** for vulnerabilities |

> **Install from** `Extender` → `BApp Store`.

---

### Exporting & Saving Attacks
#### Save Captured Requests
Click **Save Item** (`Proxy` → `HTTP history` → Right-click → Save`).

#### Export Request for SQLMap
1. Send request to Repeater
2. Click "Save Request" → `Save as request.txt`.
3. Run SQLMap: `sqlmap -r request.txt --dbs`

---

## Tips
✅ **Use Intruder for fast brute-force attacks.**  
✅ **Use Repeater for manual parameter tampering.**  
✅ **Spider the target to discover hidden files and directories.**  
✅ **Automate SQL Injection with SQLMap (`sqlmap -r request.txt --dbs`).**  
✅ **Use `Autorize` extension to find access control issues.**  
✅ **Look for API keys, tokens, and passwords in response headers.**  
✅ **Check `robots.txt` for disallowed but sensitive endpoints.**  
