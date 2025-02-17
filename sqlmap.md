# SQLMap
SQLMap is an open-source penetration testing tool that automates the process of detecting and exploiting SQL injection vulnerabilities in database systems. It supports various database types, fingerprinting, dumping data, bypassing security mechanisms, and even gaining shell access.

## Basic Usage
- `-u URL`  
  Specify the target URL.
- `--data=DATA`  
  Data string to be sent through POST (e.g. "id=1").
- `-p TESTPARAMETER`  
  Testable parameter(s).
- `--level=LEVEL`  
  Level of tests to perform (1-5, default 1).
- `--risk=RISK`  
  Risk of tests to perform (1-3, default 1).

## Enumeration
- `-a, --all`  
  Retrieve everything.
- `-b, --banner`  
  Retrieve DBMS banner.
- `--current-user`  
  Retrieve DBMS current user.
- `--current-db`  
  Retrieve DBMS current database.
- `--passwords`  
  Enumerate DBMS users password hashes.
- `--dbs`  
  Enumerate DBMS databases.
- `-D <DB NAME>`  
  Specify a database to enumerate.
- `--tables`  
  Enumerate DBMS database tables.
- `-T <TABLE NAME>`  
  Specify a database table to enumerate.
- `--columns`  
  Enumerate DBMS database table columns.
- `-C <COLUMN>`  
  Specify a database table column to enumerate.
- `--schema`  
  Enumerate DBMS schema.

## Data Extraction
- `--dump`  
  Dump DBMS database table entries.
- `--dump-all`  
  Dump all DBMS databases tables entries.
- `--is-dba`  
  Detect if the DBMS current user is DBA.

## Advanced Exploitation
- `--os-shell`  
  Prompt for an interactive operating system shell.
- `--os-pwn`  
  Prompt for an out-of-band shell, Meterpreter, or VNC.

## Usage Example
````bash
sqlmap -u "http://example.com/page.php?id=1" --dbs --batch --random-agent --level=5 --risk=3 --tamper=space2comment
````
This command performs an advanced SQL injection test on the target URL (-u). It:
- Retrieves the list of databases (`--dbs`)
- Runs in non-interactive mode (`--batch`)
- Uses a randomly generated user-agent (`--random-agent`)
- Increases scan intensity (`--level=5`) and risk factor (`--risk=3`)
- Attempts to bypass WAFs or filters using the space2comment tamper script (`--tamper=space2comment`)

---
### 🔗 References:
- [Official SQLMap Documentation](https://sqlmap.org)
- [SQLMap GitHub Repository](https://github.com/sqlmapproject/sqlmap)
