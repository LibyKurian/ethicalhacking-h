# SQLMap Cheat Sheet

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
