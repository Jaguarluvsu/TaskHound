# TaskHound

Windows Privileged Scheduled Task Disovery Tool for fun and profit.


TaskHound enumerates Windows System Scheduled Tasks over SMB (C:\Windows\System32\Tasks), parses Task XMLs, and attempts to identify tasks that run in the context of privileged accounts (and ideally stored credentials). It supports BloodHound Legacy high-value mappings by accepting a CSV/JSON export containing high-value users and SIDs.

## Disclaimer

TaskHound is strictly an audit and educational tool. Use only in environments you own or where you have explicit authorization to test. Seriously. Don't be a jerk.

## EXPERIMENTAL Features

Every feature or add-on listed here with an **EXPERIMENTAL** Tag is to be considered **UNSAFE** for prod environments. I have done limited testing in my lab. Don't blame me if the BOF for example messes up your op or gets you busted. You have been warned.

## OPSEC considerations

The Python version TaskHound relies heavily on impacket for SMB/RPC and Kerberos Shenanigans. The typical IOCs apply.
If you really care about OPSEC: Use the BOF or collect manually. If you replicate the target folder structure, the `--offline` parameter can still be used.

## Quick start

Install dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install .
```

## Usage

```bash
taskhound -h
```
```
TTTTT  AAA   SSS  K   K H   H  OOO  U   U N   N DDDD
  T   A   A S     K  K  H   H O   O U   U NN  N D   D
  T   AAAAA  SSS  KKK   HHHHH O   O U   U N N N D   D
  T   A   A     S K  K  H   H O   O U   U N  NN D   D
  T   A   A SSSS  K   K H   H  OOO   UUU  N   N DDDD

                    by 0xr0BIT

usage: taskhound [-h] [-u USERNAME] [-p PASSWORD] [-d DOMAIN] [--hashes HASHES] [-k] [-t TARGET] [--targets-file TARGETS_FILE] [--dc-ip DC_IP]
                 [--offline OFFLINE] [--bh-data BH_DATA] [--include-ms] [--unsaved-creds] [--credguard-detect] [--plain PLAIN] [--json JSON] [--csv CSV] [--backup BACKUP] [--debug]

TaskHound - Scheduled Task privilege checker with optional High Value enrichment

options:
  -h, --help            show this help message and exit

Authentication options:
  -u, --username USERNAME
                        Username (required for online mode)
  -p, --password PASSWORD
                        Password (omit with -k if using Kerberos/ccache)
  -d, --domain DOMAIN   Domain (required for online mode)
  --hashes HASHES       NTLM hashes in LM:NT format (or NT-only 32-hex) to use instead of password
  -k, --kerberos        Use Kerberos authentication (supports ccache)

Target options:
  -t, --target TARGET   Single target
  --targets-file TARGETS_FILE
                        File with targets, one per line
  --dc-ip DC_IP         Domain controller IP (required when using Kerberos without DNS)

Scanning options:
  --offline OFFLINE     Offline mode: parse previously collected XML files from directory (no authentication required)
  --bh-data BH_DATA     Path to High Value Target export (csv/json from Neo4j)
  --include-ms          Also include \Microsoft scheduled tasks (WARNING: very slow)
  --unsaved-creds       Show scheduled tasks that do not store credentials (unsaved credentials)
  --credguard-detect    EXPERIMENTAL: Attempt to detect Credential Guard status via remote registry (default: off). Only use if you know your environment supports it.

Output options:
  --plain PLAIN         Directory to save normal text output (per target)
  --json JSON           Write all results to a JSON file
  --csv CSV             Write all results to a CSV file
  --backup BACKUP       Directory to save raw XML task files (per target)

Misc:
  --debug               Enable debug output (print full stack traces)
```

Basic scan with password:

```bash
taskhound -u 'homer.simpson' -p 'P@ssw0rd' -d 'thesimpsons.springfield.local' -t 'HOSTNAME/IP' --dc-ip IP
```

Using NTLM hashes (either LM:NT or NT-only hex):

```bash
taskhound -u 'homer.simpson' --hashes ':252facd066d93dd009d4fd2cd0868384' -d 'thesimpsons.springfield.local' -t 'HOSTNAME/IP'
```

Kerberos with ccache (export KRB5CCNAME):

```bash
export KRB5CCNAME=./homer.simpson.ccache
taskhound -u 'homer.simpson' -k -d 'thesimpsons.springfield.local' -t 'HOSTNAME' --dc-ip IP
```

Show tasks that have no saved credentials (Useful in some cases, disabled by default):

```bash
taskhound -u 'homer.simpson' -p 'P@ssw0rd' -d 'thesimpsons.springfield.local' --unsaved-creds -t 'HOSTNAME'
```

Save raw XML task files for offline analysis:

```bash
taskhound -u 'homer.simpson' -p 'P@ssw0rd' -d 'thesimpsons.springfield.local' -t 'HOSTNAME' --backup ./backups
```

Analyze previously collected XML files (offline mode):

```bash
taskhound --offline ./backups --bh-data /path/to/bloodhound_export.json
```

**Note:** The offline mode expects a directory structure where each subdirectory represents a host, and XML files are organized in a path similar to their original location (e.g., `backups/hostname/Windows/System32/Tasks/TaskName`). This structure is automatically created when using the `--backup` option during online collection.

## Demo Output

Console Output / Plain file:

```
[+] HOSTNAME: Connected via SMB
[+] HOSTNAME: Local Admin Access confirmed
[*] HOSTNAME: Crawling Scheduled Tasks (skipping \Microsoft for speed)
[+] HOSTNAME: Found 5 tasks, privileged 4
----------------------
[TASK] Windows\System32\Tasks\HIGH_PRIV
       RunAs  : THESIMPSONS\homer.simpson
       What   : C:\Windows\System32\cmd.exe /c whoami
       Author : THESIMPSONS\ned.flanders
       Date   : 2025-09-16T14:12:44.7939771
       Reason : High Value Match
----------------------
```

## High-Value Detection

TaskHound accepts a CSV or JSON file (extension matters: `.csv` or `.json`) for the `--bh-data` option. The file must contain the following attributes (case-insensitive header names accepted):

- `SamAccountName`
- `SID`

You can use this query to generate the data:

```
MATCH (u:User {highvalue:true})
RETURN u.samaccountname AS SamAccountName, u.objectid as SID
ORDER BY u.samaccountname
```

If you want to have more high value targets than the default ones: Use custom queries. An example to mark everything as high value that has the keyword ADMIN in it:
```
MATCH (n) WHERE toUpper(n.name) CONTAINS "ADMIN"
OR toUpper(n.azname) CONTAINS "ADMIN"
OR toUpper(n.objectid) CONTAINS "ADMIN" 
SET n.highvalue = true, n.highvaluereason = 'Node matched ADMIN keyword' 
RETURN n
```

## **EXPERIMENTAL** Credential Guard Detection

If enabled (--credguard-detect), TaskHound checks the remote registry for Credential Guard status (HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LsaCfgFlags or IsolatedUserMode). If enabled, the output for each host/task will include:

    "credential_guard": true

If not enabled or undetectable, the field will be false or null.

This helps to determine if DPAPI dumps (aside of user vaults) are feasible on a given host. This feature is still experimental for the time being and may not be reliable on all Windows versions or VM environments.

## **EXPERIMENTAL** BOF Implementation

TaskHound includes a **Beacon Object File (BOF)** implementation of the **core collection functionality** for **AdaptixC2**. I'm sure it can be translated to work with other C2 frameworks but this is left as an exercise for the reader.

**Note**: The BOF is designed for initial data collection on a single host. For comprehensive analysis with high-value detection use the collected XML files with the main Python tool's `--offline` mode.

### Compilation

#### Quick Compilation
```bash
cd BOF/
./compile.sh
```

#### Manual Compilation
Requirements: **MinGW-w64** cross-compiler for Windows PE object files

```bash
# Install MinGW-w64 (macOS example)
brew install mingw-w64

# Compile manually
cd BOF/AdaptixC2/
x86_64-w64-mingw32-gcc -c taskhound.c -o taskhound.o \
  -fno-stack-check -fno-stack-protector -mno-stack-arg-probe \
  -fno-asynchronous-unwind-tables -fno-builtin -Os
```

### Usage

#### Basic Commands
```bash
# Current user context (uses beacon's authentication)
# Note: If using the current logon session, always prefer HOSTNAME over IP to avoid NTLM fallback!
beacon > taskhound HOSTNAME/IP

# With explicit credentials  
beacon > taskhound HOSTNAME/IP thesimpsons\homer.simpson P@ssw0rd

# With credential saving for offline analysis
beacon > taskhound HOSTNAME/IP -save C:\temp\task_collection

# Show all tasks including those without stored credentials
beacon > taskhound HOSTNAME/IP -unsaved-creds
```

### Output
```
beacon > taskhound DC highpriv P@ssw0rd1337. -save C:\Temp\test

[22/09 23:14:01] [*] Task: execute BOF
[22/09 23:14:01] [*] Agent called server, sent [9.81 Kb]
[+] TaskHound - Remote Task Collection
[+] Target: DC
[+] Using credentials: highpriv
[+] Saved: C:\Temp\test\DC\Windows\System32\Tasks\Test1
Test1: THESIMPSONS\Administrator is executing C:\Windows\System32\AcXtrnal.dll 1234 [STORED CREDS]
[+] Saved: C:\Temp\test\DC\Windows\System32\Tasks\Test2
Test2: THESIMPSONS\lowpriv is executing C:\Windows\System32\AboveLockAppHost.dll 123432 [STORED CREDS]
[+] Collection complete. Found 2 tasks
[22/09 23:14:01] [+] BOF finished
```

#### Directory Structure

When using `-save`, creates Python TaskHound compatible structure:

```
save_directory/
└── hostname/
    └── Windows/
        └── System32/
            └── Tasks/
                ├── Test1
                ├── Test2
```

#### Offline Analysis Integration

BOF-collected files work seamlessly with Python TaskHound:

```bash
# After BOF collection with -save
taskhound --offline C:\temp\collection --bh-data bloodhound_export.json
```

## Legal / License

Use responsibly. The author(s) provide no warranty. See `LICENSE` for details.

## Roadmap

There are quite a few things that I want to add / refine when I get the time to do so.

- Compatibility with BloodHound Community Edition Exports
- NetExec Module
- OpenGraph Integration for Attack Path Mapping
- Automatically grabbing the corresponding Cred Blobs from Disk to decrypt them offline, given you acquired the key somehow

## Contributing

PRs welcome. Don't expext wonders tho (fr). Half of this was caffeine induced vibe-coding.
