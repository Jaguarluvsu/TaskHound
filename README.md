# TaskHound

Windows Privileged Scheduled Task Disovery Tool for fun and profit.


TaskHound enumerates Windows System Scheduled Tasks over SMB (C:\Windows\System32\Tasks), parses Task XMLs, and attempts to identify tasks that run in the context of privileged accounts (and ideally stored credentials). It supports BloodHound Legacy high-value mappings by accepting a CSV or JSON export containing high-value users and SIDs.

## Disclaimer

TaskHound is strictly an audit and educational tool. Use only in environments you own or where you have explicit authorization to test. Seriously. Don't be a jerk.

## Quick start

Install dependencies (recommended inside a venv):

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
taskhound -u 'homer.simpson' -p 'P@ssw0rd' -d 'thesimpsons.springfield.local' -t 'HOSTNAME/IP' --dc-ip 172.17.1.11
```

Using NTLM hashes (either LM:NT or NT-only hex):

```bash
taskhound -u 'homer.simpson' --hashes ':252facd066d93dd009d4fd2cd0868384' -d 'thesimpsons.springfield.local' -t 'HOSTNAME/IP'
```

Kerberos with ccache (export KRB5CCNAME):

```bash
export KRB5CCNAME=./homer.simpson.ccache
taskhound -u 'homer.simpson' -k -d 'thesimpsons.springfield.local' -t 'HOSTNAME' --dc-ip 172.17.1.11
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

Plain file (`examples/out/HOSTNAME.txt`):

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
- `sid`

You can use this query to generate the data:

```
MATCH (u:User {highvalue:true})
RETURN u.samaccountname AS SamAccountName, u.objectid as sid
ORDER BY u.samaccountname
```

## Credential Guard Detection (EXPERIMENTAL)

If enabled (--credguard-detect), TaskHound checks the remote registry for Credential Guard status (HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LsaCfgFlags or IsolatedUserMode). If enabled, the output for each host/task will include:

    "credential_guard": true

If not enabled or undetectable, the field will be false or null.

This helps to determine if DPAPI dumps (aside of user vaults) are feasible on a given host. This feature is experimental for and may not be reliable on all Windows versions or VM environments.

## OPSEC considerations

TaskHound relies heavily on impacket for SMB/RPC and Kerberos Shenanigans. The typical IOCs apply.
If you really care about OPSEC: Do it manually. 

## Legal / License

Use responsibly. The author(s) provide no warranty. See `LICENSE` for details.

## RoadMap

There are quite a few things that I want to add / refine when I get the time to do so.

- NetExec Module
- Standalone BOF for Data Collection (To be used with the --offline feature)
- OpenGraph Integration for Attack Path Mapping

## Contributing

PRs welcome. Don't expext wonders tho (fr). Half of this was caffeine induced vibe-coding.
