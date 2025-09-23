# TaskHound BOF (Beacon Object File)

**EXPERIMENTAL** BOF implementation of TaskHound's core collection functionality for **AdaptixC2**. 

> **⚠️ EXPERIMENTAL WARNING**  
> This BOF is **UNSAFE** for production environments. Limited testing has been done in lab environments. Don't blame me if it blows up your op or gets you busted. You have been warned.

## Overview

The BOF provides **initial data collection** capabilities directly from your C2 beacon. For comprehensive analysis with high-value detection, use the collected XML files with the main Python tool's `--offline` mode.

## Compilation

### Quick Compilation
```bash
cd BOF/
./compile.sh
```

### Manual Compilation
**Requirements:** MinGW-w64 cross-compiler for Windows PE object files

```bash
# Install MinGW-w64 (macOS example)
brew install mingw-w64

# Compile manually
cd BOF/AdaptixC2/
x86_64-w64-mingw32-gcc -c taskhound.c -o taskhound.o \
  -fno-stack-check -fno-stack-protector -mno-stack-arg-probe \
  -fno-asynchronous-unwind-tables -fno-builtin -Os
```

## Usage

### Basic Commands
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

## Example Output
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

## Directory Structure

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

## Offline Analysis Integration

BOF-collected files work seamlessly with Python TaskHound:

```bash
# After BOF collection with -save (and transfer to your host)
taskhound --offline /path/to/Tasks/ --bh-data /path/to/bloodhound_export.json
```

## Compatibility

Currently designed for **AdaptixC2**. Can probably be adapted for other C2 frameworks, but that's left as an exercise for the reader.