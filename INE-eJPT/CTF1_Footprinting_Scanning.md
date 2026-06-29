# Assessment Methodologies: Footprinting and Scanning — CTF 1
### Capture The Flag Lab Writeup

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Lab Environment Overview](#2-lab-environment-overview)
3. [Reconnaissance Summary](#3-reconnaissance-summary)
4. [Flag 1 — HTTP Response Header Analysis](#4-flag-1--http-response-header-analysis)
5. [Flag 2 — robots.txt Enumeration and Directory Traversal](#5-flag-2--robotstxt-enumeration-and-directory-traversal)
6. [Flag 3 — Anonymous FTP Access and Credential Discovery](#6-flag-3--anonymous-ftp-access-and-credential-discovery)
7. [Flag 4 — MySQL Database Enumeration](#7-flag-4--mysql-database-enumeration)
8. [Summary of Findings](#8-summary-of-findings)
9. [Conclusions and Lessons Learned](#9-conclusions-and-lessons-learned)

---

## 1. Introduction

This report documents the methodology, tools, and findings from a Capture The Flag (CTF) lab exercise titled **Assessment Methodologies: Footprinting and Scanning CTF 1**, completed as part of a structured penetration testing curriculum. The objective of this lab was to perform systematic reconnaissance and enumeration against a target web server and its associated services, ultimately capturing four hidden flags embedded within the environment.

The skills exercised in this lab reflect core competencies in the information gathering and scanning phases of a penetration test, specifically:

- **HTTP header inspection** and banner grabbing
- **Web content discovery** through publicly accessible metadata files
- **Service enumeration** using network scanning tools
- **Anonymous service exploitation**, specifically unauthenticated FTP access
- **Database enumeration** following credential recovery

All activities were performed within an isolated, authorized lab environment. No live or production systems were involved.

---

## 2. Lab Environment Overview

| Parameter        | Details                          |
|------------------|----------------------------------|
| Attacker Machine | Kali Linux (GUI access provided) |
| Target Hostname  | `target.ine.local`               |
| Target IP        | `192.132.229.3`                  |
| Target URL       | `http://target.ine.local`        |
| Tools Used       | `curl`, `Nmap`, `ftp`, `mysql`   |

### Objectives

Capture four flags concealed within the target environment by applying standard footprinting and scanning techniques. The hints provided for each flag were as follows:

- **Flag 1:** The server announces its identity in every HTTP response.
- **Flag 2:** The gatekeeper's instructions reveal what should remain hidden.
- **Flag 3:** Anonymous access may lead to forgotten treasures within a directory.
- **Flag 4:** A well-named database reveals a hidden treasure in its configuration.

---

## 3. Reconnaissance Summary

Prior to targeting individual services, an initial port and service scan was performed using **Nmap** to enumerate all listening services on the target machine. This provides a comprehensive map of the attack surface and informs the selection of follow-up techniques for each flag.

### Command Used

```bash
nmap -sV target.ine.local
```

### Nmap Results

| Port     | State | Service   | Version / Detail                                      |
|----------|-------|-----------|-------------------------------------------------------|
| 21/tcp   | open  | ftp       | vsftpd 3.0.5                                          |
| 22/tcp   | open  | ssh       | OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (protocol 2.0)      |
| 25/tcp   | open  | smtp      | Postfix smtpd                                         |
| 80/tcp   | open  | http      | Werkzeug/3.0.6 Python/3.10.12                         |
| 143/tcp  | open  | imap      | Dovecot imapd (Ubuntu)                                |
| 993/tcp  | open  | ssl/imap  | Dovecot imapd (Ubuntu)                                |
| 3306/tcp | open  | mysql     | MySQL 8.0.39-0ubuntu0.22.04.1                         |

The scan revealed a broad set of services, including an FTP server with potential anonymous access (port 21), a web server (port 80), and a MySQL database instance (port 3306) — all of which were subsequently targeted in this assessment.

---

## 4. Flag 1 — HTTP Response Header Analysis

### Hint

> *"The server proudly announces its identity in every response. Look closely; you might find something unusual."*

### Methodology

HTTP response headers are transmitted by a web server with every reply and commonly contain metadata about the server software, framework version, and configuration details. In some cases, developers or administrators inadvertently embed sensitive information — such as internal identifiers or flags — within custom or standard headers.

To inspect the full HTTP response headers of the target web server, `curl` was used with the `-v` (verbose) flag, which causes the tool to display both request and response headers in their entirety.

### Command Used

```bash
curl http://target.ine.local -v
```

### Output (Relevant Excerpt)

```
* Host target.ine.local:80 was resolved.
* IPv4: 192.132.229.3
* Trying 192.132.229.3:80...
* Connected to target.ine.local (192.132.229.3) port 80
> GET / HTTP/1.1
> Host: target.ine.local
> User-Agent: curl/8.8.0
> Accept: */*
>
* Request completely sent off
< HTTP/1.1 200 OK
< Server: Werkzeug/3.0.6 Python/3.10.12
< Date: Tue, 23 Jun 2026 06:20:06 GMT
< Content-Type: text/html; charset=utf-8
< Content-Length: 2557
< Server: FLAG1_b2311210d93d43eda4e2356b46be9f41
< Connection: close
```

### Analysis

The response contained two distinct `Server` headers. The first, `Werkzeug/3.0.6 Python/3.10.12`, is a legitimate disclosure of the web framework in use. The second, however, was anomalous — a duplicate `Server` header containing the flag value. This represents a deliberate misconfiguration that mirrors a class of real-world vulnerability where sensitive data is leaked through HTTP headers.

### Flag Captured

```
FLAG1_b2311210d93d43eda4e2356b46be9f41
```

---

## 5. Flag 2 — robots.txt Enumeration and Directory Traversal

### Hint

> *"The gatekeeper's instructions often reveal what should remain unseen. Don't forget to read between the lines."*

### Methodology

The `robots.txt` file is a standard web convention used to instruct web crawlers and search engine bots on which paths they should or should not index. While intended to manage crawler behavior, this file is publicly accessible and frequently discloses the existence of directories that the administrator wishes to keep out of search engine results — often including sensitive or administrative paths.

By navigating directly to `http://target.ine.local/robots.txt`, the file's contents were retrieved and examined for disallowed paths.

### Step 1: Inspect robots.txt

**URL Visited:** `http://target.ine.local/robots.txt`

**Contents:**

```
User-agent: googlebot
Disallow: /photos

User-agent: *
Disallow: /secret-info/
Disallow: /data/
```

### Analysis

The file revealed two directories excluded from all crawlers: `/secret-info/` and `/data/`. The path `/secret-info/` was particularly suspicious given its name. Navigating to this endpoint directly in a browser returned a directory listing.

### Step 2: Access the Disclosed Directory

**URL Visited:** `http://target.ine.local/secret-info/`

**Response:** The browser rendered a directory listing containing a single entry:

```
["flag.txt"]
```

### Step 3: Retrieve the Flag File

**URL Visited:** `http://target.ine.local/secret-info/flag.txt`

The flag was retrieved directly from the file at this endpoint.

### Flag Captured

```
FLAG2_[value retrieved from flag.txt]
```

> *Note: The exact flag string was retrieved from the file at the time of the assessment. The `[value]` notation above represents the redacted flag content for report formatting purposes.*

---

## 6. Flag 3 — Anonymous FTP Access and Credential Discovery

### Hint

> *"Anonymous access sometimes leads to forgotten treasures. Connect and explore the directory; you might stumble upon something valuable."*

### Methodology

The Nmap scan performed during initial reconnaissance identified an FTP service (vsftpd 3.0.5) listening on port 21. A common misconfiguration in FTP server deployments is the allowance of **anonymous login**, which permits unauthenticated users to connect and browse files without valid credentials.

The FTP client was used to attempt an anonymous login to the target server.

### Step 1: Connect via Anonymous FTP

```bash
ftp anonymous@target.ine.local
```

**Password used:** `test@example.com`
*(Anonymous FTP conventionally accepts any email-formatted string as a password.)*

**Server Response:**

```
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
```

The server accepted the anonymous login, confirming the misconfiguration.

### Step 2: Enumerate the FTP Directory

```bash
ftp> ls
```

**Output:**

```
150 Here comes the directory listing.
-rw-r--r--    1 0        0              22 Oct 28  2024 creds.txt
-rw-r--r--    1 0        0              39 Jun 23 06:16 flag.txt
```

Two files were discovered in the root FTP directory: `flag.txt` and `creds.txt`.

### Step 3: Retrieve Both Files

**flag.txt contents:**

```
FLAG3_[####################]
```

**creds.txt contents:**

```
db_admin:password@123
```

### Analysis

The anonymous FTP access exposed not only the flag but also a plaintext credentials file containing valid database credentials (`db_admin:password@123`). This represents a critical secondary finding, as these credentials were subsequently leveraged to access the MySQL database service — directly enabling the capture of Flag 4.

### Flag Captured

```
FLAG3_[value retrieved from flag.txt]
```

---

## 7. Flag 4 — MySQL Database Enumeration

### Hint

> *"A well-named database can be quite revealing. Peek at the configurations to discover the hidden treasure."*

### Methodology

The credentials recovered from the FTP server (`db_admin:password@123`) were applied to the MySQL service identified on port 3306 during the initial Nmap scan. The MySQL client was used to authenticate to the remote database and enumerate available databases.

### Step 1: Connect to the MySQL Service

```bash
mysql -u db_admin -p -h target.ine.local
```

The `-u` flag specifies the username, `-p` prompts for the password interactively, and `-h` specifies the remote host.

Upon entering the password `password@123`, a successful connection was established.

### Step 2: Enumerate Available Databases

```sql
SHOW DATABASES;
```

**Output:**

```
+----------------------------------------+
| Database                               |
+----------------------------------------+
| FLAG4_##########################       |
| information_schema                     |
| mysql                                  |
| performance_schema                     |
| sys                                    |
+----------------------------------------+
5 rows in set (0.001 sec)
```

### Analysis

The flag was embedded directly within the name of a custom database, a deliberate configuration choice made as part of the CTF design. In a real-world assessment, this technique mirrors scenarios where sensitive identifiers, environment names, or project codes are exposed through database metadata — information that becomes accessible to any user with even minimal database access privileges.

### Flag Captured

```
FLAG4_[value embedded in the database name]
```

---

## 8. Summary of Findings

| Flag   | Discovery Vector                        | Technique Applied                          | Risk Level |
|--------|-----------------------------------------|--------------------------------------------|------------|
| Flag 1 | HTTP Response Headers                   | Verbose HTTP header inspection with `curl` | Low        |
| Flag 2 | `robots.txt` + Directory Traversal      | Public metadata file analysis              | Medium     |
| Flag 3 | Anonymous FTP Access                    | Unauthenticated FTP login and enumeration  | High       |
| Flag 4 | MySQL Database Name Enumeration         | Database login with recovered credentials  | Critical   |

### Vulnerabilities Identified

1. **Sensitive Data in HTTP Headers** — A custom `Server` header was used to transmit a flag value, analogous to real-world cases where tokens, internal build identifiers, or debug values are leaked through HTTP responses.

2. **robots.txt Disclosure** — The `robots.txt` file inadvertently advertised the path `/secret-info/`, which contained a flag file accessible without authentication.

3. **Anonymous FTP Enabled** — The FTP service permitted unauthenticated access, exposing a plaintext credential file alongside the flag. In a production environment, this would represent a severe security vulnerability.

4. **Credential Reuse and Plaintext Storage** — Credentials stored in plaintext on the FTP server were directly reusable against the MySQL service, enabling privilege escalation across services.

5. **Flag Exposed in Database Name** — Sensitive identifiers embedded in database names are accessible to all authenticated users, regardless of their intended access level.

---

## 9. Conclusions and Lessons Learned

This CTF lab effectively illustrated how an attacker can chain together a series of individually minor vulnerabilities into a complete compromise of multiple services. Beginning with passive HTTP inspection and escalating through web enumeration, anonymous service access, and credential recovery, all four flags were captured using entirely standard, well-documented techniques.

### Key Takeaways

- **HTTP headers should be audited regularly.** Custom or duplicate headers may inadvertently expose internal information. Web server configurations should be reviewed to ensure only necessary headers are returned.

- **robots.txt is not a security control.** Sensitive directories must be protected through authentication and access controls, not merely excluded from search engine indexing.

- **Anonymous FTP access should be disabled** on any server containing sensitive data. If anonymous access is required for a specific use case, the accessible directory should be strictly isolated and contain no sensitive content.

- **Credentials must never be stored in plaintext** in publicly or semi-publicly accessible locations. Credential management solutions and secrets vaults should be used in their place.

- **Database enumeration is a standard step** in any penetration test where database credentials are obtained. Naming conventions for databases and tables should not include sensitive identifiers.

The methodologies demonstrated in this lab — banner grabbing, metadata file inspection, service enumeration, anonymous access testing, and database enumeration — form a fundamental part of the footprinting and scanning phase in any professional penetration testing engagement.

---

*Report completed: June 23, 2026*
*Lab: Assessment Methodologies: Footprinting and Scanning CTF 1*
*Platform: INE Security / eLearnSecurity*
