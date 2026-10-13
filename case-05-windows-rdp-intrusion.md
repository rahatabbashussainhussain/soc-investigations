# Case 05: Windows RDP Intrusion with Backdoor Account

**Type:** Simulated lab case (self-study)
**Skills:** Windows Event IDs, Logon Types, persistence, incident response, grep

## Scenario
A Windows server behaved strangely during the night. The security log
was exported before the attacker could fully hide his actions.
I investigated what happened.

## Commands I used
grep -c ",4625," security.log
grep 198.51.100.23 security.log
grep 198.51.100.23 security.log | grep ",4624,"
grep -v 198.51.100.23 security.log

## Attack timeline
| Time | Event ID | What happened |
|---|---|---|
| 01:58:02–01:58:14 | 4625 x6 | Brute force over Remote Desktop (Logon Type 10) from 198.51.100.23 |
| 01:58:17 | 4624 | Successful login as service account svc_backup |
| 02:03:40 | 4720 | Created new account helpdesk01 |
| 02:04:02 | 4732 | Added helpdesk01 to Administrators |
| 02:06:55 | 4688 | Ran C:\Users\Public\update.exe |
| 02:15:30 | 1102 | Cleared the security log |
| 09:02:44 | 4624 | Came back as helpdesk01 from the same IP |

## False positives
- laura (Logon Type 2): normal morning login at her desk
- SYSTEM (Logon Type 5): Windows service, normal
- mikael: one wrong password, then success 16 seconds later = typo

## Verdict
The attacker tried several accounts over Remote Desktop and got in
with svc_backup, a service account that nobody watches. He created
his own admin account (helpdesk01) as a backdoor, ran a suspicious
program from the Public folder and cleared the security log to hide
his tracks. In the morning he came back using the backdoor account,
which proves the persistence worked.

## Response actions
1. Disconnect the active session and disable helpdesk01
2. Block IP 198.51.100.23
3. Close Remote Desktop to the internet (only via VPN with MFA)
4. Reset the svc_backup password
5. Save a copy of update.exe for analysis, then remove it
6. Escalate to the team lead (log clearing + backdoor = serious incident)

## MITRE ATT&CK
- T1110 – Brute Force
- T1136 – Create Account
- T1070.001 – Indicator Removal: Clear Windows Event Logs

## What I learned
I learned to always read the Event ID first, because I confused a
failed login (4625) with a successful one (4624). Attackers create
their own admin accounts with normal-looking names so they can come
back later, even if the first password is changed. And when an
attacker is still active, the first step is to stop him, not to
clean up, and I should keep suspicious files as evidence.
