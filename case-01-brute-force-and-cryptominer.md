# Case 01: Brute-Force Attack, Privilege Escalation and Crypto Miner

**Type:** Simulated lab case (self-study)
**Skills:** Linux log analysis, grep, attack timeline, triage

## Scenario
A company server was attacked. I received the login log (auth.log)
and investigated what happened.

## Commands I used
grep -c FAILED auth.log
grep SUCCESS auth.log
grep 203.0.113.66 auth.log
tail -2 auth.log

## Attack timeline
| Time | Event |
|---|---|
| 09:10–09:12 | 7 failed logins from 203.0.113.66 (root, admin, test, oracle, backup) |
| 09:12 | Successful login as "backup" |
| 09:13 | sudo /bin/bash, attacker became root |
| 09:14 | Created hidden file /tmp/.hidden/miner |

## Other findings
- 45.33.12.8: 2 failed logins, never got in (attempt only)
- Two employees had one failed login each, then success = typos (false positives)

## Verdict
This was a successful brute-force attack. The attacker from 203.0.113.66
tried 7 different usernames in about 2 minutes and got in with the
"backup" account. Then he used sudo to become root and hid a crypto
miner in /tmp/.hidden. This is serious because the attacker had full
control of the server.

## Response actions
1. Lock the "backup" account and change its password
2. Block the IP 203.0.113.66 (and 45.33.12.8, which also tried)
3. Stop and delete the miner in /tmp/.hidden
4. Check what else the attacker did as root after 09:13
5. Report the incident to the team lead

## MITRE ATT&CK
- T1110 – Brute Force
- T1548.003 – Abuse Elevation Control Mechanism: Sudo
- T1496 – Resource Hijacking
## What I learned
Many failed logins followed by one success from the same outside IP
means the attack worked, but one failed login from an internal IP is
usually just a typo. I also learned that old accounts like "backup"
are dangerous because they often have weak passwords. And when I
searched for "SUCESS" with a typo, grep gave me 0 results without any
error, so now I always check my command when a result looks strange.

