# Case 04: Phishing Email Impersonating Microsoft 365

**Type:** Simulated lab case (self-study)
**Skills:** Email header analysis, SPF/DKIM/DMARC, social engineering, Linux (grep)

## Scenario
An employee (Anna, Finance) reported a suspicious email asking her
to "verify" her password within 2 hours.

## Evidence
| Clue | Finding |
|---|---|
| From | security@micros0ft-support.com (zero instead of "o") |
| Reply-To | helpdesk.verify2026@gmail.com (free Gmail) |
| Sending server | mail.mailer-xyz.ru (203.0.113.45) |
| Authentication | SPF fail, DKIM none, DMARC fail |
| Link | http://micros0ft-support.com/login |

## Commands I used
grep -i "^from" email.txt
grep -i "^reply-to" email.txt

## Social engineering tricks
- **Urgency:** "expires in 2 hours"
- **Fear:** "mailbox will be permanently deleted"
- **Authority:** pretends to be Microsoft Security

## Verdict
Phishing. (Write your 3 pieces of evidence here.)

## Response actions
1. Asked the user whether she clicked or entered her password
2. Searched for other recipients and removed the email
3. Blocked the sender domain and IP
4. Thanked the user for reporting

## MITRE ATT&CK
- T1566.002 – Phishing: Spearphishing Link

## What I learned
(2–3 sentences in your own words.)
