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
Phishing. The email pretends to be from Microsoft, but:
1. The sender domain is micros0ft-support.com, with a zero instead
   of the letter "o". It is not owned by Microsoft.
2. SPF failed, DKIM was missing and DMARC failed, so the email did
   not pass any authentication check.
3. Replies go to a free Gmail address. A real company like Microsoft
   uses its own email addresses, not Gmail.
The email was also sent from a server in Russia (mailer-xyz.ru).

## Response actions
1. Asked the user whether she clicked or entered her password
2. Searched for other recipients and removed the email
3. Blocked the sender domain and IP
4. Thanked the user for reporting

## MITRE ATT&CK
- T1566.002 – Phishing: Spearphishing Link

## What I learned
The display name in an email can say anything, so I always check the
real address and read the domain from the right. I learned what SPF,
DKIM and DMARC mean, and that "pass" only proves the email came from
that domain, not that the domain is safe. This case connects to my
thesis: the attacker used urgency, fear and authority to make the
user act quickly without thinking.
