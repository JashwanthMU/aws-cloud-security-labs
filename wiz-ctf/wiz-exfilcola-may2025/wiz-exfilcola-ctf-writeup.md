# Wiz Cloud Hunting Games — ExfilCola CTF Writeup
**Platform:** Cloud Hunting Games by Wiz Research  
**Tags:** `AWS` `CloudTrail` `S3` `IAM` `Lambda` `EC2` `SQL` `Incident Response` `Forensics`  
**Date :** May 2026  
**Certificate:** [View Mine](https://www.cloudhuntinggames.com/certificate/exfilcola/be12e654-a13f-4c41-bad3-dbfcef21907e)  

---

## Before I Start

This one is different from my PwnedLabs writeups. This wasn't a guided lab it was an actual CTF competition made by the **Wiz Research team** (yes, that Wiz the $12 billion cloud security company). They released it publicly in May 2025 and thousands of security professionals attempted it worldwide.

I finished it. That still feels a bit unreal honestly.

The format was completely different from PwnedLabs. No step-by-step hints. No "here's what to do next." Just a ransom email from a threat group called FizzShadows saying they stole a startup's secret soda recipe and five challenges to figure out exactly what happened, how they got in, and how to stop it.

The thing I liked most everything felt like a real incident. Real logs. Real AWS services. Real attacker techniques. By the end you're not just finding flags  you're reconstructing a complete attack story.

Totally there are 5 challenges!!
---

## The Scenario

A startup called **ExfilCola** received this email:

> *"We have successfully infiltrated your corporate network and exfiltrated your most valuable data assets. Transfer 75 Bitcoin or we release everything."*
> — FizzShadows

My job: figure out if the attack actually happened, trace exactly how they got in, what they accessed, and in the final challenge actually delete the stolen file from the attacker's own server before it gets leaked.

That last part is genuinely one of the coolest things I've done in a lab setting.

---

## The 5 Challenges

### Challenge 1 — "Did They Actually Take It?"
**Task:** Confirm whether the S3 data exfiltration actually happened. Find the IAM role used in the attack.

**What I had access to:** A SQLite terminal with S3 data event logs from CloudTrail (this was a cool format querying real CloudTrail logs using SQL)

**My approach:**

First I just looked at all the events sorted by time to see what was happening around May 6th (the date on the ransom email):

```sql
SELECT * FROM s3_data_events ORDER BY EventTime DESC LIMIT 50;
```

Spotted a bucket called `soda-vault` which was obviously where the recipes would be stored. Filtered on that:

```sql
SELECT * FROM s3_data_events 
WHERE requestParameters LIKE '%soda-vault%' 
ORDER BY EventTime DESC;
```

Then I looked specifically for `GetObject` calls (that's S3 for "download a file") on any recipe files:

```sql
SELECT userIdentity_ARN, eventTime, requestParameters 
FROM s3_data_events 
WHERE path LIKE '%recipe%' 
AND eventName LIKE 'GetObject';
```

**What I found:** A role called `S3Reader` with session name `drinks` was downloading files from `soda-vault`. The other roles in the logs were named things like `exfilcola` and `exfilAccess-Role2` — normal looking company names. `S3Reader/drinks` stuck out immediately as suspicious. Didn't match the company's naming style at all.

**Answer:** `arn:aws:sts::509843726190:assumed-role/S3Reader/drinks`

>  This challenge taught me something I keep applying now — when you have CloudTrail logs, sort by time and look at what's *different*. Normal roles have normal names. Attacker-created roles often stand out if you're paying attention.

---

### Challenge 2 — "Who Assumed That Role?"
**Task:** S3Reader is an AssumedRole — find the actual IAM user who assumed it.

**My approach:**

`AssumeRole` is the CloudTrail event that gets logged when someone assumes a role. I queried CloudTrail for that specific event targeting the `S3Reader` role:

```sql
SELECT * FROM cloudtrail 
WHERE EventName = 'AssumeRole' 
AND requestParameters LIKE '%S3Reader%';
```

**What I found:** An IAM user named `Moe.Jito` called `AssumeRole` on `S3Reader`. So the attacker either compromised Moe's account or Moe IS the attacker using a separate role to cover their tracks.

**Answer:** `Moe.Jito`

>  This is the exact same technique from Lab 03 (IAM Enumeration) — AssumeRole leaves a trail. When you see a role being assumed, always check WHO assumed it and from WHERE.

---

### Challenge 3 — "How Did Moe Get In?"
**Task:** Find the initial access vector. How was Moe.Jito's credentials compromised in the first place?

This was the hardest challenge for me. I spent the most time here.

**My approach:**

Started by looking at everything Moe.Jito did in CloudTrail just before the attack:

```sql
SELECT eventTime, eventName, sourceIPAddress, userAgent
FROM cloudtrail 
WHERE userIdentity_userName = 'Moe.Jito'
ORDER BY eventTime ASC;
```

Moe's first event was `ListAttachedUserPolicies` at `2025-05-05T12:40:26Z` from IP `109.236.81.188` — that's classic attacker enumeration behaviour (same as Lab 03). But that's what Moe did AFTER the compromise. The question is what happened BEFORE that first event.

I expanded my query to look at ALL CloudTrail events in the window just before Moe's first action:

```sql
SELECT eventTime, eventName, userIdentity_ARN, sourceIPAddress
FROM cloudtrail 
WHERE eventTime BETWEEN '2025-05-05T12:00:00Z' AND '2025-05-05T12:45:00Z'
ORDER BY eventTime ASC;
```

**The key finding:** An event called `UpdateFunctionCode20150331v2` appeared just before Moe's first action. That's Lambda — someone updated a Lambda function's code right before Moe's account started doing attacker-looking things.

A Lambda function that has IAM permissions + code that was just modified by someone else = that Lambda probably ran malicious code that stole Moe's credentials or created access for the attacker.

**Answer:** Lambda function code injection — attacker modified a Lambda function to exfiltrate credentials, which then gave them access to Moe.Jito's account.

>  I had never thought about Lambda as an attack vector before this challenge. In the PwnedLabs labs everything was S3 and IAM. Lambda can hold environment variables (including AWS credentials), and if an attacker can update its code, they can make it exfiltrate those credentials on the next invocation. This was genuinely new knowledge for me.

---

### Challenge 4 — "Where Did They Come From?"
**Task:** Find the IP address of the ExfilCola workload that was the initial entry point.

This was the challenge that made me feel like an actual forensic investigator.

The attacker deleted the logs on the machine they compromised. But the hint was that Linux has something called `overlayfs` — a filesystem layer that sometimes preserves deleted files underneath.

**Commands used (on the actual virtual instance):**

```bash
# Check mounted filesystems
findmnt

# The logs were deleted from the top layer but exist in the lower overlay layer
# Unmount the overlay to expose the original files
umount /var/log

# Now the real auth.log is visible
cat /var/log/auth.log | grep sshd | egrep -o '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | tail -1
```

**What this does:** `auth.log` records SSH login events including the source IP. Even though the attacker deleted the log, the overlayfs layer preserved it underneath. The `egrep` command extracts all IP addresses from SSH daemon logs and `tail -1` gets the last one — which was the attacker's pivot IP.

I genuinely did not know overlayfs could be used like this until this challenge. This felt like a real forensics technique, not a CTF trick.

>  **The lesson:** Attackers delete logs. But Linux filesystems are complicated and deletion isn't always permanent. Real forensic investigators know to look at filesystem layers, not just the obvious log locations.

---

### Challenge 5 — "Delete the Stolen File"
**Task:** The stolen recipe file is on the attacker's server. Connect to it and delete the file before it gets leaked.

This was the most satisfying challenge. You're not just investigating anymore — you're actively stopping the attack.

**What I found from the investigation so far:**
- The attacker's server IP (from the SSH logs in Challenge 4)
- The attacker's credentials were still active (found in Lambda environment variables during Challenge 3)
- The stolen file name: `ExfilCola-Top-Secret.txt`

**The final action:**

```bash
# Delete the stolen file from the attacker's server using their own credentials against them
curl -u "FizzShadows_1:Gx27pQwz92Rk" \
  -X DELETE \
  "http://34.118.239.100/files/ExfilCola-Top-Secret.txt"
```

File deleted. Flag captured. Secret recipe saved. 

>  This challenge taught me that incident response isn't always just defensive. Sometimes you have to actively pursue the attacker's infrastructure to contain the damage. In a real incident this would involve law enforcement and legal teams — but the technical capability to trace back to attacker infrastructure is a real skill.

---

## The Full Attack Story (Reconstructed)

After completing all 5 challenges, here's what actually happened to ExfilCola:

```
1. INITIAL ACCESS
   Attacker gained access to an ExfilCola workload (EC2 instance)
   via some external vulnerability (web app? exposed port?)

2. LATERAL MOVEMENT  
   From that workload, attacker SSH'd to a higher-privilege machine
   called "ssh-fetcher" using credentials found on the first machine

3. LAMBDA EXPLOITATION
   Attacker modified a Lambda function's code to steal IAM credentials
   Lambda ran → credentials for Moe.Jito were exfiltrated to attacker

4. IAM ABUSE
   Using Moe.Jito's credentials, attacker assumed the S3Reader role
   (which had access to soda-vault bucket)

5. DATA EXFILTRATION
   S3Reader role downloaded ExfilCola-Top-Secret.txt from soda-vault
   File uploaded to attacker's own server at 34.118.239.100

6. EXTORTION
   FizzShadows sent ransom email demanding 75 Bitcoin
```

---

## What Made This Different from PwnedLabs

I want to be honest about this because I think it's useful for other students.

PwnedLabs labs are structured. Each one teaches you a specific technique and the path is fairly guided. That's great for learning — I learned a ton from those 6 labs.

This CTF had **none of that structure**. You get a scenario and 5 blank terminals. No hints about which service to look at. No prompts about what commands to run. You have to figure out the entire investigation path yourself.

That gap between guided lab and real CTF is significant. Some of the things that helped me:

- Doing the PwnedLabs labs first (especially Breach in the Cloud and IAM Enumeration those patterns came up directly here)
- Thinking in timelines cloud attacks have a sequence. Find the sequence.
- When stuck: look at what changed just before the suspicious event, not just the event itself

The Lambda angle in Challenge 3 was the hardest because nothing in my previous labs covered Lambda as an attack vector. I had to think about it differently: "what events happened RIGHT BEFORE Moe started acting suspiciously?" that's what led me to the `UpdateFunctionCode` event.

---

## What I Learned That's New

Things this CTF taught me that I hadn't seen in the PwnedLabs labs:

**1. Querying CloudTrail logs with SQL**  
The CTF gave you a SQLite interface to CloudTrail data. This is actually close to how it works in real life — AWS Athena lets you query CloudTrail logs with SQL over S3. Writing SQL queries to answer forensic questions felt very real.

**2. Lambda as an attack vector**  
Lambda functions can have IAM roles, environment variables with credentials, and code that runs in your environment. If an attacker can `UpdateFunctionCode`, they can run anything in your environment with that Lambda's permissions. I hadn't thought about Lambda security before this.

**3. overlayfs for log recovery**  
Linux filesystem layers can preserve "deleted" files underneath the active layer. Forensic investigators know this. Attackers who try to cover their tracks by deleting logs may not succeed if the investigator knows where to look.

**4. Tracing lateral movement via SSH logs**  
`auth.log` is one of the most valuable forensic artifacts on a Linux machine. It records every SSH login with source IP, timestamp, and whether it succeeded. Combine that with CloudTrail and you can trace an attacker across multiple machines.

**5. Threat hunting follows the timeline, not the tool**  
In PwnedLabs labs I was thinking tool-first (what does GuardDuty show? what does Detective show?). In this CTF there was no GuardDuty. I had to think timeline-first — what happened, in what order, and what does each event imply about the next one?

---

## If I Was a Security Engineer at a Company Like ExfilCola

What controls would have stopped or caught this attack earlier?

| Point in Attack | What Would Have Stopped It |
|----------------|---------------------------|
| Initial workload compromise | Regular patching + WAF + restricted Security Groups (no 0.0.0.0/0) — from Security Hub Lab |
| Lateral SSH movement | SSH keys with passphrase + no shared credentials between machines + Secrets Manager |
| Lambda code modification | CloudTrail alert on `UpdateFunctionCode` from unexpected IP + Lambda code signing |
| IAM role assumption from external IP | GuardDuty `InstanceCredentialExfiltration` alert — from Detective Lab |
| S3 data exfiltration | S3 data events enabled in CloudTrail + Macie PII detection + GuardDuty S3 Protection |
| Log deletion | CloudWatch Logs with immutable retention + S3 Object Lock on log buckets |

The thing I keep noticing: every attack I study traces back to the same set of missing controls. MFA, least privilege IAM, CloudTrail everywhere, GuardDuty on, Security Hub findings being reviewed. It's not exotic stuff. It's the basics being skipped.


## Things I Still Want to Learn From This

- **AWS Athena** — the real tool for querying CloudTrail logs with SQL at scale. I want to set this up in a personal AWS account.
- **Lambda security** in depth — environment variables, execution roles, code signing, and how attackers abuse serverless functions
- **Linux forensics** deeper — overlayfs was new to me. Want to understand more about filesystem forensics
- **How to set up a personal cloud honeytoken environment** — the kind where if anyone touches a fake credential, you get an alert immediately (PwnedLabs actually has a lab for this I haven't done yet)

---

## MITRE ATT&CK Mapping

| Technique Used in CTF | MITRE ID |
|----------------------|----------|
| Initial access via compromised workload | T1190 — Exploit Public-Facing Application |
| Lambda code modification for credential theft | T1525 — Implant Internal Image |
| IAM role assumption with stolen credentials | T1078.004 — Valid Accounts: Cloud Accounts |
| S3 data exfiltration | T1530 — Data from Cloud Storage |
| SSH lateral movement | T1021.004 — Remote Services: SSH |
| Log deletion for defense evasion | T1562.008 — Disable Cloud Logs |

---

## References

- [Wiz Blog — ExfilCola CTF Announcement](https://www.wiz.io/blog/the-cloud-hunting-games-ctf-challenge)
- [Cloud Hunting Games](https://www.cloudhuntinggames.com)
- [MITRE ATT&CK Cloud Matrix](https://attack.mitre.org/matrices/enterprise/cloud/)
- [AWS CloudTrail S3 Data Events](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html)
- [AWS Lambda Security Best Practices](https://docs.aws.amazon.com/lambda/latest/dg/lambda-security.html)
- [overlayfs — Linux Kernel Documentation](https://www.kernel.org/doc/html/latest/filesystems/overlayfs.html)
- [My Certificate](https://www.cloudhuntinggames.com/certificate/exfilcola/be12e654-a13f-4c41-bad3-dbfcef21907e)

---
Thanks for reading!!
