# Lab 06 — Reveal Hidden Risks with AWS Security Hub (CSPM)
**Platform:** PwnedLabs | **Difficulty:** Beginner | **Category:** Blue Team / Posture Management  
**Tags:** `AWS` `Security Hub` `CSPM` `CIS Benchmark` `Misconfigurations` `Compliance`  
**Date:** May 2026  
**My GitHub:** [JashwanthMU](https://github.com/JashwanthMU)

---

This lab was different from the previous ones. Until now everything was either "you're the attacker" or "here are the logs, find what happened." This one was more like — *here's a running AWS environment, now tell me what's wrong with it before an attacker finds it first.* That's a new kind of thinking for me and honestly it clicked in a way I didn't expect.

---

## What is This Lab Even About?

So the lab is about **AWS Security Hub** and something called **CSPM** — Cloud Security Posture Management. When I first read that I had no idea what "posture" meant in security context. After going through the lab I get it now.

**Posture basically means: how does your cloud environment look from a security perspective right now?**

Think of it like a doctor checking your health. GuardDuty (from the previous lab) is like a doctor that calls you when you're already sick. Security Hub CSPM is like a doctor that checks everything before you get sick and says "hey you're not eating right, this will cause a problem later." It finds misconfigurations — things that aren't broken yet but will be exploited if someone finds them.

The cool thing I learned: Security Hub doesn't just come up with its own rules. It checks your environment against actual industry security standards like:

- **AWS Foundational Security Best Practices (FSBP)** — AWS's own checklist
- **CIS AWS Foundations Benchmark** — a standard from the Center for Internet Security used by companies worldwide
- **PCI DSS** — if you handle credit cards you legally have to meet this
- **NIST** — government/enterprise standard

So when Security Hub says something FAILED, it means your config doesn't meet one of these real standards. That's not just a lab thing — actual enterprise companies get audited against these same benchmarks.

---

## What I Did in This Lab

### Step 1 — Logging In and First Look at Security Hub

Logged into the AWS console with the lab credentials. Navigated to Security Hub.

The first thing that hit me was the **Security Score** at the top. The lab environment had a score somewhere around **40-something percent**. That means less than half the security checks were passing. In a real company that would be really bad.

I noticed Security Hub has two main sections:
- **Summary** — overall score, severity breakdown, top failing checks
- **Findings** — every individual misconfiguration it found
- **Security Standards** — the specific benchmarks being checked against

The dashboard was already showing a bunch of CRITICAL and HIGH findings before I even did anything. That's the point — Security Hub is always running in the background, automatically checking everything.

---

### Step 2 — Understanding the Findings

Clicked into the **Findings** tab. There were a lot of them. At first I felt overwhelmed because there were like 50+ items. Then I sorted by severity — CRITICAL first — and it became much more manageable.

Some of the findings I saw (these are real finding types Security Hub checks for):

**CRITICAL findings:**
- Root account MFA not enabled — the root user (most powerful account in all of AWS) had no MFA. Anyone with the root password could do literally anything.
- S3 bucket public access not blocked — we've seen this attack pattern already from Lab 02

**HIGH findings:**
- CloudTrail not enabled in all regions — there were blind spots where activity wasn't being logged
- IAM password policy too weak — no minimum length, no complexity requirements
- Security Groups allowing unrestricted access (0.0.0.0/0) on sensitive ports

**MEDIUM findings:**
- EBS volumes not encrypted by default
- CloudTrail log file validation not enabled — logs could be tampered with and you wouldn't know

When I clicked into any single finding, Security Hub shows you:
- What failed
- Which resource failed (the specific ARN)
- Why it matters
- A direct link to AWS documentation on how to fix it

That last part was genuinely useful. It's not just telling you what's broken, it's showing you the exact fix.

---

### Step 3 — Looking at the CIS Benchmark Standard

Went to **Security Standards** → enabled the **CIS AWS Foundations Benchmark**.

This was the part that made everything click for me. CIS has numbered controls like:

- **CIS 1.x** — IAM controls (passwords, MFA, access keys)
- **CIS 2.x** — Storage controls (S3, EBS encryption)
- **CIS 3.x** — Logging controls (CloudTrail, Config)
- **CIS 4.x** — Monitoring controls (CloudWatch alarms)
- **CIS 5.x** — Networking controls (VPC, Security Groups)

Each one has a PASS or FAIL next to it. The lab environment was failing a bunch of them. I spent time going through each failing control to understand what it was checking and why it mattered.

One that stood out: **CIS 1.14 — Ensure access keys are rotated every 90 days or less**

The check was failing because there were IAM users with access keys that hadn't been rotated in months. If those keys got leaked (like in the previous S3 lab where we found hardcoded keys), an attacker would have them for a long time. Regular rotation limits that window.

Another one: **CIS 3.1 — Ensure CloudTrail is enabled in all regions**

This was failing because CloudTrail was only enabled in us-east-1. An attacker doing stuff in us-west-2 would be completely invisible. No logs = no evidence = no detection.

---

### Step 4 — The Insight That Hit Me

While going through the findings I had a bit of a moment where I connected this to the previous labs.

In Lab 02 (S3 Enumeration), the attacker found a public bucket and pulled credentials from it. Security Hub's finding **S3.2 — S3 buckets should prohibit public read access** would have flagged that bucket BEFORE the attack happened.

In Lab 05 (Amazon Detective), we investigated an instance role being used from an external IP. Security Hub's finding **EC2.8 — EC2 instances should use IMDSv2** would have flagged the IMDSv1 vulnerability that made that credential theft possible.

This was the moment I understood why CSPM exists. It's the "fix before they find it" tool. If a security team is regularly reviewing and fixing Security Hub findings, many of the attack paths from the previous labs simply wouldn't work.

---

### Step 5 — Finding the Flag

The flag in this lab was embedded inside one of the Security Hub findings — specifically inside the details of a particular CRITICAL finding that the lab wanted us to investigate deeply. By navigating into the finding's resource details and reading through the full finding JSON, the flag was there.

I'm keeping this vague on purpose — if you're solving the lab yourself you should find it the same way I did. The process of reading through finding details is the actual skill being tested here.

---

## What is CSPM Really? (My Understanding After This Lab)

Before this lab I'd heard the word CSPM thrown around but didn't really get it. Now I think of it like this:

Security Hub CSPM is basically a continuous automated audit running 24/7 on your AWS account. Every few hours it's checking hundreds of configuration settings across your entire environment and comparing them to known-good security standards.

The companies I want to work at — Wiz, Palo Alto, Lacework — their core products are CSPM tools. Wiz literally does this for multi-cloud environments (AWS + Azure + GCP) and that's why they're worth so much. After doing this lab I understand what they're selling. They're selling "we'll tell you everything that's misconfigured before an attacker finds it."

---

## What Was Misconfigured and Why It's Dangerous

Here's my breakdown of the main issues the lab environment had:

**No MFA on root account**  
The root account can do literally anything — delete all data, close the account, change billing. No MFA means a leaked root password = complete account takeover. This should be the first thing you fix in any AWS account.

**CloudTrail gaps**  
If CloudTrail isn't on in every region, attackers can operate in those regions with zero logging. In the previous labs we used CloudTrail to catch attackers. No CloudTrail = blind spot = free zone for attackers.

**Weak IAM password policy**  
Short passwords, no complexity = easier to brute force or spray. The CIS benchmark requires minimum 14 characters.

**Security Groups open to 0.0.0.0/0 on port 22 (SSH)**  
This means anyone on the internet can try to SSH into EC2 instances. The attack surface is the entire internet. Should be restricted to your company's IP range only.

**EBS not encrypted by default**  
If someone gets access to an EBS volume (like the public EBS snapshot from Lab 04), unencrypted data is immediately readable. Encryption at rest means even if they get the snapshot, it's useless without the key.

**Stale access keys**  
Old keys that are never rotated are ticking time bombs. If one gets leaked and no one notices, the attacker has persistent access indefinitely.

---

## How to Fix These (Remediation)

I'll go through the main ones:

**Enable MFA on root immediately:**
```
AWS Console → Account → Security credentials → Assign MFA device
Use a virtual MFA app (Google Authenticator) or hardware key
```
> There's no CLI command for this one — MFA on root must be done through the console.

**Fix the CloudTrail gap:**
```bash
# Enable CloudTrail across ALL regions
aws cloudtrail create-trail \
  --name org-wide-trail \
  --s3-bucket-name my-cloudtrail-logs \
  --is-multi-region-trail \
  --enable-log-file-validation
  
aws cloudtrail start-logging --name org-wide-trail
```

**Fix weak IAM password policy:**
```bash
aws iam update-account-password-policy \
  --minimum-password-length 14 \
  --require-symbols \
  --require-numbers \
  --require-uppercase-characters \
  --require-lowercase-characters \
  --max-password-age 90 \
  --password-reuse-prevention 24
```

**Block public access on all S3 buckets account-wide:**
```bash
aws s3control put-public-access-block \
  --account-id $(aws sts get-caller-identity --query Account --output text) \
  --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,\
    BlockPublicPolicy=true,RestrictPublicBuckets=true
```

**Fix Security Groups — remove 0.0.0.0/0 on port 22:**
```bash
# First find the offending security group
aws ec2 describe-security-groups \
  --filters "Name=ip-permission.from-port,Values=22" \
             "Name=ip-permission.cidr,Values=0.0.0.0/0" \
  --query 'SecurityGroups[*].{ID:GroupId,Name:GroupName}'

# Remove the overly permissive rule
aws ec2 revoke-security-group-ingress \
  --group-id sg-xxxxxxxx \
  --protocol tcp \
  --port 22 \
  --cidr 0.0.0.0/0

# Add back restricted access (your company IP only)
aws ec2 authorize-security-group-ingress \
  --group-id sg-xxxxxxxx \
  --protocol tcp \
  --port 22 \
  --cidr YOUR_COMPANY_IP/32
```

**Enable EBS encryption by default:**
```bash
aws ec2 enable-ebs-encryption-by-default --region us-east-1
# Do this in every region you use
```

**Rotate stale access keys:**
```bash
# Find all users with old access keys
aws iam list-users --query 'Users[*].UserName' --output text | \
  xargs -I {} aws iam list-access-keys --user-name {} \
  --query 'AccessKeyMetadata[?Status==`Active`].{User:UserName,Key:AccessKeyId,Created:CreateDate}'

# For each key older than 90 days: deactivate old, create new, update application, delete old
aws iam update-access-key --user-name USERNAME --access-key-id AKIAXXXXXXX --status Inactive
aws iam create-access-key --user-name USERNAME
```

---

## Real World Application — If I Was a Security Engineer Tomorrow

This is something I'm adding to every writeup — connecting the lab to what I'd actually do in a real job. Here's my thinking on Security Hub in production:

The first week at any cloud security job, I'd check:

1. Is Security Hub enabled in ALL regions? (not just one)
2. What's the current security score? (below 70% = serious work needed)
3. Are there any CRITICAL findings? (fix those in the first sprint)
4. Is the CIS benchmark enabled? (if not, enable it immediately)
5. Is there an alert when new CRITICAL findings appear? (EventBridge → SNS → Slack)

The thing that surprised me was how many real companies probably have these basic things misconfigured. The lab environment was a fictional company but the misconfigs (no root MFA, open security groups, CloudTrail gaps) are exactly the kind of things that come up in real cloud security assessments. Companies like Wiz exist because finding and fixing these automatically at scale is genuinely hard.

---

## Connection to Previous Labs

One thing I try to do in each writeup is connect it back to what came before, because cloud security is not a set of isolated topics — it's a chain.

| Previous Lab | Connection to This Lab |
|---|---|
| Lab 02 — S3 Enumeration | Security Hub finding S3.2 would have flagged the public bucket before the attack |
| Lab 04 — Account ID from S3 | Security Hub finding EC2.1 flags public EBS snapshots — the thing we pivoted to after getting the account ID |
| Lab 05 — Amazon Detective | Detective investigates after GuardDuty detects. Security Hub prevents by fixing config before GuardDuty needs to fire |
| Lab 03 — IAM Enumeration | Security Hub IAM findings (MFA, password policy, stale keys) make IAM-based attacks much harder |

This is the thing that really motivates me — each lab builds on the last one. CSPM is like the foundation. If Security Hub findings are all green, the attack paths from Labs 2, 3, and 4 mostly stop working.

---

## What I Learned

Honestly the biggest thing from this lab wasn't a specific command or service. It was the mental model shift.

Before this lab I was mostly thinking offensively — how does an attacker get in? Now I'm thinking about how you stop them before they even try. CSPM is boring compared to a juicy attack chain, but it's probably the highest-leverage thing a cloud security team can do. One misconfiguration found and fixed by Security Hub might prevent the exact attack chain I simulated in Lab 02 or Lab 04.

I also now understand what CSPM products like Wiz actually do. They do this same thing (automated config scanning against security benchmarks) but across AWS + Azure + GCP + Kubernetes all in one place. That's the commercial value. After this lab, when I see Wiz in a job posting I know exactly what skill they're looking for.

---

## Things I Want to Understand Better

I always add this section because there's always stuff I don't fully get yet:

- **How does Security Hub handle false positives at scale?** Some findings might be intentional (like a public S3 bucket that's meant to be public for hosting a website). How do teams suppress those properly without hiding real issues?
- **How do you prioritize when there are 500+ findings?** The lab had a manageable number. A real enterprise might have thousands. What's the triage methodology?
- **Custom controls** — Security Hub lets you write your own checks. I want to understand how that works.
- **Multi-account Security Hub** — the lab was a single account. Real companies have 50-100 AWS accounts. There's a way to aggregate all findings centrally. I want to learn that.

---

## MITRE ATT&CK Mapping

Security Hub CSPM findings map directly to attack techniques attackers use:

| Finding | ATT&CK Technique it Prevents |
|---------|------------------------------|
| Root MFA not enabled | T1078 — Valid Accounts |
| Open Security Groups (port 22) | T1190 — Exploit Public-Facing Application |
| CloudTrail gaps | T1562.008 — Disable Cloud Logs |
| Stale access keys | T1552.001 — Credentials in Files |
| Public S3 buckets | T1530 — Data from Cloud Storage |
| IMDSv1 allowed | T1552.005 — Cloud Instance Metadata API |

---

## References

- [AWS Security Hub Documentation](https://docs.aws.amazon.com/securityhub/latest/userguide/what-is-securityhub.html)
- [CIS AWS Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services)
- [AWS Foundational Security Best Practices controls](https://docs.aws.amazon.com/securityhub/latest/userguide/fsbp-standard.html)
- [PwnedLabs — Reveal Hidden Risks with AWS Security Hub](https://pwnedlabs.io/labs/reveal-hidden-risks-with-aws-security-hub)
- [MITRE ATT&CK Cloud Matrix](https://attack.mitre.org/matrices/enterprise/cloud/)

---


