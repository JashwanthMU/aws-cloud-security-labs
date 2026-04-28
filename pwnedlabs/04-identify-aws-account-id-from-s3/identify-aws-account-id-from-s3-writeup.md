# Identify the AWS Account ID from a Public S3 Bucket — PwnedLabs Writeup
**Author:** Jashwanth | **Platform:** PwnedLabs | **Difficulty:** Beginner  
**Tags:** `AWS` `S3` `Reconnaissance` `Account ID Enumeration` `EBS Snapshots` `s3:ResourceAccount` `OSINT`   
**Lab URL:** https://pwnedlabs.io/labs/identify-the-aws-account-id-from-a-public-s3-bucket

---

> ⚠️ **Disclaimer:** This writeup is for educational purposes only. All commands were executed inside a sanctioned lab environment. Never use these techniques against systems you don't own or have explicit written permission to test.

---

## Table of Contents
1. [Scenario](#1-scenario)
2. [Core Concept — Why AWS Account IDs Matter](#2-core-concept--why-aws-account-ids-matter)
3. [Tools Used](#3-tools-used)
4. [Attack Path — Step by Step](#4-attack-path--step-by-step)
5. [Blue Team — How to Detect This Attack](#5-blue-team--how-to-detect-this-attack)
6. [Root Cause Analysis](#6-root-cause-analysis)
7. [Remediation](#7-remediation)
8. [Real-World Playbook — If This Happens at Your Company](#8-real-world-playbook--if-this-happens-at-your-company)
9. [Real-World Breach Connection](#9-real-world-breach-connection)
10. [Key Takeaways](#10-key-takeaways)
11. [References](#11-references)

---

## 1. Scenario

**Company:** Mega Big Tech (fictional)  
**Our Role:** Red Team — External Penetration Tester  
**Entry Point:** A single IP address + AWS credentials (simulating a tester given minimal initial access)  
**Mission:** Starting from only an IP address, identify the AWS Account ID that owns the target's public S3 bucket, then discover any further exposed cloud resources using that account ID

**In plain English:**  
A company's website loads images from a public S3 bucket. That bucket's name leaks from the page source. Using a clever AWS API technique that exploits the `s3:ResourceAccount` policy condition key, we can brute-force the 12-digit AWS Account ID that owns that bucket — one digit at a time — without ever needing direct access to the account. With that Account ID, we then pivot to discover publicly exposed EBS snapshots that shouldn't be public.

**Attack Chain at a Glance:**
```
[IP Address] → [nmap scan: port 80 open] → [Browse website]
    → [Page source: S3 bucket name discovered: mega-big-tech]
        → [Bucket enumeration: public, images only]
            → [curl headers: bucket region = us-east-1]
                → [s3-account-search tool: brute-force Account ID digit by digit]
                    → [Account ID: 107513503799] 
                        → [Pivot: discover public EBS snapshot] 
```

---

## 2. Core Concept — Why AWS Account IDs Matter

This lab teaches a technique that goes far beyond a simple CTF flag. Understanding WHY account IDs matter in a real engagement is essential.

### What is an AWS Account ID?
Every AWS account has a unique 12-digit identifier (e.g., `107513503799`). It is embedded in every ARN (Amazon Resource Name) and used across all AWS services to identify resource ownership.

### Why attackers want it
Once an attacker has your AWS Account ID, they can:

| What They Can Do | How |
|-----------------|-----|
| Enumerate IAM users and roles | AWS returns distinct error messages for valid vs invalid IAM principals — attackers use this to verify if `arn:aws:iam::ACCOUNT_ID:user/admin` exists |
| Discover public EBS snapshots | Filter `describe-snapshots` by `--owner-ids ACCOUNT_ID` |
| Discover public RDS snapshots | Filter `describe-db-snapshots` by account ownership |
| Target spear-phishing | Account ID in ARNs in public code/docs reveals internal usernames and role names |
| Construct valid ARNs for further attacks | Many AWS attacks require knowing the exact ARN of a target resource |

>  AWS Account IDs are often considered "not sensitive" by developers — they frequently appear in public GitHub repos, Terraform configs, and CloudFormation templates. This lab shows why that assumption is dangerous.

### The `s3:ResourceAccount` Technique (How the Tool Works)

Security researcher Ben Bridts discovered that AWS's `s3:ResourceAccount` IAM policy condition key — designed to *prevent* the Confused Deputy Problem — can be weaponized to enumerate account IDs.

**The Confused Deputy Problem (simplified):**
- Your company gives a third-party service permission to access your S3 bucket
- An attacker creates their own bucket and tricks that service into accessing it using your credentials
- `s3:ResourceAccount` was created to say: *"Only access S3 buckets owned by MY account ID"*

**How attackers abuse it:**
The `s3-account-search` tool creates an IAM policy that uses `s3:ResourceAccount` with a wildcard, then tests the bucket access with each possible digit prefix. If access is granted → that digit is correct. If denied → try the next digit. This repeats until all 12 digits are discovered.

```
Testing: 1*          → Access Granted   (first digit is 1)
Testing: 10*         → Access Denied  
Testing: 11*         → Access Denied   
Testing: 107*        → Access Granted   (first three digits are 107)
... continues until full 12 digits found
```

The tool needs:
1. A **bucket name** (discovered from recon)
2. An **IAM role** you control that has `s3:GetObject` or `s3:ListBucket` on the target bucket

---

## 3. Tools Used

| Tool | Purpose |
|------|---------|
| `nmap` | Port scan — identify open services on the target IP |
| `nslookup` / `dig -x` | Reverse DNS — confirm the IP belongs to AWS EC2 |
| Browser + View Source | Discover S3 bucket references in page HTML |
| `curl` | Retrieve page source, read HTTP response headers |
| `aws s3 ls` | Enumerate bucket contents (unauthenticated) |
| `aws sts get-caller-identity` | Verify our AWS identity |
| `aws configure` | Set up the provided credentials profile |
| `s3-account-search` | Brute-force the AWS Account ID using `s3:ResourceAccount` |
| `aws ec2 describe-snapshots` | Discover public EBS snapshots using the found Account ID |

---

## 4. Attack Path — Step by Step

### Step 1 — Configure Credentials and Verify Identity

We were given AWS credentials at the start of the lab. Configure them first:

```bash
aws configure --profile lab
# AWS Access Key ID: [provided]
# AWS Secret Access Key: [provided]
# Default region: us-east-1
# Output format: json
```

Verify our identity:

```bash
aws sts get-caller-identity --profile lab
```

**Output:**
```json
{
  "UserId": "AIDA...",
  "Account": "427648302155",
  "Arn": "arn:aws:iam::427648302155:user/s3user"
}
```

We are `s3user` in account `427648302155`. This is the attacker-controlled account used for the enumeration — not the target's account. The role `LeakyBucket` in this account will be the tool we use to discover the target's Account ID.

Try some basic IAM enumeration — all return `AccessDenied`:

```bash
aws iam list-users --profile lab    # AccessDenied
aws iam list-groups --profile lab   # AccessDenied
aws iam list-roles --profile lab    # AccessDenied
```

>  This is a minimal-privilege account. IAM enumeration fails. The attack path here is not IAM-based — it's infrastructure recon from the IP address.

---

### Step 2 — Network Reconnaissance on the Target IP

```bash
nslookup 54.204.171.32
# Non-authoritative answer: ec2-54-204-171-32.compute-1.amazonaws.com
```

>  The reverse DNS confirms this is an AWS EC2 instance in `us-east-1` (compute-1 = us-east-1). We're dealing with AWS infrastructure.

```bash
nmap -sC -sV 54.204.171.32
```

**Output:**
```
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd
```

Only port 80 is open. This is a simple web server — no SSH, no RDP, no admin panels. The attack surface is the web application.

---

### Step 3 — Web Application Analysis — Discover the S3 Bucket Name

Browse to `http://54.204.171.32` in the browser. The site belongs to "Mega Big Tech" — a basic corporate website. Most links are non-functional. The focus is on finding AWS infrastructure references.

**View page source / use curl:**

```bash
curl http://54.204.171.32 | grep -i "s3\|amazonaws\|bucket"
```

**Finding in page source:**
```html
<img src="https://mega-big-tech.s3.amazonaws.com/images/hero.jpg">
<img src="https://mega-big-tech.s3.amazonaws.com/images/logo.png">
```

>  **Bucket name discovered: `mega-big-tech`**

The website is serving static assets (images) directly from this S3 bucket. This is a very common pattern — and a very common way bucket names get exposed.

---

### Step 4 — S3 Bucket Enumeration

Attempt unauthenticated listing:

```bash
aws s3 ls s3://mega-big-tech --no-sign-request
```

**Output:**
```
PRE images/
```

```bash
aws s3 ls s3://mega-big-tech/images/ --no-sign-request
```

**Output:**
```
2023-xx-xx  xx:xx:xx    48291  hero.jpg
2023-xx-xx  xx:xx:xx    12043  logo.png
2023-xx-xx  xx:xx:xx    94820  team.jpg
... (all images)
```

The bucket is publicly listable and contains only image files — no credentials, no config files, no sensitive data visible. A dead end for direct data exfiltration.

**Discover the bucket's region from HTTP headers:**

```bash
curl -I https://mega-big-tech.s3.amazonaws.com
```

**Key header in response:**
```
x-amz-bucket-region: us-east-1
```

>  The `x-amz-bucket-region` header in S3 HTTP responses leaks the exact AWS region where the bucket is hosted. This will matter when we pivot to look for EBS snapshots.

---

### Step 5 — Install `s3-account-search` Tool

```bash
pip3 install s3-account-search
```

This tool was developed by security researcher Ben Bridts and is built around the `s3:ResourceAccount` IAM policy condition key technique described in Section 2.

---

### Step 6 — Brute-Force the AWS Account ID

The tool needs:
- Our configured AWS profile (`lab`)
- The ARN of a role we can assume that has S3 permissions (`LeakyBucket`, provided by the lab)
- The target bucket name (`mega-big-tech`)

```bash
s3-account-search --profile lab \
  arn:aws:iam::427648302155:role/LeakyBucket \
  mega-big-tech
```

**What happens under the hood:**
```
Testing account ID prefix: 1...   → Granted 
Testing account ID prefix: 10...  → Denied  
Testing account ID prefix: 107... → Granted 
Testing account ID prefix: 1075.. → Granted 
... (continues digit by digit)
```

**Final output:**
```
Found account ID: 107513503799
```

>  **Target AWS Account ID: `107513503799`** 

This is the flag for the lab. But more importantly — this is now a pivot point for further reconnaissance.

---

### Step 7 — Pivot: Discover Public EBS Snapshots

With the Account ID in hand, check for publicly exposed EBS snapshots:

**Via AWS Management Console:**
- Log into your AWS console
- Select region: `us-east-1`
- EC2 → Elastic Block Store → Snapshots
- Filter: Public snapshots, Owner: `107513503799`
- **Result: 1 public EBS snapshot found** 

**Via AWS CLI:**

```bash
aws ec2 describe-snapshots \
  --owner-ids 107513503799 \
  --query "Snapshots[*].{ID:SnapshotId,Description:Description,StartTime:StartTime}" \
  --output table \
  --region us-east-1
```

**Output:**
```
-----------------------------------------------------------
|                   DescribeSnapshots                     |
+------------------+---------------------+----------------+
|   Description    |      StartTime      |      ID        |
+------------------+---------------------+----------------+
|  DB Backup       |  2023-10-xx...      |  snap-0abc...  |
+------------------+---------------------+----------------+
```

>  A publicly exposed EBS snapshot is catastrophic. EBS snapshots are disk images — they can contain databases, application code, config files, plaintext credentials, SSH keys, and entire operating system environments. Any AWS user in the same region can copy this snapshot to their own account and mount it.

---

## 5. Blue Team — How to Detect This Attack

### Detection Challenge: The Enumeration Happens in the Attacker's Account

This is the most important detection note for this lab. The `s3-account-search` technique works by making `sts:AssumeRole` calls in the **attacker's own AWS account** — not yours. The IAM policy evaluation happens on their side.

>  **The bucket owner's CloudTrail will NOT log the account ID brute-force activity** unless S3 data events are explicitly enabled (they are off by default due to cost and volume).

### Detection Signal 1 — Enable S3 Data Events in CloudTrail

```bash
# Enable data events for the specific bucket
aws cloudtrail put-event-selectors \
  --trail-name your-cloudtrail-trail \
  --event-selectors '[{
    "ReadWriteType": "All",
    "IncludeManagementEvents": true,
    "DataResources": [{
      "Type": "AWS::S3::Object",
      "Values": ["arn:aws:s3:::mega-big-tech/"]
    }]
  }]'
```

With data events enabled, you'll see **every** `GetObject` and `ListBucket` request, including from which IP and account.

### Detection Signal 2 — Unusual ListBucket Patterns

The `s3-account-search` tool makes many rapid `ListBucket` calls from an external account. Even without data events, look for:

```bash
# In S3 server access logs (if enabled)
grep "ListBucket" /path/to/s3-access-logs/ | \
  awk '{print $4}' | sort | uniq -c | sort -rn
# Any IP making 12+ ListBucket requests to your bucket in <60 seconds = suspicious
```

### Detection Signal 3 — Public EBS Snapshot Alert via AWS Config

```bash
# AWS Config rule to detect any publicly shared EBS snapshot
aws configservice put-config-rule --config-rule '{
  "ConfigRuleName": "ebs-snapshot-public-restorable-check",
  "Source": {
    "Owner": "AWS",
    "SourceIdentifier": "EBS_SNAPSHOT_PUBLIC_RESTORABLE_CHECK"
  }
}'
```

**Alert rule:** Any EBS snapshot set to `createVolumePermission: all` → immediate alert.

### Detection Signal 4 — Amazon GuardDuty S3 Protection

Enable GuardDuty S3 Protection — it monitors S3 access patterns and can alert on:
- Access from unusual geographic locations
- Access patterns inconsistent with normal application behaviour
- Known malicious IP addresses accessing your buckets

```bash
aws guardduty update-detector \
  --detector-id [your-detector-id] \
  --data-sources '{"S3Logs": {"Enable": true}}'
```

---

## 6. Root Cause Analysis

| # | Root Cause | Severity |
|---|-----------|---------|
| 1 | S3 bucket `mega-big-tech` publicly listable — bucket name confirmed through page source, listability confirmed via unauthenticated enumeration |   Critical |
| 2 | EBS snapshot set to public — any AWS user in the same region can copy and mount the disk image, potentially containing databases, credentials, and source code |   Critical |
| 3 | S3 bucket name exposed in page source HTML — trivial to discover with a single `curl` and `grep` |  High |
| 4 | S3 data events not enabled on CloudTrail — account ID enumeration via `s3:ResourceAccount` is invisible to the bucket owner |  High |
| 5 | No AWS Config rule monitoring EBS snapshot public access — the snapshot was publicly exposed with no automated detection |  High |
| 6 | No GuardDuty S3 Protection enabled — anomalous ListBucket patterns go undetected |  Medium |
| 7 | Website serving assets directly from S3 bucket rather than through CloudFront — unnecessary direct exposure of bucket name |   Medium |

---

## 7. Remediation

### Immediate (within 1 hour of detection)

```bash
# 1. Make the EBS snapshot private IMMEDIATELY
aws ec2 modify-snapshot-attribute \
  --snapshot-id snap-0abc123... \
  --attribute createVolumePermission \
  --operation-type remove \
  --group-names all

# Verify it's no longer public
aws ec2 describe-snapshot-attribute \
  --snapshot-id snap-0abc123... \
  --attribute createVolumePermission
# Should return empty createVolumePermissions

# 2. Block all public access on the S3 bucket
aws s3api put-public-access-block \
  --bucket mega-big-tech \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

# 3. Check ALL EBS snapshots in the account for public access
aws ec2 describe-snapshots \
  --owner-ids self \
  --query "Snapshots[?State=='completed'].{ID:SnapshotId}" \
  --output text | xargs -I {} aws ec2 describe-snapshot-attribute \
    --snapshot-id {} --attribute createVolumePermission
```

### Short-Term (within 24 hours)

**Serve S3 assets through CloudFront instead of direct S3 URLs:**
```bash
# Create CloudFront distribution in front of S3 bucket
# This hides the actual bucket name from page source
aws cloudfront create-distribution \
  --origin-domain-name mega-big-tech.s3.amazonaws.com \
  --default-root-object index.html

# Update S3 bucket policy to only allow CloudFront access (OAC)
aws s3api put-bucket-policy --bucket mega-big-tech --policy '{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "Service": "cloudfront.amazonaws.com"
    },
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::mega-big-tech/*",
    "Condition": {
      "StringEquals": {
        "AWS:SourceArn": "arn:aws:cloudfront::107513503799:distribution/DISTRIBUTION_ID"
      }
    }
  }]
}'
```

**Enable S3 data events in CloudTrail:**
```bash
aws cloudtrail put-event-selectors \
  --trail-name main-trail \
  --event-selectors '[{
    "ReadWriteType": "All",
    "IncludeManagementEvents": true,
    "DataResources": [{
      "Type": "AWS::S3::Object",
      "Values": ["arn:aws:s3:::mega-big-tech/"]
    }]
  }]'
```

### Long-Term (within 1 week)

**Automated EBS snapshot visibility audit (run weekly):**
```bash
#!/bin/bash
# List all public EBS snapshots owned by account
PUBLIC_SNAPS=$(aws ec2 describe-snapshots \
  --owner-ids self \
  --filters Name=attribute-value,Values=all \
  --query 'Snapshots[*].SnapshotId' \
  --output text)

if [ -n "$PUBLIC_SNAPS" ]; then
  echo "ALERT: Public EBS snapshots found: $PUBLIC_SNAPS"
  # Send to SNS/Slack/PagerDuty
fi
```

**Enable AWS Config rule for public EBS snapshots:**
```bash
aws configservice put-config-rule --config-rule '{
  "ConfigRuleName": "ebs-snapshot-public-restorable-check",
  "Source": {
    "Owner": "AWS",
    "SourceIdentifier": "EBS_SNAPSHOT_PUBLIC_RESTORABLE_CHECK"
  }
}'
```

**Enable GuardDuty S3 Protection across all accounts:**
```bash
aws guardduty update-detector \
  --detector-id $(aws guardduty list-detectors --query 'DetectorIds[0]' --output text) \
  --data-sources '{"S3Logs": {"Enable": true}}'
```

**Periodic Account ID exposure audit — find your Account ID in public repos:**
```bash
# Search GitHub for your account ID (use GitHub search or trufflehog)
# Your Account ID in a public repo = someone could be building attack paths against you
trufflehog github --repo https://github.com/your-org/your-repo
```

---

## 8. Real-World Playbook — If This Happens at Your Company

> Your incident response guide for account ID exposure and public snapshot discovery.

### Detection Triggers (What Should Alert You)

| Signal | Source | Urgency |
|--------|--------|---------|
| AWS Config finding: EBS snapshot set to public | AWS Config |   Immediate |
| GuardDuty finding: S3 access from unknown external account | GuardDuty |   Immediate |
| Unusual volume of `ListBucket` API calls from unknown IPs | S3 Access Logs / CloudTrail |   Immediate |
| Account ID found in public GitHub repository | Secrets scanning / trufflehog |   High |
| CloudFront origin exposes raw S3 bucket URL | Security review |   Medium |
| S3 bucket accessible without CloudFront | AWS Config / manual audit |   Medium |

### Incident Response Steps (Production)

```
1. CONTAIN   → Make EBS snapshot private immediately (highest priority — disk images can contain anything)
2. ASSESS    → Determine when the snapshot was made public, and how long it's been public
3. SCOPE     → Check ALL EBS, RDS, and Redshift snapshots for public access
4. AUDIT     → Check all S3 buckets for public listing (s3api get-bucket-acl, get-bucket-policy)
5. TRACE     → Enable CloudTrail data events and S3 access logging if not already enabled
6. HUNT      → Search GitHub, GitLab, Pastebin for your Account ID — was it already known?
7. REMEDIATE → Block S3 public access, serve through CloudFront, make all snapshots private
8. HARDEN    → Enable AWS Config rules, GuardDuty S3 Protection, automated snapshot audits
9. REVIEW    → Post-incident report, developer security training on S3 and snapshot hygiene
```

### Key AWS CLI Commands for Real IR

```bash
# Find ALL public EBS snapshots owned by your account
aws ec2 describe-snapshots \
  --owner-ids self \
  --filters "Name=attribute-value,Values=all" \
  --query "Snapshots[*].{ID:SnapshotId,Description:Description,StartTime:StartTime}" \
  --output table \
  --region us-east-1

# Find ALL public RDS snapshots
aws rds describe-db-snapshots \
  --snapshot-type public \
  --query "DBSnapshots[?Engine!='null'].{ID:DBSnapshotIdentifier,Engine:Engine}" \
  --output table

# Find ALL public S3 buckets in your account
aws s3api list-buckets --query 'Buckets[*].Name' --output text | \
  xargs -I {} sh -c 'echo "{}:"; aws s3api get-bucket-acl --bucket {} 2>/dev/null | grep -i "AllUsers\|AuthenticatedUsers" || echo "  Not public"'

# Check if Block Public Access is enabled account-wide
aws s3control get-public-access-block \
  --account-id $(aws sts get-caller-identity --query Account --output text)

# Search CloudTrail for all ListBucket events on your bucket in last 7 days
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ListBuckets \
  --start-time $(date -d '7 days ago' +%s)

# Instantly make ALL public EBS snapshots private (use with caution in prod!)
aws ec2 describe-snapshots --owner-ids self \
  --filters "Name=attribute-value,Values=all" \
  --query "Snapshots[*].SnapshotId" --output text | \
  xargs -I {} aws ec2 modify-snapshot-attribute \
    --snapshot-id {} \
    --attribute createVolumePermission \
    --operation-type remove \
    --group-names all
```

---

## 9. Real-World Breach Connection

**This technique is actively used by real threat actors and security researchers:**

**Capital One (2019)** — The attacker's initial recon included identifying the account structure and public resources associated with the target AWS account. Knowing the Account ID accelerated the attack chain.

**Exposed EBS Snapshots are a chronic industry problem.** Research by Reposify (2021) found that thousands of organizations had public EBS snapshots containing sensitive data including database dumps, source code, and plaintext credentials. A single misconfigured snapshot can expose the equivalent of an entire production database to any AWS user worldwide.

**GrayHatWarfare** is a public database that indexes publicly exposed AWS S3 buckets and EBS snapshots. Attackers actively use it to find exposed company data without running any tools at all. If your snapshot is public, it may already be indexed.

**The `s3:ResourceAccount` technique** was originally documented by researcher Ben Bridts in a blog post, and later incorporated into the `hackingthe.cloud` knowledge base — confirming it's part of the standard AWS red team toolkit.

>**MITRE ATT&CK Mapping:**
> - T1530 — Data from Cloud Storage
> - T1580 — Cloud Infrastructure Discovery
> - T1619 — Cloud Storage Object Discovery
> - T1087.004 — Account Discovery: Cloud Account

---

## 10. Key Takeaways

| # | Lesson | Apply Where |
|---|--------|------------|
| 1 | S3 bucket names in page source HTML = attack surface. Always serve static assets through CloudFront | Web app architecture review |
| 2 | A public S3 bucket with only images is not "harmless" — the bucket name enables account ID enumeration | S3 security assessments |
| 3 | `curl -I` on an S3 URL reveals the `x-amz-bucket-region` header — always check HTTP headers for info disclosure | Web recon |
| 4 | `s3:ResourceAccount` + `s3-account-search` = 12-digit Account ID from a bucket name alone | AWS red team toolkit |
| 5 | Account ID → public EBS snapshot search → disk images with databases and credentials | Post-recon pivoting |
| 6 | The account ID brute-force is invisible to the bucket owner unless S3 data events are enabled (costly, off by default) | Defensive blind spots |
| 7 | AWS Account IDs are NOT a secret — treat them as sensitive but already potentially known | Risk posture |
| 8 | Public EBS snapshots are disaster-level misconfigurations — enable AWS Config rule for this immediately | Cloud hardening priorities |
| 9 | `nslookup`/`dig -x` on any IP during an AWS engagement — immediately tells you if it's EC2, RDS, CloudFront, etc. | Initial recon |
| 10 | The attack chain here required zero exploits — only public information, one open-source tool, and chained AWS API calls | Cloud security fundamentals |

---

## 11. References

- [Ben Bridts — Finding the AWS Account ID of Any Public S3 Bucket](https://cloudar.be/awsblog/finding-the-account-id-of-any-public-s3-bucket/)
- [HackingThe.Cloud — AWS Account ID from S3 Bucket](https://hackingthe.cloud/aws/enumeration/account_id_from_s3_bucket/)
- [s3-account-search Tool (GitHub)](https://github.com/WeAreCloudar/s3-account-search)
- [AWS S3 ResourceAccount Condition Key](https://docs.aws.amazon.com/AmazonS3/latest/userguide/amazon-s3-policy-keys.html)
- [AWS CloudFront with S3 Origin Access Control](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-restricting-access-to-s3.html)
- [AWS Config — EBS Snapshot Public Restorable Check](https://docs.aws.amazon.com/config/latest/developerguide/ebs-snapshot-public-restorable-check.html)
- [MITRE ATT&CK — Cloud Infrastructure Discovery (T1580)](https://attack.mitre.org/techniques/T1580/)
- [MITRE ATT&CK — Cloud Storage Object Discovery (T1619)](https://attack.mitre.org/techniques/T1619/)
- [PwnedLabs — Identify the AWS Account ID from a Public S3 Bucket](https://pwnedlabs.io/labs/identify-the-aws-account-id-from-a-public-s3-bucket)

---

by Jashwanth | [GitHub](https://github.com/JashwanthMU) | Part of the `aws-cloud-security-labs` writeup series*
