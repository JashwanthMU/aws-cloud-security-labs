# Investigate Threats with Amazon Detective — PwnedLabs Writeup 
**Tags:** `AWS` `Amazon Detective` `GuardDuty` `CloudTrail` `VPC Flow Logs` `Threat Investigation` `Incident Response` `Blue Team`   
**Lab URL:** https://pwnedlabs.io/labs/investigate-threats-with-amazon-detective

---

> ⚠️ **Disclaimer:** This writeup is for educational purposes only. All investigation steps were performed inside a sanctioned lab environment on pre-generated findings.

---

## Table of Contents
1. [Scenario](#1-scenario)
2. [Core Concept — The AWS Threat Detection Stack](#2-core-concept--the-aws-threat-detection-stack)
3. [Tools Used](#3-tools-used)
4. [Investigation Path — Step by Step](#4-investigation-path--step-by-step)
5. [Root Cause Analysis](#5-root-cause-analysis)
6. [Remediation](#6-remediation)
7. [Real-World Playbook — If This Happens at Your Company](#7-real-world-playbook--if-this-happens-at-your-company)
8. [Real-World Breach Connection](#8-real-world-breach-connection)
9. [Key Takeaways](#9-key-takeaways)
10. [References](#10-references)

---

## 1. Scenario

**Company:** Huge Logistics (fictional)  
**Our Role:** Blue Team — Cloud Security Analyst  
**Entry Point:** AWS Management Console access with Amazon Detective and GuardDuty pre-enabled  
**Mission:** A GuardDuty alert has fired indicating suspicious activity in the AWS environment. Use Amazon Detective to investigate the finding, reconstruct the full attack timeline, identify affected resources, determine if it is a true positive or false positive, and scope the full blast radius

**In plain English:**  
Unlike the previous labs where we were playing the attacker, this lab is pure blue team. GuardDuty detected something suspicious — a compromised credential being used from an unusual location with anomalous API call patterns. Amazon Detective is the tool that answers the deeper question GuardDuty cannot: *"We know something bad happened — but what exactly? When? Which resources were touched? What else did the attacker do?"*

This lab teaches you how real SOC analysts and cloud security engineers investigate live threats inside AWS natively, without needing Splunk, a SIEM, or external tooling.

**Investigation Flow:**
```
[GuardDuty Finding Triggered] → [Pivot to Amazon Detective]
    → [Examine Entity Profile: IAM User/Role]
        → [Analyze API Call Volume — Baseline vs Anomaly]
            → [Examine Source IPs — Geolocation + Threat Intel]
                → [Inspect VPC Flow Logs — Network Behaviour]
                    → [Review Finding Groups — Related Activity]
                        → [Timeline Reconstructed] → [Scope Confirmed] 
```

---

## 2. Core Concept — The AWS Threat Detection Stack

Before the investigation, understand how GuardDuty and Detective fit together. This is the most important architectural concept in AWS blue team work.

### The Three-Layer Stack

```
┌─────────────────────────────────────────────────────────┐
│                   AWS Security Hub                       │
│     (Aggregates + prioritizes all findings centrally)    │
└────────────────────────┬────────────────────────────────┘
                         │
          ┌──────────────┼──────────────┐
          │              │              │
   ┌──────▼──────┐ ┌─────▼─────┐ ┌────▼──────┐
   │  GuardDuty  │ │  Macie    │ │ Inspector │
   │  (DETECTS)  │ │ (DETECTS) │ │ (DETECTS) │
   └──────┬──────┘ └─────┬─────┘ └────┬──────┘
          │              │             │
          └──────────────▼─────────────┘
                         │
              ┌──────────▼──────────┐
              │   Amazon Detective   │
              │   (INVESTIGATES)     │
              │                      │
              │  - Behavior graphs   │
              │  - Entity profiles   │
              │  - Timeline analysis │
              │  - Finding groups    │
              └─────────────────────┘
```

| Service | What It Does | Analogy |
|---------|-------------|---------|
| **GuardDuty** | Continuously monitors CloudTrail, VPC Flow Logs, DNS logs using ML to detect threats. Generates findings. | Smoke alarm — tells you there's a fire |
| **Amazon Detective** | Ingests 12+ months of CloudTrail, VPC Flow Logs, GuardDuty findings. Builds behavior graphs. Answers "what happened and what else was affected?" | Forensic investigator — tells you how the fire started, where it spread, and what was destroyed |
| **Security Hub** | Aggregates findings from GuardDuty, Macie, Inspector, Detective, and partner tools into one prioritized dashboard | Incident management system — organizes all alarms |

### What Amazon Detective Actually Does Under the Hood

Detective uses three analytical techniques simultaneously:

- **Machine Learning** — Establishes behavioural baselines per entity (IAM user, EC2 instance, IP address). Flags deviations.
- **Statistical Analysis** — Compares current activity to historical norms. "This IP made 400 API calls in the last hour vs. an average of 3."
- **Graph Theory** — Maps relationships between entities. "This IP also touched these 5 other EC2 instances and this S3 bucket."

Detective ingests data from:
- AWS CloudTrail management events
- Amazon VPC Flow Logs
- Amazon EKS audit logs
- GuardDuty findings
- AWS Security Hub findings
- Amazon Security Lake

It retains up to **12 months** of aggregated data — giving you a full year of behavioural baseline for every entity in your account.

---

## 3. Tools Used

| Tool | Purpose |
|------|---------|
| AWS Management Console | Primary interface for this lab — all investigation is GUI-based |
| Amazon GuardDuty Console | Starting point — view the initial finding that triggered the investigation |
| Amazon Detective Console | Core investigation tool — entity profiles, behavior graphs, finding groups |
| Detective — Entity Profile | Deep dive into IAM user/role or EC2 instance activity over time |
| Detective — Finding Groups | View all related findings grouped by security event |
| Detective — API Call Volume | Compare current API activity vs established baseline |
| Detective — Geolocations | Map source IPs and flag anomalous geographies |
| Detective — VPC Flow Logs | Inspect network traffic patterns for affected resources |
| Detective — Overall Summary | Account-level view of all findings and involved entities |

---

## 4. Investigation Path — Step by Step

### Step 1 — Start in GuardDuty: Examine the Initial Finding

Navigate to **Amazon GuardDuty** in the AWS Console.

In the **Findings** panel, a finding is present. Key details to note on every GuardDuty finding:

```
Finding Type:    UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS
Severity:        High
Account:         794929857501
Region:          us-east-1
IAM Entity:      arn:aws:iam::794929857501:role/HugeLogisticsAppRole
Source IP:       [External IP — not an AWS IP range]
Time:            [Timestamp of first occurrence]
```

**What this finding means:**  
EC2 instance credentials (from the instance metadata service — IMDS) were used to make API calls from **outside AWS infrastructure**. This is a strong indicator that an attacker stole the instance's IAM role credentials and is now using them from their own machine.

>  EC2 instance credentials should only ever be used from within the EC2 instance itself. If you see them used from an external IP, that is a near-certain indication of credential theft via SSRF or direct instance compromise.

**Pivot to Detective:**  
Click **"Investigate in Detective"** on the finding detail pane. Detective opens directly to a curated investigation view for this specific finding.

---

### Step 2 — Amazon Detective: GuardDuty Finding Overview

Detective immediately presents the **Finding Overview** page for the triggered alert.

Key panels visible:

**Finding details panel:**
- Finding type, severity, first/last seen timestamps
- The involved IAM role ARN
- The external source IP address

**Involved entities panel:**
Lists all entities connected to this finding:
- The IAM role (`HugeLogisticsAppRole`)
- The EC2 instance the role was assigned to
- The external IP address
- AWS services that were called

>  This is Detective's core power — it automatically surfaces all entities connected to a finding so you don't have to manually correlate CloudTrail logs. What would take hours of `grep` and `jq` is presented visually in seconds.

---

### Step 3 — Investigate the IAM Role Profile

Click on the **IAM Role entity** (`HugeLogisticsAppRole`) to open its entity profile.

**API Call Volume panel:**

This panel shows:
- Total API calls over the investigation time window
- A baseline line (Detective's ML-computed "normal" for this role)
- Current activity line

**Finding:** API call volume is massively elevated above the baseline. The role is calling services it has never called before — S3 `GetObject`, `ListBuckets`, IAM `ListUsers`, `GetPolicy`, and EC2 `DescribeInstances` — all hallmarks of attacker enumeration.

**New Geolocations panel:**

Detective shows a world map with the source IPs for all API calls made by this role.

**Finding:** The overwhelming majority of legitimate calls originate from the EC2 instance's IP (an AWS internal IP in `us-east-1`). A new source IP appears from an entirely different country — this is the external attacker using the stolen credentials.

>  "New Geolocations" in Detective is one of the most powerful quick-triage signals. A role or user that has always called APIs from `us-east-1` suddenly appearing from Eastern Europe or Southeast Asia is immediately suspicious.

**Observed With panel:**

Shows all EC2 instances and services this role has been observed interacting with — useful for mapping lateral movement.

---

### Step 4 — Investigate the Source IP Profile

Navigate back and click on the **external source IP** entity.

Detective's IP profile shows:

**Threat Intelligence panel:**
- Whether the IP appears in known threat intelligence feeds
- Associated domains (if any)
- Previous GuardDuty findings involving this IP

**Finding:** The IP is flagged in threat intelligence feeds — associated with known malicious infrastructure or Tor exit nodes.

**EC2 instances contacted panel:**
Shows every EC2 instance in the account that received connections from this IP — revealing the full scope of network activity from the attacker's machine.

**API calls issued panel:**
Every AWS API call made from this IP, in chronological order. This is the attacker's full activity log, reconstructed automatically by Detective.

---

### Step 5 — Examine Finding Groups

Navigate to **Detective → Finding Groups** in the left panel.

Finding Groups is Detective's most powerful feature for incident response. Rather than investigating one finding in isolation, Finding Groups uses graph analysis to cluster all related findings into a single security event.

**What the Finding Group shows:**

The group for this event contains multiple related findings:

```
Finding 1: UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS
           → Stolen instance credentials used from external IP

Finding 2: Discovery:S3/BucketEnumeration.Unusual
           → Unusual S3 bucket listing behaviour for this role

Finding 3: PrivilegeEscalation:IAMUser/AdministrativePermissions
           → Role attempted to access admin-level services

Finding 4: Impact:S3/ObjectRead.Unusual
           → Unusual volume of S3 object reads
```

>  If GuardDuty tells you *"there's a fire"*, Finding Groups tells you *"the fire started in the kitchen, spread to the living room, and here's every room it touched."* Without Finding Groups, a SOC analyst might investigate each finding in isolation and miss that they are all part of a single coordinated attack chain.

**The Finding Group visualization:**

Detective renders a visual graph showing:
- The attacker's IP at the center
- Lines connecting to every affected entity (the IAM role, EC2 instance, S3 buckets accessed)
- Timestamps on each connection
- GuardDuty finding severity icons on affected nodes

This graph **is** the attack timeline — visually reconstructed, automatically.

---

### Step 6 — Investigate the EC2 Instance Profile

Click on the **EC2 instance** entity that had the compromised role assigned.

**Key panels:**

**VPC Flow Logs panel:**
- Inbound/outbound network traffic for this instance over time
- Spikes in outbound traffic correlating with the breach timestamp
- Connections to unusual internal IPs (potential lateral movement indicator)

**GuardDuty findings panel:**
- All GuardDuty findings associated with this specific instance
- Historical finding count vs. current spike

**Container activity (if applicable):**
If the EC2 instance runs containers, Detective can drill into ECS/EKS-level activity.

---

### Step 7 — Triage Conclusion and Scope Assessment

After completing all entity profiles and reviewing the Finding Group, we can answer the four essential IR questions:

| Question | Answer |
|----------|--------|
| **True positive or false positive?** | TRUE POSITIVE — external IP confirmed malicious, credentials used outside AWS, anomalous API patterns |
| **How did it happen?** | EC2 instance role credentials were exfiltrated (likely via SSRF or direct instance compromise) and used externally |
| **What was accessed?** | S3 buckets enumerated and objects read; IAM permissions probed; EC2 instances described |
| **What is the blast radius?** | The `HugeLogisticsAppRole` and all resources it had access to — S3 buckets, IAM read permissions, EC2 describe access |

**Flag retrieved from the Detective investigation.** 

---

## 5. Root Cause Analysis

| # | Root Cause | Severity |
|---|-----------|---------|
| 1 | EC2 instance role credentials (`HugeLogisticsAppRole`) exfiltrated and used from an external IP — IMDS v1 (IMDSv1) likely enabled, allowing SSRF-based credential theft without authentication |   Critical |
| 2 | `HugeLogisticsAppRole` had overly broad permissions — attacker could enumerate S3, IAM, and EC2 from a single role |   Critical |
| 3 | No IMDSv2 enforced on the EC2 instance — IMDSv1 allows any process on the instance (and SSRF vulnerabilities) to fetch credentials without a token |   Critical |
| 4 | No CloudWatch alarm on `InstanceCredentialExfiltration` GuardDuty finding type — detection relied on manual review |   High |
| 5 | Role had no IP condition restricting API calls to AWS IP ranges only |   High |
| 6 | No VPC endpoint policies to restrict which services the role could reach from within the VPC |  Medium |
| 7 | Detective and GuardDuty enabled but no automated response (Lambda/EventBridge) to contain on finding |   Medium |

---

## 6. Remediation

### Immediate 

```bash
# 1. Revoke all active sessions for the compromised role
# Add an explicit Deny all policy to the role immediately
aws iam put-role-policy \
  --role-name HugeLogisticsAppRole \
  --policy-name EMERGENCY_DENY_ALL \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*"
    }]
  }'

# 2. Find the EC2 instance using this role and isolate it
aws ec2 describe-instances \
  --filters "Name=iam-instance-profile.arn,Values=arn:aws:iam::794929857501:instance-profile/HugeLogisticsAppRole" \
  --query "Reservations[*].Instances[*].InstanceId" --output text

# 3. Isolate the instance — move it to a quarantine security group
aws ec2 modify-instance-attribute \
  --instance-id i-0abc123... \
  --groups sg-quarantine-id  # security group with no inbound/outbound rules

# 4. Take a forensic snapshot of the instance EBS volume before terminating
aws ec2 create-snapshot \
  --volume-id vol-0abc123... \
  --description "FORENSIC-SNAPSHOT-$(date +%Y%m%d)" \
  --tag-specifications 'ResourceType=snapshot,Tags=[{Key=Purpose,Value=ForensicEvidence}]'

# 5. Block the attacker's external IP at the NACL level
aws ec2 create-network-acl-entry \
  --network-acl-id acl-0abc123 \
  --rule-number 1 \
  --protocol -1 \
  --rule-action deny \
  --cidr-block ATTACKER_IP/32 \
  --egress
```

### Short-Term (within 24 hours)

**Enforce IMDSv2 on ALL EC2 instances (prevents SSRF credential theft):**

```bash
# Enforce IMDSv2 on an existing instance
aws ec2 modify-instance-metadata-options \
  --instance-id i-0abc123... \
  --http-tokens required \
  --http-put-response-hop-limit 1

# Enforce IMDSv2 on all NEW instances via account-level setting
aws ec2 modify-instance-metadata-defaults \
  --http-tokens required \
  --http-put-response-hop-limit 1
```

>  IMDSv2 requires a session token to retrieve instance credentials. SSRF attacks cannot include the required PUT request to get the token, so they fail silently. This single change eliminates the most common EC2 credential theft vector.

**Add an IP condition to the role trust policy — restrict API calls to AWS IPs only:**

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "ec2.amazonaws.com"},
    "Action": "sts:AssumeRole",
    "Condition": {
      "IpAddress": {
        "aws:SourceIp": [
          "10.0.0.0/8",
          "172.16.0.0/12",
          "192.168.0.0/16"
        ]
      }
    }
  }]
}
```

**Scope down the role permissions using IAM Access Advisor:**

```bash
# Find what services this role actually uses
aws iam generate-service-last-accessed-details \
  --arn arn:aws:iam::794929857501:role/HugeLogisticsAppRole

aws iam get-service-last-accessed-details --job-id [job-id]
# Remove all permissions for services not accessed in the last 90 days
```

### Long-Term 

**Automated response — EventBridge + Lambda to auto-contain on critical GuardDuty findings:**

```json
// EventBridge rule: trigger Lambda when InstanceCredentialExfiltration finding fires
{
  "source": ["aws.guardduty"],
  "detail-type": ["GuardDuty Finding"],
  "detail": {
    "severity": [{"numeric": [">=", 7]}],
    "type": ["UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS"]
  }
}
```

```python
# Lambda function — auto-attach DenyAll to compromised role
import boto3

def lambda_handler(event, context):
    finding = event['detail']
    role_arn = finding['resource']['accessKeyDetails']['userArn']
    role_name = role_arn.split('/')[-1]

    iam = boto3.client('iam')
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName='AUTO_EMERGENCY_DENY',
        PolicyDocument='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}'
    )

    # Send SNS alert
    sns = boto3.client('sns')
    sns.publish(
        TopicArn='arn:aws:sns:us-east-1:794929857501:SecurityAlerts',
        Subject=f'CRITICAL: Role {role_name} auto-contained',
        Message=f'GuardDuty finding triggered auto-containment for role: {role_name}\nFinding: {finding["type"]}'
    )
```

**Enable Detective Finding Groups email digest for daily security review:**

```bash
# Detective doesn't have CLI alerting directly, but you can pull findings via API
aws detective list-graphs
aws detective list-members --graph-arn arn:aws:detective:us-east-1:794929857501:graph:abc123
```

---

## 7. Real-World Playbook — If This Happens at Your Company

> Your production IR guide for AWS credential exfiltration incidents.

### Detection Triggers (What Should Alert You)

| Signal | Source | Urgency |
|--------|--------|---------|
| GuardDuty: `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` | GuardDuty |   Immediate — auto-contain |
| Detective: New geolocation for IAM role/user in last 24h | Amazon Detective |   Immediate |
| Detective: API call volume 10x above baseline for any entity | Amazon Detective |   Immediate |
| Detective: IP flagged in threat intelligence feeds accessing your account | Amazon Detective |   Immediate |
| GuardDuty: `Recon:IAMUser/UserPermissions` — credential enumeration | GuardDuty |   High |
| GuardDuty: `Discovery:S3/BucketEnumeration.Unusual` | GuardDuty |   High |
| EC2 IMDS endpoint receiving unusual volume of GET requests | CloudWatch |   High |

### Incident Response Steps 

```
1. TRIAGE    → Open GuardDuty finding, pivot to Detective, confirm true vs false positive
               Key question: Is the source IP inside AWS IP ranges? If no → true positive

2. CONTAIN   → Immediately attach DenyAll policy to compromised role
               Isolate the EC2 instance into a quarantine security group

3. PRESERVE  → Snapshot the EC2 EBS volume for forensics BEFORE terminating
               Export all Detective findings and CloudTrail logs to S3 with Object Lock

4. SCOPE     → Use Detective Finding Groups to identify ALL related activity
               Answer: What services were accessed? What data was touched? Other instances compromised?

5. HUNT      → Use Detective entity profiles to check if the attacker IP touched
               any OTHER roles, users, or resources in your account

6. NOTIFY    → Security team, engineering leads, legal if PII/regulated data was accessed

7. ERADICATE → Terminate compromised instance, create clean replacement
               Rotate all credentials that were accessible to the compromised role

8. HARDEN    → Enforce IMDSv2, scope down role permissions, add IP conditions to trust policies
               Set up EventBridge + Lambda for automated containment

9. REVIEW    → Post-incident report, 5 whys analysis, update runbooks
               Conduct IMDS exposure audit across all EC2 instances
```

### Key AWS CLI Commands for Real IR

```bash
# Get ALL GuardDuty findings in the last 24 hours above severity 7
aws guardduty list-findings \
  --detector-id $(aws guardduty list-detectors --query 'DetectorIds[0]' --output text) \
  --finding-criteria '{"Criterion":{"severity":{"Gte":7},"updatedAt":{"Gte":"24h"}}}' 

# Describe a specific GuardDuty finding in detail
aws guardduty get-findings \
  --detector-id [detector-id] \
  --finding-ids [finding-id]

# Check IMDSv2 status on ALL EC2 instances
aws ec2 describe-instances \
  --query "Reservations[*].Instances[*].{ID:InstanceId,IMDSv2:MetadataOptions.HttpTokens}" \
  --output table
# Any instance showing "optional" instead of "required" is vulnerable

# Find all EC2 instances with instance profiles (roles assigned)
aws ec2 describe-instances \
  --query "Reservations[*].Instances[*].{ID:InstanceId,Role:IamInstanceProfile.Arn}" \
  --output table | grep -v None

# List all Detective behavior graphs in your account
aws detective list-graphs

# Start a Detective investigation on a specific IAM entity
aws detective start-investigation \
  --graph-arn arn:aws:detective:us-east-1:794929857501:graph:abc123 \
  --entity-arn arn:aws:iam::794929857501:role/HugeLogisticsAppRole \
  --scope-start-time "2026-04-01T00:00:00Z" \
  --scope-end-time "2026-04-30T23:59:59Z"

# Check if automated containment Lambda exists
aws lambda list-functions \
  --query "Functions[?contains(FunctionName,'guardduty') || contains(FunctionName,'contain')].FunctionName"
```

---

## 8. Real-World Breach Connection

**Capital One (2019):** The breach started when an attacker exploited an SSRF vulnerability in a web application running on an EC2 instance. The SSRF allowed the attacker to query the EC2 metadata service (IMDS) and steal the IAM role credentials attached to the instance — exactly the scenario this lab simulates. If IMDSv2 had been enforced (it didn't exist at the time, but was later released specifically because of incidents like this), the attack would have failed at this step.

**SCARLETEEL (2023):** A real threat actor group documented by Sysdig, targeting AWS environments. Their technique involved compromising containers running on EC2, stealing instance role credentials via IMDS, and then using those credentials externally to enumerate and exfiltrate data from S3 buckets. GuardDuty's `InstanceCredentialExfiltration.OutsideAWS` finding type was created directly in response to this attack pattern.

**The IMDS Problem at Scale:** AWS research has shown that a significant percentage of EC2 instances in production environments still run with IMDSv1 enabled — meaning SSRF-to-credential-theft is a viable attack against a large portion of AWS infrastructure. The fix (IMDSv2) is one CLI command per instance, yet it remains one of the most common unpatched misconfigurations security teams find during cloud assessments.

>  **MITRE ATT&CK Mapping:**
> - T1552.005 — Unsecured Credentials: Cloud Instance Metadata API
> - T1078.004 — Valid Accounts: Cloud Accounts
> - T1530 — Data from Cloud Storage
> - T1087.004 — Account Discovery: Cloud Account
> - T1046 — Network Service Discovery

---

## 9. Key Takeaways

| # | Lesson | Apply Where |
|---|--------|------------|
| 1 | GuardDuty detects threats. Detective investigates them. They are complementary — you need both | Every AWS security architecture |
| 2 | `InstanceCredentialExfiltration.OutsideAWS` = near-certain true positive. Auto-contain, don't wait | GuardDuty alert triage |
| 3 | Detective Finding Groups is the first place to go in any investigation — it shows the full story, not just one chapter | Incident response workflow |
| 4 | "New Geolocation" in Detective entity profiles is one of the fastest ways to confirm credential compromise | Triage phase |
| 5 | API call volume vs. baseline in Detective instantly separates human-speed anomalies from automated attacker enumeration | Behavioral analysis |
| 6 | IMDSv2 enforcement is the single highest-impact, lowest-effort EC2 hardening action available | EC2 security baseline |
| 7 | EC2 instance roles should have IP conditions in their trust policies — credentials used outside AWS IP ranges should be denied | IAM hardening |
| 8 | Automated response (EventBridge + Lambda) to critical GuardDuty findings reduces mean time to contain from hours to seconds | Detection engineering |
| 9 | Detective retains 12 months of behavioral data — even if an attacker was quiet for weeks before acting, Detective can show the full context | Threat hunting |
| 10 | Every entity in your AWS account has a Detective profile. Investigate the IP, the role, the instance, AND their relationships — not just one | Scoping methodology |

---

## 10. References

- [Amazon Detective Official Documentation](https://docs.aws.amazon.com/detective/latest/userguide/what-is-detective.html)
- [Amazon Detective Features Page](https://aws.amazon.com/detective/features/)
- [Amazon Detective Best Practices Guide](https://aws.github.io/aws-security-services-best-practices/guides/detective/)
- [AWS GuardDuty — InstanceCredentialExfiltration Finding](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html)
- [Enforcing IMDSv2 on EC2 Instances](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html)
- [SCARLETEEL Attack Campaign — Sysdig Research](https://sysdig.com/blog/scarleteel-operation-leveraging-terraform-kubernetes-and-aws-for-data-theft/)
- [Capital One Breach — AWS SSRF and IMDS Abuse](https://krebsonsecurity.com/2019/07/capital-one-data-theft-impacts-106m-people/)
- [AWS Blog — Using Detective API for GuardDuty Investigation](https://aws.amazon.com/blogs/security/how-to-use-the-amazon-detective-api-to-investigate-guardduty-security-findings-and-enrich-data-in-security-hub/)
- [MITRE ATT&CK — Cloud Instance Metadata API (T1552.005)](https://attack.mitre.org/techniques/T1552/005/)
- [PwnedLabs — Investigate Threats with Amazon Detective](https://pwnedlabs.io/labs/investigate-threats-with-amazon-detective)

---

