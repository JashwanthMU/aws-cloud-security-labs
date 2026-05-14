# Identify IAM Breaches with CloudTrail and Athena

> **Platform:** PwnedLabs  
> **Difficulty:** Beginner
> **Category:** AWS Cloud Security / Threat Detection  
> **Tags:** `CloudTrail` `Athena` `IAM` `S3` `Threat Hunting` `Log Analysis`

---

## 1. Scenario

A fictional company's AWS environment has been flagged for suspicious activity. You are handed a CloudTrail S3 bucket containing months of API call logs, and your goal is to act as a cloud threat hunter. Using Amazon Athena you will query the raw JSON logs at scale, identify the compromised IAM principal, reconstruct the attacker's actions, and determine what data—if any—was accessed or exfiltrated.

This lab simulates a real-world incident response scenario where a SOC analyst or cloud security engineer must pivot from an alert to evidence using only native AWS tooling.

---

## 2. Core Concept

### What is AWS CloudTrail?

AWS CloudTrail records every API call made in your AWS account—who made it, from where, when, and what resource was targeted. Logs are delivered as gzip-compressed JSON files to an S3 bucket, partitioned by account, region, and date:

```
s3://<bucket>/AWSLogs/<account-id>/CloudTrail/<region>/<year>/<month>/<day>/
```

Each log record contains fields like:

| Field | Description |
|---|---|
| `eventTime` | UTC timestamp of the API call |
| `eventName` | The API action (e.g., `ListBuckets`, `AssumeRole`) |
| `userIdentity` | Who made the call (IAM user, role, service) |
| `sourceIPAddress` | Caller's IP |
| `requestParameters` | Input to the API call |
| `responseElements` | What the API returned |
| `errorCode` | Set if the call failed (e.g., `AccessDenied`) |

### What is Amazon Athena?

Amazon Athena is a serverless SQL query engine that runs directly against data stored in S3. You define a table schema (using Apache Hive DDL) pointing at your CloudTrail S3 prefix, and Athena parses the nested JSON on the fly. This lets you query billions of log records without moving data or spinning up a database—paying only for the data scanned.

### Why CloudTrail + Athena for IAM Breach Hunting?

- **Scale:** CloudTrail logs grow to GB/TB fast. Athena handles it without ETL pipelines.
- **Speed:** Filter by time, principal, event type, or IP in seconds.
- **Forensic depth:** Every `AssumeRole`, `GetSecretValue`, `CreateAccessKey`, and `PutObject` is recorded.
- **Cost-effective:** Partition pruning reduces scan cost dramatically.

---

## 3. Tools Used

| Tool | Purpose |
|---|---|
| AWS Console / CLI | Navigation and initial access |
| Amazon S3 | Stores CloudTrail log files |
| Amazon Athena | SQL querying over raw log files |
| AWS Glue Data Catalog | Stores the table schema Athena references |
| CloudTrail | Source of all API audit records |
| jq (optional) | Local JSON parsing for spot-checks |

---

## 4. Attack-Path Step-by-Step

### Step 1 — Locate the CloudTrail Bucket

Navigate to **CloudTrail → Event History** in the AWS console. Note the S3 bucket name under *Storage location*. Alternatively, from the CLI:

```bash
aws cloudtrail describe-trails --query 'trailList[*].S3BucketName'
```

Example output:
```
["flaws2-cloudtrail-logs-653711331788"]
```

Confirm the structure is present:

```bash
aws s3 ls s3://flaws2-cloudtrail-logs-653711331788/AWSLogs/653711331788/CloudTrail/ --recursive | head -20
```

---

### Step 2 — Create the Athena Table (CloudTrail Schema)

Open **Amazon Athena**, select or create a database (e.g., `security_labs`), and run the following DDL to create a table pointing at the CloudTrail logs. This is the standard AWS-provided schema for CloudTrail JSON:

```sql
CREATE EXTERNAL TABLE security_labs.cloudtrail_logs (
    eventVersion        STRING,
    userIdentity        STRUCT<
                            type:             STRING,
                            principalId:      STRING,
                            arn:              STRING,
                            accountId:        STRING,
                            invokedBy:        STRING,
                            accessKeyId:      STRING,
                            userName:         STRING,
                            sessionContext:   STRUCT<
                                                  attributes: STRUCT<
                                                                  mfaAuthenticated: STRING,
                                                                  creationDate:     STRING>,
                                                  sessionIssuer: STRUCT<
                                                                     type:        STRING,
                                                                     principalId: STRING,
                                                                     arn:         STRING,
                                                                     accountId:   STRING,
                                                                     userName:    STRING>>>,
    eventTime           STRING,
    eventSource         STRING,
    eventName           STRING,
    awsRegion           STRING,
    sourceIPAddress     STRING,
    userAgent           STRING,
    errorCode           STRING,
    errorMessage        STRING,
    requestParameters   STRING,
    responseElements    STRING,
    additionalEventData STRING,
    requestId           STRING,
    eventId             STRING,
    resources           ARRAY<STRUCT<arn:STRING,accountId:STRING,type:STRING>>,
    eventType           STRING,
    apiVersion          STRING,
    readOnly            STRING,
    recipientAccountId  STRING,
    serviceEventDetails STRING,
    sharedEventID       STRING,
    vpcEndpointId       STRING
)
ROW FORMAT SERDE 'com.amazon.emr.hive.serde.CloudTrailSerde'
STORED AS INPUTFORMAT 'com.amazon.emr.cloudtrail.CloudTrailInputFormat'
OUTPUTFORMAT 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat'
LOCATION 's3://flaws2-cloudtrail-logs-653711331788/AWSLogs/653711331788/CloudTrail/';
```

> **Tip:** Replace the `LOCATION` with your actual bucket path. If logs span multiple regions, point to the parent prefix and use partition projection.

Verify with:
```sql
SELECT COUNT(*) FROM security_labs.cloudtrail_logs;
```

---

### Step 3 — Identify Active IAM Principals

Get a bird's-eye view of every IAM principal that made API calls:

```sql
SELECT
    userIdentity.userName,
    userIdentity.type,
    userIdentity.arn,
    COUNT(*) AS event_count
FROM security_labs.cloudtrail_logs
GROUP BY
    userIdentity.userName,
    userIdentity.type,
    userIdentity.arn
ORDER BY event_count DESC;
```

Sample output:

| userName | type | arn | event_count |
|---|---|---|---|
| level3 | IAMUser | arn:aws:iam::653711331788:user/level3 | 847 |
| backup-service | IAMUser | arn:aws:iam::653711331788:user/backup-service | 213 |
| AssumedRole | AssumedRole | arn:aws:sts::653711331788:assumed-role/... | 54 |

Flag any principals you don't recognize or that appear disproportionately active.

---

### Step 4 — Hunt for Access Key Creation (Persistence)

Attackers commonly create new access keys on a compromised account to maintain persistence after the initial vector is closed. Query:

```sql
SELECT
    eventTime,
    userIdentity.userName  AS actor,
    requestParameters,
    responseElements,
    sourceIPAddress
FROM security_labs.cloudtrail_logs
WHERE eventName = 'CreateAccessKey'
ORDER BY eventTime;
```

If you see `CreateAccessKey` for an account that already has active keys, or a key being created by an unfamiliar actor, that is a strong indicator of compromise.

---

### Step 5 — Find Reconnaissance Activity

Attackers enumerate resources after gaining access. Common enumeration events:

```sql
SELECT
    eventTime,
    userIdentity.userName,
    eventName,
    sourceIPAddress,
    errorCode
FROM security_labs.cloudtrail_logs
WHERE eventName IN (
    'ListBuckets',
    'ListObjects',
    'GetBucketAcl',
    'GetBucketPolicy',
    'ListUsers',
    'ListRoles',
    'ListAttachedUserPolicies',
    'GetAccountSummary',
    'DescribeInstances',
    'ListSecrets'
)
ORDER BY eventTime;
```

A burst of read-only IAM/S3/EC2 API calls from a single principal in a short window is classic recon behaviour.

---

### Step 6 — Identify Privilege Escalation Attempts

Check for attempts to attach policies or assume higher-privileged roles:

```sql
SELECT
    eventTime,
    userIdentity.userName,
    eventName,
    requestParameters,
    errorCode,
    sourceIPAddress
FROM security_labs.cloudtrail_logs
WHERE eventName IN (
    'AttachUserPolicy',
    'AttachRolePolicy',
    'PutUserPolicy',
    'CreateRole',
    'AssumeRole',
    'UpdateAssumeRolePolicy',
    'PassRole'
)
ORDER BY eventTime;
```

Pay close attention to `errorCode IS NULL` rows — those succeeded. `AccessDenied` errors indicate failed escalation attempts, but still reveal attacker intent.

---

### Step 7 — Trace the Compromised Principal's Full Timeline

Once you identify the suspect principal (e.g., `level3`), reconstruct their complete API timeline:

```sql
SELECT
    eventTime,
    eventName,
    eventSource,
    sourceIPAddress,
    userAgent,
    errorCode,
    requestParameters
FROM security_labs.cloudtrail_logs
WHERE userIdentity.userName = 'level3'
ORDER BY eventTime;
```

Walk through the timeline chronologically:

1. What was the **first** API call? → Indicates when compromise began.
2. Did the IP address **change** mid-session? → Possible credential sharing or proxy pivot.
3. Were there any **data access** events (`GetObject`, `GetSecretValue`)? → Exfiltration evidence.

---

### Step 8 — Detect Data Exfiltration via S3

```sql
SELECT
    eventTime,
    userIdentity.userName,
    requestParameters,
    sourceIPAddress
FROM security_labs.cloudtrail_logs
WHERE eventName = 'GetObject'
  AND userIdentity.userName = 'level3'
ORDER BY eventTime;
```

If `GetObject` appears on a bucket the user should not normally access, cross-reference `requestParameters` to extract the object key — this tells you exactly what files were downloaded.

---

### Step 9 — Check for CloudTrail Tampering

Sophisticated attackers attempt to blind defenders by disabling logging:

```sql
SELECT
    eventTime,
    userIdentity.userName,
    eventName,
    requestParameters,
    sourceIPAddress
FROM security_labs.cloudtrail_logs
WHERE eventName IN (
    'StopLogging',
    'DeleteTrail',
    'PutEventSelectors',
    'UpdateTrail'
)
ORDER BY eventTime;
```

Any hit here is a critical severity finding—it indicates the attacker was aware of CloudTrail and attempted to cover their tracks.

---

### Step 10 — Summarise the Breach Timeline

Compile your findings into a structured timeline. Example:

| Time (UTC) | Event | Principal | Source IP | Significance |
|---|---|---|---|---|
| 2024-01-15 02:13:47 | `GetCallerIdentity` | level3 | 45.33.32.156 | Attacker confirmed identity |
| 2024-01-15 02:14:02 | `ListBuckets` | level3 | 45.33.32.156 | S3 recon begins |
| 2024-01-15 02:15:18 | `GetObject` (secret-data.txt) | level3 | 45.33.32.156 | Data exfiltrated |
| 2024-01-15 02:16:55 | `CreateAccessKey` | level3 | 45.33.32.156 | Persistence established |
| 2024-01-15 02:18:01 | `AssumeRole` (admin-role) | level3 | 45.33.32.156 | Privilege escalation |

---

## 5. Blue Team — How to Detect This Attack

### Detection Signals (CloudWatch / GuardDuty)

| Signal | GuardDuty Finding | Severity |
|---|---|---|
| API calls from unusual IP / Tor exit node | `UnauthorizedAccess:IAMUser/TorIPCaller` | High |
| Credential used from new geography | `UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B` | Medium |
| Large volume of `GetObject` calls | `Exfiltration:S3/AnomalousBehavior` | High |
| `CreateAccessKey` on own account | `Persistence:IAMUser/AnomalousBehavior` | High |
| `StopLogging` or `DeleteTrail` | `Stealth:IAMUser/CloudTrailLoggingDisabled` | Critical |

### CloudWatch Metric Filters to Set Up

Create metric filters on your CloudTrail CloudWatch log group:

```json
// Alert on IAM changes
{ ($.eventName = CreateAccessKey) ||
  ($.eventName = AttachUserPolicy) ||
  ($.eventName = PutUserPolicy) }

// Alert on CloudTrail tampering
{ ($.eventName = StopLogging) ||
  ($.eventName = DeleteTrail) }

// Alert on console login failures
{ ($.eventName = ConsoleLogin) &&
  ($.errorMessage = "Failed authentication") }
```

---

## 6. Root Cause Analysis

In a typical lab scenario matching this exercise, the root cause chain is:

1. **Leaked credentials** — The IAM access key for `level3` (or equivalent) was exposed, typically via a public GitHub commit, a misconfigured EC2 instance metadata endpoint, or a hard-coded secret in application code.

2. **No MFA enforcement** — The compromised IAM user was able to authenticate with just the access key and secret, with no second factor required.

3. **Overly permissive policy** — The user had read access to sensitive S3 buckets and `iam:CreateAccessKey` rights on their own account, neither of which was required for their job function. This violates least-privilege.

4. **No alerting** — No GuardDuty findings were being acted on, and no CloudWatch alarms were configured for IAM key creation or privilege escalation events.

---

## 7. Remediation

### Immediate (Incident Response)

```bash
# Disable the compromised access key immediately
aws iam update-access-key \
    --user-name level3 \
    --access-key-id AKIAIOSFODNN7EXAMPLE \
    --status Inactive

# Rotate to a new key and delete the compromised one
aws iam delete-access-key \
    --user-name level3 \
    --access-key-id AKIAIOSFODNN7EXAMPLE

# Revoke any active sessions for the user
aws iam delete-login-profile --user-name level3
```

### Short-Term Hardening

- **Enable GuardDuty** in every region — it alerts on compromised credentials in near real-time.
- **Enforce MFA** for all IAM users using an SCP or IAM policy condition:
  ```json
  {
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
          "BoolIfExists": { "aws:MultiFactorAuthPresent": "false" }
      }
  }
  ```
- **Apply least privilege** — audit all users with `iam:CreateAccessKey` on `Resource: "*"` and scope it down.
- **Enable CloudTrail log file validation** to detect tampered logs:
  ```bash
  aws cloudtrail update-trail --name main-trail --enable-log-file-validation
  ```

### Long-Term Controls

- Use **IAM Identity Center (SSO)** with short-lived role credentials instead of long-lived IAM user access keys.
- Set up **AWS Config rules**: `iam-user-mfa-enabled`, `access-keys-rotated`, `cloudtrail-enabled`.
- Use **S3 Access Analyzer** to detect bucket policies granting unintended public or cross-account access.
- Store secrets in **AWS Secrets Manager** instead of passing them as environment variables or committing to source control.
- Tag all IAM principals with owner/team and automate key rotation policies.

---

## 8. Real-World Playbook — If This Happens at Your Company

```
T+0 min   Alert fires (GuardDuty / SIEM / user report)
T+5 min   Disable the compromised access key via CLI
T+10 min  Open Athena, run Step 7 query to scope the full timeline
T+20 min  Identify all resources accessed; note S3 GetObject events
T+30 min  Check for CreateAccessKey / AssumeRole — attacker persistence?
T+40 min  Check CloudTrail for StopLogging / DeleteTrail attempts
T+60 min  Brief security leadership with: who, what, when, from where
T+90 min  Notify data owners of any accessed sensitive objects
T+2 hrs   Patch root cause (revoke keys, fix secret exposure, tighten policy)
T+24 hrs  Post-incident review; update runbooks and detection rules
```

Key questions to answer during IR:
- Was the access key leaked externally (GitHub, S3, application logs)?
- Did the attacker escalate privileges or move laterally?
- Was any PII, financial data, or IP downloaded?
- Was the CloudTrail log integrity maintained (validate with `aws cloudtrail validate-logs`)?

---

## 10. Key Takeaways

- **CloudTrail is your forensic foundation** — every API call is logged; the question is whether you're querying it.
- **Athena eliminates the need for SIEM ingestion** to query CloudTrail at scale; a SQL query can surface a breach timeline in under a minute.
- **Look for four attacker stages in logs:** Recon (List* events) → Access (GetObject/GetSecretValue) → Persistence (CreateAccessKey) → Escalation (AssumeRole/AttachPolicy).
- **IAM least privilege is the most impactful preventive control** — if the compromised user couldn't `CreateAccessKey` or access sensitive buckets, the blast radius shrinks dramatically.
- **GuardDuty + CloudWatch Alarms** convert reactive forensics into proactive detection.
- **Log file validation** (`--enable-log-file-validation`) ensures you can trust your CloudTrail evidence during forensics.
- **Long-lived access keys are a liability** — prefer IAM Identity Center roles with short session durations.

---

## 11. References

- [AWS CloudTrail User Guide](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html)
- [Querying CloudTrail Logs with Athena](https://docs.aws.amazon.com/athena/latest/ug/cloudtrail-logs.html)
- [Amazon Athena – Getting Started](https://docs.aws.amazon.com/athena/latest/ug/getting-started.html)
- [AWS GuardDuty Finding Types – IAM](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html)
- [IAM Security Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [Capital One Breach Analysis – US Senate Report](https://www.hsgac.senate.gov/imo/media/doc/2022-08-03%20PSI%20Staff%20Report%20-%20Capital%20One.pdf)
- [PwnedLabs – Identify IAM Breaches with CloudTrail and Athena](https://pwnedlabs.io)
- [AWS Security Incident Response Guide](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html)
- [CloudTrail Log File Integrity Validation](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html)

---
