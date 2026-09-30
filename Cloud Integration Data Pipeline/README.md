# GovernX: Cloud Integration & Data Pipeline
## 🚀 Overview

The `AWSConnector` is designed to actively poll and audit cloud infrastructure to detect misconfigurations and security vulnerabilities. It currently supports extracting configurations from the following AWS services:
- **EC2:** Detects unencrypted EBS volumes, disabled monitoring, and outdated IMDSv1 instances.
- **S3:** Detects publicly accessible buckets and unencrypted storage.
- **RDS:** Detects publicly accessible databases, missing Multi-AZ configurations, and unencrypted instances.
- **IAM:** Audits user access keys and MFA enforcement.
- **VPC / Security Groups:** Audits ingress/egress rules for potentially dangerous open ports (e.g., world-open databases).

## 🛠️ Testing via Native Moto Integration

To facilitate testing without requiring actual AWS credentials or incurring cloud costs, the `AWSConnector` has been built with native [Moto](https://github.com/getmoto/moto) mock support.

When initialized, the connector will seamlessly instantiate a local, in-memory AWS environment, generate intentionally vulnerable mock resources, and execute real `boto3` queries against them.

### Prerequisites

```bash
pip install boto3 moto
```

### Running the Audit

Simply execute the script to start the mock server, seed the resources, and run the full security audit:

```bash
python aws_connector.py
```

### Output

The audit will complete in seconds and output its findings directly to the console, while also exporting a comprehensive structured JSON report to `aws_audit.json`.

```text
INFO:botocore.credentials:Found credentials in environment variables.
INFO:__main__:AWS connector initialized for region: us-east-1 (MOTO ENABLED)
INFO:__main__:======================================================================
INFO:__main__:RUNNING FULL AWS SECURITY AUDIT (MOCK BOTO3 ENGINE)
INFO:__main__:======================================================================
INFO:__main__:🔍 Auditing EC2 instances...
INFO:__main__:✅ EC2 audit complete. Found 3 issues.
INFO:__main__:🔍 Auditing S3 buckets...
...
INFO:__main__:Total Findings: 9
INFO:__main__:Total Resources Scanned: 4
```