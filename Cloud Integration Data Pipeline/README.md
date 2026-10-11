# GovernX: Cloud Integration & Data Pipeline (Week 1 & 2)

This folder contains the foundational **Backend & Cloud Integration Pipeline** for the GovernX Compliance Engine. It is responsible for continuously polling cloud environments, extracting security configurations, normalizing the data, validating compliance, aggregating findings, and serving it via a REST API to the rest of the application.

## Architecture & Modules

The pipeline is composed of core modules working in tandem:

### 1. `aws_connector.py` (The Extraction Engine)
Actively polls and audits cloud infrastructure to detect misconfigurations and security vulnerabilities across AWS services (EC2, S3, RDS, IAM, VPC).
* **Mock Integration:** Seamlessly integrated with `Moto` to automatically spin up a localized mock AWS environment containing intentionally vulnerable resources for safe, cost-free testing. (As issue with real data integration was coming)

### 2. `cloud_poller.py` (The Orchestrator)
A multi-cloud, multi-region orchestrator that manages the execution of cloud connectors.
* Handles caching mechanisms, retry logic, and concurrent polling cycles.

### 3. `data_normalizer.py` (The Transformer)
Takes the raw, service-specific output from the cloud connectors and standardizes it into a universal JSON format.
* Performs data quality validation, normalizes severity levels, and outputs clean structured data (`normalized_findings.json` & `normalized_resources.json`).

### 4. `aws_compliance_checks.py` (The NIST Validator)
A library containing 20+ automated compliance checks (EC2, S3, RDS, IAM, VPC) directly mapped to NIST CSF 2.0 controls.
* Takes normalized data and validates it against security frameworks, producing pass/fail compliance scores.

### 5. `finding_aggregator.py` (The Deduplicator)
Aggregates and deduplicates findings from multiple clouds and audit runs.
* Solves the issue of duplicate findings polluting the dashboard by merging duplicate resources and generating intelligent compliance statistics.

### 6. `api_endpoints_week2.py` (The API Gateway v2)
A modern, asynchronous FastAPI application that exposes the backend capabilities.
* Triggers on-demand background audits and compliance validations via `POST /api/v2/audit/{audit_id}/run-compliance-checks`.
* Serves the aggregated findings and statistics via REST endpoints.

---

## 🚀 Getting Started

### Prerequisites
Make sure you have the required dependencies installed:
```bash
  pip install -r requirements.txt
```

### 1. Running the Core Pipeline Manually
You can test the extraction and normalizer directly from your terminal:
```bash
  python cloud_poller.py
  python data_normalizer.py
```

### 2. Running the Compliance & Aggregation Engine (Week 2)
Test the deduplication and NIST compliance validations:
```bash
  python aws_compliance_checks.py
  python finding_aggregator.py
```

### 3. Running the API Server (Week 2)
To expose the pipeline to the rest of the GovernX ecosystem, start the upgraded v2 API server:
```bash
  python api_endpoints_week2.py
```
Once the server shows `GovernX API started`, open the web browser and navigate to the interactive testing interface:
**[http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)**

From this Swagger UI, you can manually trigger compliance audits, get aggregated duplicates, and query findings.

---