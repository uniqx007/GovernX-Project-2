# GovernX: Cloud Integration & Data Pipeline (Week 1)

This repository contains the foundational **Backend & Cloud Integration Pipeline** for the GovernX NIST CSF 2.0 Compliance Engine. It is responsible for continuously polling cloud environments, extracting security configurations, normalizing the data, and serving it via a REST API to the rest of the application.

## Architecture & Modules

The pipeline is composed of four core modules working in tandem:

### 1. `aws_connector.py` (The Extraction Engine)
Actively polls and audits cloud infrastructure to detect misconfigurations and security vulnerabilities across AWS services (EC2, S3, RDS, IAM, VPC).
* **Mock Integration:** Seamlessly integrated with `Moto` to automatically spin up a localized mock AWS environment containing intentionally vulnerable resources for safe, cost-free testing. (As issue with real data integration was coming)

### 2. `cloud_poller.py` (The Orchestrator)
A multi-cloud, multi-region orchestrator that manages the execution of cloud connectors.
* Handles caching mechanisms, retry logic, and concurrent polling cycles.
* Designed to easily scale to support Azure and GCP in future sprints.

### 3. `data_normalizer.py` (The Transformer)
Takes the raw, service-specific output from the cloud connectors and standardizes it into a universal JSON format.
* Performs data quality validation, normalizes severity levels, and outputs clean structured data (`normalized_findings.json` & `normalized_resources.json`) ready to be mapped to the NIST CSF 2.0 framework.

### 4. `api_endpoints.py` (The API Gateway)
A modern, asynchronous FastAPI application that exposes the backend capabilities to the Frontend and Data Engineering teams.
* Triggers on-demand background audits via `POST /api/v1/audit/start`.
* Serves the normalized findings and statistics via REST endpoints.

---

## 🚀 Getting Started

### Prerequisites
Make sure you have the required dependencies installed:
```bash
  pip install -r requirements.txt
```

### 1. Running the Pipeline Manually
You can test the entire pipeline end-to-end directly from your terminal:

**Run the Poller & Connector:**
```bash
  python cloud_poller.py
```
*This will execute the mock Moto AWS environment, detect vulnerabilities, and cache the raw results.*

**Run the Normalizer:**
```bash
  python data_normalizer.py
```
*This will ingest the raw audit and export beautifully normalized JSON data.*

### 2. Running the API Server
To expose the pipeline to the rest of the GovernX ecosystem, start the API server:
```bash
  python api_endpoints.py
```
Once the server says `GovernX API started`, open your web browser and navigate to the interactive testing interface:
👉 **[http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)**

From this Swagger UI, you can manually trigger audits and query findings.


---