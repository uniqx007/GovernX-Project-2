# GovernX: Cloud Integration & Governance Pipeline (Weeks 1 - 4)

This repository contains the complete **Backend, Cloud Integration & Governance Data Pipeline** for the GovernX NIST CSF 2.0 Compliance Engine (Person 1: Backend Lead). 

It continuously polls cloud environments, extracts security configurations, normalizes data, validates compliance against 24 NIST CSF controls, deduplicates findings, tracks supply chain risk, enforces organizational policies, and exposes a hardened REST API via a unified production application.

---

## Architecture & Complete Module Roadmap

### 📦 Week 1: Foundation & Data Acquisition
* **[`aws_connector.py`](aws_connector.py)**: Cloud infrastructure scanner across EC2, S3, RDS, IAM, and VPC. Built-in Moto emulation seeds an isolated AWS environment with realistic misconfigurations.
* **[`cloud_poller.py`](cloud_poller.py)**: Multi-region orchestrator managing polling schedules, exponential retry backoff, and local TTL caching (`./.cache/`).
* **[`data_normalizer.py`](data_normalizer.py)**: Converts vendor-specific raw outputs into universal GovernX dataclasses (`ResourceType`, `ServiceType`, `Severity`).
* **[`api_endpoints.py`](api_endpoints.py)**: Initial REST API v1 (`/api/v1/...`).

### 🛡️ Week 2: Compliance & Finding Deduplication
* **[`aws_compliance_checks.py`](aws_compliance_checks.py)**: 24 automated compliance check rules mapped to NIST CSF categories (EBS encryption, IMDSv2, S3 Public Access, RDS KMS, IAM MFA, etc.).
* **[`finding_aggregator.py`](finding_aggregator.py)**: MD5-hash deduplicator (`resource_id + finding_type + service`) tracking `first_seen`, `last_seen`, and occurrence counts.
* **[`api_endpoints_week2.py`](api_endpoints_week2.py)**: Extended REST API v2 (`/api/v2/...`).

### 🏛️ Week 3: NIST CSF 2.0 Govern Function (GV)
* **[`supply_chain_connector.py`](supply_chain_connector.py)**: Third-party vendor risk assessment, security certification tracking (SOC2 / ISO27001), concentration risk analysis, and weighted scoring (`GV.SC`).
* **[`organizational_policy_engine.py`](organizational_policy_engine.py)**: Enterprise policy parser and violation evaluator cross-referencing cloud findings against corporate security mandates (`GV.PO`).
* **[`governance_data_collector.py`](governance_data_collector.py)**: Board oversight scorecard, cyber insurance parameters, strategic initiatives, and risk appetite breach detection (`GV.OC`, `GV.OV`, `GV.RM`).
* **[`stakeholder_registry.py`](stakeholder_registry.py)**: Risk ownership assignment per cloud domain, SLA escalation matrix, and alert routing (`GV.RR`).

### 🚀 Week 4: Production Hardening & Optimization
* **[`api_optimization.py`](api_optimization.py)**: Thread-safe in-memory TTL Cache, sliding-window rate limiting, and structured pagination.
* **[`security_hardening.py`](security_hardening.py)**: Zero-trust API Key and JWT authentication, Role-Based Access Control (RBAC), security audit logging, and data masking.
* **[`error_handling.py`](error_handling.py)**: Domain exception hierarchy, standardized error response envelopes, and `/health/live` & `/health/ready` probes.
* **[`deployment_config.py`](deployment_config.py)**: Production settings management, CORS configurations, and secrets handling.
* **[`governx_app.py`](governx_app.py)**: **The Master Production Application** uniting Weeks 1 - 4 into a single, cohesive, fully functioning FastAPI service.

---

## ⚡ Quickstart Guide

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run the Unified Production Application
Start the master application wiring Weeks 1, 2, 3, and 4 together:
```bash
python governx_app.py
```
Open your browser and navigate to the interactive Swagger UI:
👉 **[http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)**

---

## 🔗 Key API Route Reference

| Category | Method & Endpoint | Description |
| :--- | :--- | :--- |
| **System** | `GET /health/live` | Container / Kubernetes Liveness Probe |
| **System** | `GET /health/ready` | Readiness Probe verifying 6 core subsystems |
| **Week 1** | `POST /api/v1/audit/trigger` | Trigger Moto AWS security audit & normalization |
| **Week 1** | `GET /api/v1/audit/{id}/findings` | Query normalized findings with filters & pagination |
| **Week 2** | `GET /api/v2/compliance/checks` | List 24 automated compliance checks mapped to NIST CSF |
| **Week 2** | `POST /api/v2/audit/{id}/run-compliance-checks` | Run compliance checks and get 0-100% score |
| **Week 2** | `GET /api/v2/findings/aggregated` | Retrieve deduplicated findings across all historical audits |
| **Week 2** | `GET /api/v2/findings/deduplication-stats` | Retrieve deduplication ratio & occurrence statistics |
| **Week 3** | `GET /api/v3/govern/supply-chain/summary` | Vendor risk summary, weighted scores & concentration risk |
| **Week 3** | `GET /api/v3/govern/policies` | Active enterprise security policies & mandatory rules |
| **Week 3** | `GET /api/v3/govern/policies/compliance-summary` | Policy violation scorecard and compliance percentage |
| **Week 3** | `GET /api/v3/govern/governance/scorecard` | Board governance overview & risk appetite breach analysis |
| **Week 3** | `GET /api/v3/govern/stakeholders` | Risk ownership registry and SLA escalation matrix |
| **Week 4** | `GET /api/v4/cache/stats` | In-memory TTL cache hit/miss performance metrics |

---

## 🧪 Running Component Smoke Tests

Each module is standalone and testable directly from the terminal:
```bash
python supply_chain_connector.py      # Test vendor risk scoring (GV.SC)
python organizational_policy_engine.py # Test policy violation evaluator (GV.PO)
python governance_data_collector.py   # Test board scorecard & risk appetite (GV.OV)
python stakeholder_registry.py        # Test risk owners & SLA escalation (GV.RR)
python api_optimization.py            # Test TTL cache & rate limiter
python security_hardening.py          # Test RBAC, tokens & audit logger
python error_handling.py              # Test error envelopes & health probes
python deployment_config.py           # Test configuration management
```