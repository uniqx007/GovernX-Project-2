"""
GovernX Master Production Application - governx_app.py
Unified Backend & Cloud Integration Gateway (Weeks 1 - 4)

Wires together:
- Week 1: Multi-Cloud Ingestion, Boto3 Moto Auditing, Normalization (/api/v1/...)
- Week 2: 24 NIST Compliance Checks, MD5 Finding Deduplication (/api/v2/...)
- Week 3: CSF 2.0 Govern Function: Supply Chain, Policies, Board Governance, Stakeholders (/api/v3/govern/...)
- Week 4: Security Hardening, TTL Caching, Rate Limiting, Health Monitoring, Production Resilience
"""

import os
import json
import logging
from datetime import datetime
from dataclasses import dataclass, asdict
from contextlib import asynccontextmanager
from typing import Dict, List, Any, Optional

from fastapi import FastAPI, HTTPException, Query, Header, Request, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

# Core Modules (From Week 1 & 2)
from aws_connector import AWSConnector
from data_normalizer import DataNormalizer
from aws_compliance_checks import AWSComplianceChecks, ComplianceChecker
from finding_aggregator import FindingAggregator

# Week 3 Modules (Govern Function)
from supply_chain_connector import SupplyChainConnector
from organizational_policy_engine import OrganizationalPolicyEngine
from governance_data_collector import GovernanceDataCollector
from stakeholder_registry import StakeholderRegistry

# Week 4 Modules (Production Hardening & Optimization)
from api_optimization import TTLCache, InMemoryRateLimiter, paginate_items
from security_hardening import (
    verify_api_key, check_permission, mask_sensitive_data,
    SecurityAuditLogger, SECURITY_HEADERS, UserRole
)
from error_handling import (
    GovernXBaseException, ResourceNotFoundError, AuthenticationError,
    governx_exception_handler, global_generic_exception_handler, HealthMonitor
)
from deployment_config import load_deployment_config

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("governx_app")

# =====================================================================
# CONFIGURATION & GLOBAL STATE
# =====================================================================

config = load_deployment_config()
cache = TTLCache(default_ttl_seconds=config.cache_ttl_seconds)
rate_limiter = InMemoryRateLimiter(requests_per_minute=config.rate_limit_per_minute)
audit_logger = SecurityAuditLogger()
health_monitor = HealthMonitor()

# Subsystem Engines
normalizer = DataNormalizer()
supply_chain = SupplyChainConnector()
policy_engine = OrganizationalPolicyEngine()
gov_collector = GovernanceDataCollector()
stakeholder_reg = StakeholderRegistry()
global_aggregator = FindingAggregator()

# In-Memory Datastores (Audit State)
audit_cache: Dict[str, Dict[str, Any]] = {}
findings_cache: Dict[str, List[Dict[str, Any]]] = {}
resources_cache: Dict[str, List[Dict[str, Any]]] = {}
compliance_cache: Dict[str, Dict[str, Any]] = {}
aggregated_findings_cache: Dict[str, List[Dict[str, Any]]] = {}


# =====================================================================
# LIFESPAN INITIALIZATION (PRE-LOAD DATA FOR INSTANT USAGE)
# =====================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("======================================================================")
    logger.info("STARTING GOVERNX UNIFIED CLOUD GOVERNANCE & COMPLIANCE ENGINE")
    logger.info(f"Environment: {config.environment} | Port: {config.port} | Debug: {config.debug}")
    logger.info("======================================================================")

    # Automatically preload existing datasets or perform a cold-start seed
    try:
        # Preload from local cache files if present
        if os.path.exists("normalized_findings.json") and os.path.exists("normalized_resources.json"):
            with open("normalized_findings.json", "r", encoding="utf-8") as f:
                norm_findings = json.load(f)
            with open("normalized_resources.json", "r", encoding="utf-8") as f:
                norm_resources = json.load(f)

            audit_id = "audit_latest"
            audit_cache[audit_id] = {
                "audit_id": audit_id,
                "provider": "aws",
                "status": "complete",
                "findings_count": len(norm_findings),
                "resources_count": len(norm_resources),
                "timestamp": datetime.now().isoformat()
            }
            findings_cache[audit_id] = norm_findings
            resources_cache[audit_id] = norm_resources

            # Pre-evaluate policies
            policy_engine.evaluate_findings(norm_findings)

            # Pre-populate aggregator
            global_aggregator.add_findings_batch(norm_findings, source="aws_moto_seed")
            aggregated_findings_cache[audit_id] = [f.to_dict() for f in global_aggregator.get_all_findings()]

            logger.info("Preloaded audit datasets and evaluated initial policies successfully")
    except Exception as e:
        logger.warning(f"Note during cache preload: {e}")

    yield
    logger.info("GovernX API stopped gracefully.")


# Initialize Master FastAPI App
app = FastAPI(
    title="GovernX Cloud Compliance & Governance Platform",
    description="Unified API Gateway integrating Cloud Audits (W1), NIST Compliance & Deduplication (W2), "
                "Govern-Function Third-Party Risk & Policies (W3), and Production Hardening (W4).",
    version="1.0.0",
    lifespan=lifespan
)

# Register Custom Exception Handlers
app.add_exception_handler(GovernXBaseException, governx_exception_handler)
app.add_exception_handler(Exception, global_generic_exception_handler)

# Enable CORS for Frontend UI
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =====================================================================
# MIDDLEWARE: SECURITY HEADERS & RATE LIMITING
# =====================================================================

@app.middleware("http")
async def security_and_rate_limit_middleware(request: Request, call_next):
    # 1. Rate Limiting Check
    client_ip = request.client.host if request.client else "127.0.0.1"
    allowed, remaining = rate_limiter.is_allowed(client_ip)
    if not allowed:
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={"status": "error", "message": "Rate limit exceeded (120 req/min). Try again shortly."}
        )

    # 2. Security Audit Logging for mutations
    if request.method in ("POST", "PUT", "DELETE"):
        audit_logger.record(
            action=f"{request.method} {request.url.path}",
            client_id=client_ip,
            endpoint=request.url.path,
            status="INCOMING"
        )

    # 3. Process Request
    response = await call_next(request)

    # 4. Inject OWASP Security Headers
    for header, value in SECURITY_HEADERS.items():
        response.headers[header] = value
    response.headers["X-RateLimit-Remaining"] = str(remaining)

    return response


# =====================================================================
# AUTHENTICATION DEPENDENCY
# =====================================================================

async def get_current_user(x_api_key: Optional[str] = Header(None)) -> Dict[str, Any]:
    """Validates API Key if enforcement is active"""
    if not config.api_key_enforced:
        return {"role": UserRole.ADMIN, "owner": "Local Developer (Auth Bypass Active)"}

    identity = verify_api_key(x_api_key)
    if not identity:
        raise AuthenticationError("Invalid or missing X-API-Key header.")
    return identity


# =====================================================================
# DATA MODELS
# =====================================================================

class AuditTriggerRequest(BaseModel):
    provider: str = Field("aws", description="Cloud provider to audit (aws, azure)")
    region: Optional[str] = Field("us-east-1", description="Target region")
    force_refresh: bool = Field(False, description="Bypass cache")


class FindingAlertRequest(BaseModel):
    resource_id: str
    service: str
    severity: str
    finding_type: str


# =====================================================================
# SYSTEM & HEALTH ENDPOINTS (WEEK 4)
# =====================================================================

@app.get("/", tags=["System"])
async def root_overview():
    return {
        "service": "GovernX Unified Cloud Audit Platform",
        "version": "1.0.0",
        "status": "online",
        "documentation": "/docs",
        "weeks_integrated": ["Week 1: Extraction", "Week 2: Compliance", "Week 3: Governance", "Week 4: Production"]
    }


@app.get("/health/live", tags=["System"])
async def liveness_probe():
    """Kubernetes / Container Liveness Probe"""
    return health_monitor.get_liveness()


@app.get("/health/ready", tags=["System"])
async def readiness_probe():
    """Subsystem Readiness Probe"""
    status_map = {
        "cloud_poller": True,
        "data_normalizer": True,
        "compliance_engine": True,
        "supply_chain_connector": True,
        "policy_engine": True,
        "stakeholder_registry": True
    }
    return health_monitor.get_readiness(status_map)


@app.get("/api/v4/cache/stats", tags=["Optimization"])
async def get_cache_stats(user: Dict = Depends(get_current_user)):
    """In-memory TTL cache statistics"""
    return cache.stats()


# =====================================================================
# WEEK 1: CLOUD AUDITING & NORMALIZATION ENDPOINTS (/api/v1/...)
# =====================================================================

@app.post("/api/v1/audit/trigger", tags=["Week 1: Cloud Audit"])
async def trigger_cloud_audit(req: AuditTriggerRequest, user: Dict = Depends(get_current_user)):
    """Trigger on-demand cloud security audit using Moto AWS emulation"""
    logger.info(f"Triggering audit for provider={req.provider}, region={req.region}")

    try:
        connector = AWSConnector(region=req.region or "us-east-1")
        audit_res = connector.run_full_audit()

        # Normalize raw findings & resources
        norm_findings = []
        for f in connector.findings:
            nf = normalizer.normalize_aws_finding(f.to_dict()).to_dict()
            nf['service'] = f.service
            norm_findings.append(nf)
        norm_resources = []
        for r in connector.resources:
            nr = normalizer.normalize_aws_resource(asdict(r)).to_dict()
            nr['service'] = r.service
            norm_resources.append(nr)

        audit_id = f"audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        audit_cache[audit_id] = {
            "audit_id": audit_id,
            "provider": req.provider,
            "region": req.region,
            "status": "complete",
            "findings_count": len(norm_findings),
            "resources_count": len(norm_resources),
            "timestamp": datetime.now().isoformat()
        }
        findings_cache[audit_id] = norm_findings
        resources_cache[audit_id] = norm_resources

        # Feed findings to finding aggregator
        global_aggregator.add_findings_batch(norm_findings, source=audit_id)
        aggregated_findings_cache[audit_id] = [f.to_dict() for f in global_aggregator.get_all_findings()]

        # Automatically evaluate policies against new findings
        policy_engine.evaluate_findings(norm_findings)

        return {
            "audit_id": audit_id,
            "status": "complete",
            "provider": req.provider,
            "region": req.region,
            "findings_discovered": len(norm_findings),
            "resources_scanned": len(norm_resources),
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Audit execution failed: {e}")
        raise HTTPException(status_code=500, detail=f"Audit failed: {str(e)}")


@app.get("/api/v1/audit/{audit_id}/findings", tags=["Week 1: Cloud Audit"])
async def get_audit_findings(
    audit_id: str,
    severity: Optional[str] = Query(None),
    service: Optional[str] = Query(None),
    skip: int = Query(0),
    limit: int = Query(50)
):
    """Retrieve normalized findings from an audit run with pagination"""
    if audit_id not in findings_cache:
        raise ResourceNotFoundError("Audit Findings", audit_id)

    findings = findings_cache[audit_id]
    if severity:
        findings = [f for f in findings if f.get("severity") == severity.upper()]
    if service:
        findings = [f for f in findings if f.get("service_type", "").lower() == service.lower() or f.get("service", "").lower() == service.lower()]

    return paginate_items(mask_sensitive_data(findings), skip=skip, limit=limit)


@app.get("/api/v1/audit/{audit_id}/resources", tags=["Week 1: Cloud Audit"])
async def get_audit_resources(
    audit_id: str,
    service: Optional[str] = Query(None),
    skip: int = Query(0),
    limit: int = Query(50)
):
    """Retrieve discovered cloud resources"""
    if audit_id not in resources_cache:
        raise ResourceNotFoundError("Audit Resources", audit_id)

    resources = resources_cache[audit_id]
    if service:
        resources = [r for r in resources if r.get("service", "").lower() == service.lower()]

    return paginate_items(mask_sensitive_data(resources), skip=skip, limit=limit)


@app.get("/api/v1/audit/{audit_id}/summary", tags=["Week 1: Cloud Audit"])
async def get_audit_summary(audit_id: str):
    """High-level summary breakdown of scanned audit"""
    if audit_id not in audit_cache:
        raise ResourceNotFoundError("Audit", audit_id)

    findings = findings_cache.get(audit_id, [])
    resources = resources_cache.get(audit_id, [])

    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        s = f.get("severity", "LOW")
        sev_counts[s] = sev_counts.get(s, 0) + 1

    return {
        "audit_info": audit_cache[audit_id],
        "total_findings": len(findings),
        "total_resources": len(resources),
        "findings_by_severity": sev_counts
    }


# =====================================================================
# WEEK 2: COMPLIANCE CHECKS & DEDUPLICATION (/api/v2/...)
# =====================================================================

@app.get("/api/v2/compliance/checks", tags=["Week 2: Compliance & Dedup"])
async def list_available_compliance_checks(
    service: Optional[str] = Query(None),
    severity: Optional[str] = Query(None)
):
    """List 24 automated compliance checks mapped to NIST CSF 2.0 controls"""
    checks = list(AWSComplianceChecks.CHECKS.values())
    if service:
        checks = [c for c in checks if c.service.lower() == service.lower()]
    if severity:
        checks = [c for c in checks if c.severity.upper() == severity.upper()]

    return [asdict(c) for c in checks]


@app.post("/api/v2/audit/{audit_id}/run-compliance-checks", tags=["Week 2: Compliance & Dedup"])
async def execute_compliance_checks_api(audit_id: str):
    """Run 24 automated compliance checks against resources from an audit"""
    if audit_id not in resources_cache:
        raise ResourceNotFoundError("Audit Resources", audit_id)

    resources = resources_cache[audit_id]
    checker = ComplianceChecker()

    for r in resources:
        cfg = dict(r.get("configuration", {}))
        res_id = r.get("resource_id", "unknown")
        svc = r.get("service", "").lower()

        cfg["InstanceId"] = res_id
        cfg["Name"] = res_id
        cfg["DBInstanceIdentifier"] = res_id
        cfg["resource_id"] = res_id

        if svc == "ec2":
            checker.check_ec2_imdsv2(cfg)
            checker.check_ec2_monitoring(cfg)
            checker.check_ec2_ebs_encryption(cfg)
        elif svc == "s3":
            checker.check_s3_public_access_blocked(cfg)
            checker.check_s3_encryption(cfg)
            checker.check_s3_versioning(cfg)
        elif svc == "rds":
            checker.check_rds_encryption(cfg)
            checker.check_rds_backup_retention(cfg)
            checker.check_rds_multi_az(cfg)
            checker.check_rds_public_access(cfg)

    results = checker.get_results()
    passed = len([res for res in results if res.passed])
    failed = len([res for res in results if not res.passed])
    score = round((passed / len(results) * 100), 1) if results else 100.0

    summary_data = {
        "timestamp": datetime.now().isoformat(),
        "total_checks_executed": len(results),
        "passed_checks": passed,
        "failed_checks": failed,
        "compliance_score_percentage": score,
        "results": [asdict(res) for res in results]
    }
    compliance_cache[audit_id] = summary_data
    return summary_data


@app.get("/api/v2/audit/{audit_id}/compliance-summary", tags=["Week 2: Compliance & Dedup"])
async def get_compliance_summary_api(audit_id: str):
    """Retrieve compliance score and summary for an audit"""
    if audit_id not in compliance_cache:
        # Generate on the fly if not evaluated yet
        return await execute_compliance_checks_api(audit_id)
    return compliance_cache[audit_id]


@app.get("/api/v2/findings/aggregated", tags=["Week 2: Compliance & Dedup"])
async def get_all_aggregated_findings(
    duplicates_only: bool = Query(False),
    skip: int = Query(0),
    limit: int = Query(50)
):
    """Retrieve deduplicated findings across all historical audits"""
    all_findings = [f.to_dict() for f in global_aggregator.get_all_findings()]
    if duplicates_only:
        all_findings = [f for f in all_findings if f.get("occurrence_count", 0) > 1]
    return paginate_items(all_findings, skip=skip, limit=limit)


@app.get("/api/v2/findings/deduplication-stats", tags=["Week 2: Compliance & Dedup"])
async def get_deduplication_statistics():
    """Retrieve deduplication metrics (ratio, unique vs raw)"""
    stats = global_aggregator.validate_deduplication()
    return stats


# =====================================================================
# WEEK 3: GOVERN FUNCTION ENDPOINTS (/api/v3/govern/...)
# =====================================================================

@app.get("/api/v3/govern/supply-chain/summary", tags=["Week 3: Supply Chain Risk (GV.SC)"])
async def get_supply_chain_summary():
    """Vendor risk assessment summary & concentration risk (NIST CSF 2.0 GV.SC)"""
    return supply_chain.summary()


@app.get("/api/v3/govern/supply-chain/vendors", tags=["Week 3: Supply Chain Risk (GV.SC)"])
async def list_vendor_assessments():
    """Full vendor registry with individual gap breakdowns & security tiers"""
    return [asdict(a) for a in supply_chain.assess_all()]


@app.get("/api/v3/govern/policies", tags=["Week 3: Policies & Governance (GV.PO)"])
async def list_organizational_policies():
    """List active enterprise organizational security policies and rules"""
    return [p.to_dict() for p in policy_engine.policies]


@app.get("/api/v3/govern/policies/compliance-summary", tags=["Week 3: Policies & Governance (GV.PO)"])
async def get_policy_compliance_summary():
    """Organizational policy compliance scorecard and active violations"""
    return policy_engine.get_compliance_summary()


@app.get("/api/v3/govern/governance/scorecard", tags=["Week 3: Board Oversight (GV.OC/OV)"])
async def get_board_governance_scorecard():
    """Board-level oversight metrics, cyber insurance, and risk appetite breach status"""
    return gov_collector.get_board_scorecard()


@app.get("/api/v3/govern/stakeholders", tags=["Week 3: Stakeholders & Roles (GV.RR)"])
async def list_stakeholder_registry():
    """Risk owners, assigned technical domains, and escalation rules"""
    return stakeholder_reg.get_registry_summary()


@app.post("/api/v3/govern/stakeholders/route-alert", tags=["Week 3: Stakeholders & Roles (GV.RR)"])
async def route_finding_alert_endpoint(finding: FindingAlertRequest):
    """Automatically route a critical finding to accountable stakeholder with SLA"""
    alert = stakeholder_reg.route_finding_alert(finding.dict())
    return asdict(alert)


# =====================================================================
# APPLICATION ENTRYPOINT
# =====================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "governx_app:app",
        host=config.host,
        port=config.port,
        reload=config.debug
    )
