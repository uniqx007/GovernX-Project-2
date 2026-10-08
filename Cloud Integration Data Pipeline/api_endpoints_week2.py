"""
GovernX: API Endpoints Week 2 - Extended endpoints for compliance & aggregation
Week 2
REST API with compliance checks, deduplication, finding aggregation
"""

from fastapi import FastAPI, HTTPException, Query, BackgroundTasks
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from datetime import datetime
import logging
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI
app = FastAPI(
    title="GovernX Cloud Audit API (Week 2)",
    description="API for continuous cloud security auditing and compliance checking",
    version="0.2.0"
)

# ============================================
# MODELS
# ============================================

class ComplianceCheckResponse(BaseModel):
    """Compliance check response"""
    check_id: str
    check_name: str
    resource_id: str
    resource_type: str
    passed: bool
    severity: str
    nist_category: str
    message: str
    timestamp: str


class ComplianceSummary(BaseModel):
    """Compliance summary"""
    total_checks: int
    passed_checks: int
    failed_checks: int
    compliance_score: float  # 0-100
    checks_by_severity: Dict[str, int]
    checks_by_service: Dict[str, int]


class AggregatedFindingResponse(BaseModel):
    """Aggregated finding response"""
    finding_id: str
    resource_id: str
    resource_type: str
    finding_type: str
    severity: str
    service: str
    occurrence_count: int
    first_seen: str
    last_seen: str
    sources: List[str]


# ============================================
# GLOBAL STATE
# ============================================

audit_cache = {}
findings_cache = {}
resources_cache = {}
compliance_cache = {}
aggregated_findings_cache = {}


# ============================================
# HEALTH ENDPOINTS
# ============================================

@app.get("/", tags=["Health"])
async def health_check() -> Dict[str, Any]:
    """Health check endpoint"""
    return {
        "service": "GovernX Cloud Audit API (Week 2)",
        "status": "running",
        "features": ["Cloud Auditing", "Compliance Checks", "Finding Aggregation"],
        "timestamp": datetime.now().isoformat(),
        "version": "0.2.0"
    }


# ============================================
# COMPLIANCE CHECK ENDPOINTS
# ============================================

@app.get("/api/v2/compliance/checks", response_model=List[Dict[str, Any]], tags=["Compliance"])
async def get_available_compliance_checks(
    service: Optional[str] = Query(None, description="Filter by service"),
    severity: Optional[str] = Query(None, description="Filter by severity")
) -> List[Dict[str, Any]]:
    """Get available compliance checks"""
    
    # Return compliance checks based on filters
    checks = [
        {
            'check_id': 'ec2_imdsv2_enabled',
            'name': 'EC2 IMDSv2 Enabled',
            'service': 'ec2',
            'severity': 'MEDIUM',
            'nist_category': 'PR.DS-01'
        },
        {
            'check_id': 's3_public_access_blocked',
            'name': 'S3 Block Public Access',
            'service': 's3',
            'severity': 'CRITICAL',
            'nist_category': 'PR.DS-03'
        },
        {
            'check_id': 'rds_encryption_enabled',
            'name': 'RDS Encryption at Rest',
            'service': 'rds',
            'severity': 'CRITICAL',
            'nist_category': 'PR.DS-01'
        },
        {
            'check_id': 'iam_mfa_enabled',
            'name': 'IAM MFA for Console Users',
            'service': 'iam',
            'severity': 'HIGH',
            'nist_category': 'PR.AC-01'
        }
    ]
    
    # Apply filters
    if service:
        checks = [c for c in checks if c['service'] == service]
    if severity:
        checks = [c for c in checks if c['severity'] == severity]
    
    return checks


@app.post("/api/v2/audit/{audit_id}/run-compliance-checks", response_model=ComplianceSummary, tags=["Compliance"])
async def run_compliance_checks(audit_id: str, background_tasks: BackgroundTasks) -> ComplianceSummary:
    """Run compliance checks on audit findings"""
    
    if audit_id not in audit_cache:
        raise HTTPException(status_code=404, detail=f"Audit {audit_id} not found")
    
    audit = audit_cache[audit_id]
    
    # Schedule background task
    background_tasks.add_task(execute_compliance_checks, audit_id, audit)
    
    return ComplianceSummary(
        total_checks=0,
        passed_checks=0,
        failed_checks=0,
        compliance_score=0.0,
        checks_by_severity={},
        checks_by_service={}
    )


@app.get("/api/v2/audit/{audit_id}/compliance-summary", response_model=ComplianceSummary, tags=["Compliance"])
async def get_compliance_summary(audit_id: str) -> ComplianceSummary:
    """Get compliance check summary for audit"""
    
    if audit_id not in compliance_cache:
        raise HTTPException(status_code=404, detail=f"No compliance data for audit {audit_id}")
    
    compliance_data = compliance_cache[audit_id]
    
    return ComplianceSummary(
        total_checks=compliance_data.get('total_checks', 0),
        passed_checks=compliance_data.get('passed_checks', 0),
        failed_checks=compliance_data.get('failed_checks', 0),
        compliance_score=compliance_data.get('compliance_score', 0.0),
        checks_by_severity=compliance_data.get('checks_by_severity', {}),
        checks_by_service=compliance_data.get('checks_by_service', {})
    )


@app.get("/api/v2/audit/{audit_id}/compliance-checks/failed", response_model=List[ComplianceCheckResponse], tags=["Compliance"])
async def get_failed_compliance_checks(
    audit_id: str,
    severity: Optional[str] = Query(None),
    skip: int = Query(0),
    limit: int = Query(100)
) -> List[ComplianceCheckResponse]:
    """Get failed compliance checks for audit"""
    
    if audit_id not in compliance_cache:
        raise HTTPException(status_code=404, detail=f"No compliance data for audit {audit_id}")
    
    compliance_data = compliance_cache[audit_id]
    failed_checks = [c for c in compliance_data.get('checks', []) if not c['passed']]
    
    if severity:
        failed_checks = [c for c in failed_checks if c['severity'] == severity]
    
    return failed_checks[skip:skip+limit]


# ============================================
# FINDING AGGREGATION ENDPOINTS
# ============================================

@app.get("/api/v2/findings/aggregated", response_model=List[AggregatedFindingResponse], tags=["Aggregation"])
async def get_aggregated_findings(
    severity: Optional[str] = Query(None),
    service: Optional[str] = Query(None),
    duplicates_only: bool = Query(False),
    skip: int = Query(0),
    limit: int = Query(100)
) -> List[AggregatedFindingResponse]:
    """Get aggregated (deduplicated) findings across all audits"""
    
    # Combine all findings from all audits
    all_aggregated = []
    for audit_findings in aggregated_findings_cache.values():
        all_aggregated.extend(audit_findings)
    
    # Filter
    if severity:
        all_aggregated = [f for f in all_aggregated if f.get('severity') == severity]
    if service:
        all_aggregated = [f for f in all_aggregated if f.get('service') == service]
    if duplicates_only:
        all_aggregated = [f for f in all_aggregated if f.get('occurrence_count', 0) > 1]
    
    return all_aggregated[skip:skip+limit]


@app.get("/api/v2/findings/deduplication-stats", tags=["Aggregation"])
async def get_deduplication_statistics() -> Dict[str, Any]:
    """Get deduplication statistics"""
    
    total_raw = sum(len(v) for v in findings_cache.values())
    total_unique = sum(len(v) for v in aggregated_findings_cache.values())
    
    return {
        'total_raw_findings': total_raw,
        'total_unique_findings': total_unique,
        'deduplication_ratio': (1 - (total_unique / total_raw) * 100) if total_raw > 0 else 0,
        'timestamp': datetime.now().isoformat()
    }


@app.get("/api/v2/findings/duplicates", response_model=List[AggregatedFindingResponse], tags=["Aggregation"])
async def get_duplicate_findings(
    min_occurrences: int = Query(2, description="Minimum occurrence count")
) -> List[AggregatedFindingResponse]:
    """Get findings that have occurred multiple times"""
    
    all_aggregated = []
    for audit_findings in aggregated_findings_cache.values():
        all_aggregated.extend(audit_findings)
    
    duplicates = [f for f in all_aggregated if f.get('occurrence_count', 0) >= min_occurrences]
    
    return duplicates


@app.post("/api/v2/audit/{audit_id}/aggregate-findings", tags=["Aggregation"])
async def aggregate_audit_findings(audit_id: str, background_tasks: BackgroundTasks) -> Dict[str, Any]:
    """Aggregate findings from audit (deduplicate)"""
    
    if audit_id not in findings_cache:
        raise HTTPException(status_code=404, detail=f"No findings for audit {audit_id}")
    
    background_tasks.add_task(deduplicate_findings, audit_id)
    
    return {
        'audit_id': audit_id,
        'status': 'aggregating',
        'message': 'Finding aggregation in progress'
    }


# ============================================
# BACKGROUND TASKS
# ============================================

async def execute_compliance_checks(audit_id: str, audit_info: Dict):
    """Execute compliance checks in background"""
    try:
        logger.info(f"Running compliance checks for audit {audit_id}")
        
        # Import compliance checker
        from aws_compliance_checks import ComplianceChecker, AWSComplianceChecks
        
        findings = findings_cache.get(audit_id, [])
        resources = resources_cache.get(audit_id, [])
        
        checker = ComplianceChecker()
        
        # Run compliance checks on resources
        for resource in resources:
            if resource.get('service') == 'ec2':
                # Run EC2 checks
                checker.check_ec2_imdsv2(resource.get('configuration', {}))
                checker.check_ec2_monitoring(resource.get('configuration', {}))
            elif resource.get('service') == 's3':
                # Run S3 checks
                checker.check_s3_public_access_blocked(resource.get('configuration', {}))
                checker.check_s3_encryption(resource.get('configuration', {}))
        
        # Get results
        results = checker.get_results()
        
        # Calculate summary
        passed = len([r for r in results if r.passed])
        failed = len([r for r in results if not r.passed])
        score = (passed / len(results) * 100) if results else 0
        
        # Cache compliance data
        compliance_cache[audit_id] = {
            'timestamp': datetime.now().isoformat(),
            'total_checks': len(results),
            'passed_checks': passed,
            'failed_checks': failed,
            'compliance_score': score,
            'checks': [
                {
                    'check_id': r.check_id,
                    'resource_id': r.resource_id,
                    'resource_type': r.resource_type,
                    'passed': r.passed,
                    'severity': r.severity,
                    'message': r.message
                }
                for r in results
            ],
            'checks_by_severity': {
                'CRITICAL': len([r for r in results if r.severity == 'CRITICAL' and not r.passed]),
                'HIGH': len([r for r in results if r.severity == 'HIGH' and not r.passed]),
                'MEDIUM': len([r for r in results if r.severity == 'MEDIUM' and not r.passed]),
                'LOW': len([r for r in results if r.severity == 'LOW' and not r.passed])
            },
            'checks_by_service': {
                'ec2': len([r for r in results if 'EC2' in r.resource_type]),
                's3': len([r for r in results if 'S3' in r.resource_type]),
                'rds': len([r for r in results if 'RDS' in r.resource_type]),
                'iam': len([r for r in results if 'IAM' in r.resource_type])
            }
        }
        
        logger.info(f"Compliance checks complete: {passed} passed, {failed} failed")
    
    except Exception as e:
        logger.error(f"Compliance check failed: {e}")


async def deduplicate_findings(audit_id: str):
    """Deduplicate findings in background"""
    try:
        logger.info(f"Aggregating findings for audit {audit_id}")
        
        from finding_aggregator import FindingAggregator
        
        aggregator = FindingAggregator()
        findings = findings_cache.get(audit_id, [])
        
        # Add findings to aggregator
        aggregator.add_findings_batch(findings, source=audit_id)
        
        # Get aggregated findings
        aggregated = [f.to_dict() for f in aggregator.get_all_findings()]
        
        aggregated_findings_cache[audit_id] = aggregated
        
        logger.info(f"Aggregation complete: {len(aggregated)} unique findings")
    
    except Exception as e:
        logger.error(f"Finding aggregation failed: {e}")


# ============================================
# STARTUP & SHUTDOWN
# ============================================

@app.on_event("startup")
async def startup():
    """Initialize on startup"""
    logger.info("✅ GovernX API (Week 2) started")


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info"
    )
