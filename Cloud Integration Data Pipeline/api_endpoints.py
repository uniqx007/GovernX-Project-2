"""
GovernX: API Endpoints - FastAPI endpoints for cloud auditing
REST API for triggering audits, retrieving findings
"""

from fastapi import FastAPI, HTTPException, Query, BackgroundTasks
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from datetime import datetime
import logging
import json
from contextlib import asynccontextmanager

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ============================================
# LIFESPAN
# ============================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("GovernX API started")
    yield
    logger.info("GovernX API stopped")

# Initialize FastAPI
app = FastAPI(
    title="GovernX Cloud Audit API",
    description="API for continuous cloud security auditing and NIST CSF 2.0 compliance",
    version="0.1.0",
    lifespan=lifespan
)

# ============================================
# MODELS
# ============================================

class AuditRequest(BaseModel):
    """Request to trigger cloud audit"""
    provider: str  # 'aws', 'azure'
    regions: Optional[List[str]] = None  # If None, all regions
    force_refresh: bool = False  # Skip cache


class AuditResponse(BaseModel):
    """Response from audit request"""
    audit_id: str
    provider: str
    status: str  # 'queued', 'running', 'complete', 'error'
    findings_count: int
    resources_count: int
    timestamp: str
    message: str


class FindingResponse(BaseModel):
    """Single finding response"""
    finding_id: str
    resource_id: str
    resource_type: str
    finding_type: str
    severity: str
    description: str
    remediation: str
    timestamp: str
    provider: str


class ResourceResponse(BaseModel):
    """Single resource response"""
    resource_id: str
    resource_type: str
    service: str
    region: str
    configuration: Dict[str, Any]
    timestamp: str
    provider: str


class AuditSummary(BaseModel):
    """Summary of audit results"""
    audit_id: str
    provider: str
    timestamp: str
    status: str
    total_findings: int
    findings_by_severity: Dict[str, int]
    total_resources: int
    resources_by_service: Dict[str, int]


class ProviderStatus(BaseModel):
    """Status of cloud provider connection"""
    provider: str
    connected: bool
    last_audit: Optional[str]
    regions: List[str]
    credentials_valid: bool
    message: str


# ============================================
# GLOBAL STATE
# ============================================

audit_cache = {}
findings_cache = {}
resources_cache = {}
provider_status = {}


# ============================================
# HEALTH & STATUS ENDPOINTS
# ============================================

@app.get("/", tags=["Health"])
async def health_check() -> Dict[str, Any]:
    """Health check endpoint"""
    return {
        "service": "GovernX Cloud Audit API",
        "status": "running",
        "timestamp": datetime.now().isoformat(),
        "version": "0.1.0"
    }


@app.get("/api/v1/health", tags=["Health"])
async def detailed_health() -> Dict[str, Any]:
    """Detailed health check with provider status"""
    return {
        "service": "GovernX Cloud Audit API",
        "status": "running",
        "timestamp": datetime.now().isoformat(),
        "providers": provider_status,
        "cache_info": {
            "audits": len(audit_cache),
            "findings": len(findings_cache),
            "resources": len(resources_cache)
        }
    }


@app.get("/api/v1/providers/status", response_model=List[ProviderStatus], tags=["Providers"])
async def get_provider_status() -> List[ProviderStatus]:
    """Get status of all cloud providers"""
    statuses = []
    
    # AWS status
    try:
        import boto3
        session = boto3.Session()
        statuses.append(ProviderStatus(
            provider="aws",
            connected=True,
            last_audit=provider_status.get("aws", {}).get("last_audit"),
            regions=["us-east-1", "us-west-2", "eu-west-1"],
            credentials_valid=True,
            message="AWS credentials valid"
        ))
    except Exception as e:
        statuses.append(ProviderStatus(
            provider="aws",
            connected=False,
            last_audit=None,
            regions=[],
            credentials_valid=False,
            message=f"AWS connection error: {str(e)}"
        ))
    
    return statuses


# ============================================
# AUDIT ENDPOINTS
# ============================================

@app.post("/api/v1/audit/start", response_model=AuditResponse, tags=["Audits"])
async def start_audit(request: AuditRequest, background_tasks: BackgroundTasks) -> AuditResponse:
    """Start cloud security audit"""
    
    logger.info(f"Starting audit for {request.provider}")
    
    # Validate provider
    if request.provider.lower() not in ['aws', 'azure']:
        raise HTTPException(status_code=400, detail="Provider must be 'aws' or 'azure'")
    
    # Generate audit ID
    audit_id = f"{request.provider}_{datetime.now().timestamp()}"
    
    # Add to cache
    audit_info = {
        'id': audit_id,
        'provider': request.provider,
        'status': 'queued',
        'started': datetime.now().isoformat(),
        'regions': request.regions or ['us-east-1'],
        'force_refresh': request.force_refresh
    }
    audit_cache[audit_id] = audit_info
    
    # Schedule background task to run audit
    if request.provider.lower() == 'aws':
        background_tasks.add_task(run_aws_audit, audit_id, audit_info)
    else:
        background_tasks.add_task(run_azure_audit, audit_id, audit_info)
    
    return AuditResponse(
        audit_id=audit_id,
        provider=request.provider,
        status='queued',
        findings_count=0,
        resources_count=0,
        timestamp=datetime.now().isoformat(),
        message=f"Audit {audit_id} queued for {request.provider}"
    )


@app.get("/api/v1/audit/{audit_id}", response_model=AuditResponse, tags=["Audits"])
async def get_audit_status(audit_id: str) -> AuditResponse:
    """Get audit status"""
    
    if audit_id not in audit_cache:
        raise HTTPException(status_code=404, detail=f"Audit {audit_id} not found")
    
    audit = audit_cache[audit_id]
    findings_count = len(findings_cache.get(audit_id, []))
    resources_count = len(resources_cache.get(audit_id, []))
    
    return AuditResponse(
        audit_id=audit_id,
        provider=audit['provider'],
        status=audit['status'],
        findings_count=findings_count,
        resources_count=resources_count,
        timestamp=audit.get('started', datetime.now().isoformat()),
        message=audit.get('message', 'Audit in progress')
    )


@app.get("/api/v1/audit/{audit_id}/summary", response_model=AuditSummary, tags=["Audits"])
async def get_audit_summary(audit_id: str) -> AuditSummary:
    """Get audit summary with statistics"""
    
    if audit_id not in audit_cache:
        raise HTTPException(status_code=404, detail=f"Audit {audit_id} not found")
    
    audit = audit_cache[audit_id]
    findings = findings_cache.get(audit_id, [])
    resources = resources_cache.get(audit_id, [])
    
    # Calculate statistics
    findings_by_severity = {}
    for finding in findings:
        severity = finding.get('severity', 'UNKNOWN')
        findings_by_severity[severity] = findings_by_severity.get(severity, 0) + 1
    
    resources_by_service = {}
    for resource in resources:
        service = resource.get('service', 'UNKNOWN')
        resources_by_service[service] = resources_by_service.get(service, 0) + 1
    
    return AuditSummary(
        audit_id=audit_id,
        provider=audit['provider'],
        timestamp=audit.get('started', datetime.now().isoformat()),
        status=audit['status'],
        total_findings=len(findings),
        findings_by_severity=findings_by_severity,
        total_resources=len(resources),
        resources_by_service=resources_by_service
    )


# ============================================
# FINDINGS ENDPOINTS
# ============================================

@app.get("/api/v1/findings/latest", response_model=List[FindingResponse], tags=["Findings"])
async def get_latest_findings(
    provider: Optional[str] = Query(None, description="Filter by provider"),
    severity: Optional[str] = Query(None, description="Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)"),
    skip: int = Query(0),
    limit: int = Query(100)
) -> List[FindingResponse]:
    """Get latest findings across all audits"""
    
    all_findings = []
    for audit_id, findings in findings_cache.items():
        all_findings.extend(findings)
    
    # Filter
    if provider:
        all_findings = [f for f in all_findings if f.get('provider') == provider]
    
    if severity:
        all_findings = [f for f in all_findings if f.get('severity') == severity]
    
    # Paginate
    return all_findings[skip:skip+limit]


@app.get("/api/v1/audit/{audit_id}/findings", response_model=List[FindingResponse], tags=["Findings"])
async def get_audit_findings(
    audit_id: str,
    severity: Optional[str] = Query(None),
    skip: int = Query(0),
    limit: int = Query(100)
) -> List[FindingResponse]:
    """Get findings for specific audit"""
    
    if audit_id not in findings_cache:
        raise HTTPException(status_code=404, detail=f"No findings for audit {audit_id}")
    
    findings = findings_cache[audit_id]
    
    # Filter by severity if specified
    if severity:
        findings = [f for f in findings if f.get('severity') == severity]
    
    # Paginate
    return findings[skip:skip+limit]


# ============================================
# RESOURCES ENDPOINTS
# ============================================

@app.get("/api/v1/audit/{audit_id}/resources", response_model=List[ResourceResponse], tags=["Resources"])
async def get_audit_resources(
    audit_id: str,
    service: Optional[str] = Query(None),
    skip: int = Query(0),
    limit: int = Query(100)
) -> List[ResourceResponse]:
    """Get resources from specific audit"""
    
    if audit_id not in resources_cache:
        raise HTTPException(status_code=404, detail=f"No resources for audit {audit_id}")
    
    resources = resources_cache[audit_id]
    
    # Filter by service if specified
    if service:
        resources = [r for r in resources if r.get('service') == service]
    
    # Paginate
    return resources[skip:skip+limit]


# ============================================
# BACKGROUND TASKS
# ============================================

async def run_aws_audit(audit_id: str, audit_info: Dict):
    """Run AWS audit in background"""
    try:
        logger.info(f"Running AWS audit {audit_id}")
        
        # Import AWS connector
        from aws_connector import AWSConnector
        
        # Update status
        audit_info['status'] = 'running'
        
        # Run audit for each region
        all_findings = []
        all_resources = []
        
        for region in audit_info.get('regions', ['us-east-1']):
            connector = AWSConnector(region=region)
            result = connector.run_full_audit()
            
            all_findings.extend(result.get('findings', []))
            all_resources.extend(result.get('resources', []))
        
        # Cache results
        findings_cache[audit_id] = all_findings
        resources_cache[audit_id] = all_resources
        
        # Update audit status
        audit_info['status'] = 'complete'
        audit_info['message'] = f"Found {len(all_findings)} findings, {len(all_resources)} resources"
        provider_status['aws'] = {'last_audit': datetime.now().isoformat()}
        
        logger.info(f"AWS audit {audit_id} complete")
    
    except Exception as e:
        logger.error(f"AWS audit {audit_id} failed: {e}")
        audit_info['status'] = 'error'
        audit_info['message'] = str(e)


async def run_azure_audit(audit_id: str, audit_info: Dict):
    """Run Azure audit in background (placeholder)"""
    try:
        logger.info(f"Running Azure audit {audit_id}")
        
        # TODO: Implement Azure connector
        audit_info['status'] = 'error'
        audit_info['message'] = 'Azure connector not yet implemented'
        
        logger.warning(f"Azure audit {audit_id} not implemented")
    
    except Exception as e:
        logger.error(f"Azure audit {audit_id} failed: {e}")
        audit_info['status'] = 'error'
        audit_info['message'] = str(e)





if __name__ == "__main__":
    import uvicorn
    # Run API server
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info"
    )
