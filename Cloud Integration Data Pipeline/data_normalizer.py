"""
GovernX: Data Normalizer - Standardize cloud findings across providers
Normalize AWS/Azure data to unified format
"""

import json
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
from dataclasses import dataclass, asdict
from enum import Enum

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ============================================
# ENUMS & STANDARDS
# ============================================

class Severity(str, Enum):
    """Standard severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ResourceType(str, Enum):
    """Standardized resource types"""
    # Compute
    VIRTUAL_MACHINE = "VirtualMachine"
    CONTAINER = "Container"
    SERVERLESS_FUNCTION = "ServerlessFunction"
    
    # Storage
    OBJECT_STORAGE = "ObjectStorage"
    BLOCK_STORAGE = "BlockStorage"
    DATABASE = "Database"
    
    # Network
    LOAD_BALANCER = "LoadBalancer"
    FIREWALL = "Firewall"
    NETWORK_INTERFACE = "NetworkInterface"
    
    # Security
    IAM_USER = "IAMUser"
    IAM_ROLE = "IAMRole"
    IAM_POLICY = "IAMPolicy"
    
    # Other
    OTHER = "Other"


class ServiceType(str, Enum):
    """Standard service types"""
    COMPUTE = "Compute"
    STORAGE = "Storage"
    DATABASE = "Database"
    NETWORK = "Network"
    SECURITY = "Security"
    MANAGEMENT = "Management"


# ============================================
# NORMALIZED DATA MODELS
# ============================================

@dataclass
class NormalizedFinding:
    """Normalized finding across cloud providers"""
    finding_id: str  # Unique ID
    provider: str  # aws, azure, gcp
    resource_id: str
    resource_type: ResourceType
    service_type: ServiceType
    finding_type: str
    severity: Severity
    description: str
    remediation: str
    evidence: Dict[str, Any]  # Provider-specific evidence
    timestamp: str
    last_updated: str
    
    def to_dict(self) -> Dict:
        data = asdict(self)
        data['resource_type'] = self.resource_type.value
        data['service_type'] = self.service_type.value
        data['severity'] = self.severity.value
        return data


@dataclass
class NormalizedResource:
    """Normalized resource across cloud providers"""
    resource_id: str
    provider: str  # aws, azure, gcp
    resource_type: ResourceType
    service_type: ServiceType
    name: str
    region: str
    account_id: str
    tags: Dict[str, str]
    configuration: Dict[str, Any]
    timestamp: str
    
    def to_dict(self) -> Dict:
        data = asdict(self)
        data['resource_type'] = self.resource_type.value
        data['service_type'] = self.service_type.value
        return data


# ============================================
# DATA NORMALIZER
# ============================================

class DataNormalizer:
    """Normalize cloud data to standard format"""
    
    def __init__(self):
        self.normalized_findings: List[NormalizedFinding] = []
        self.normalized_resources: List[NormalizedResource] = []
        logger.info("Data normalizer initialized")
    
    # ============================================
    # AWS NORMALIZATION
    # ============================================
    
    def normalize_aws_finding(self, aws_finding: Dict[str, Any], provider: str = 'aws') -> NormalizedFinding:
        """Normalize AWS finding"""
        
        # Map AWS service to standard service type
        service_mapping = {
            'ec2': ServiceType.COMPUTE,
            's3': ServiceType.STORAGE,
            'rds': ServiceType.DATABASE,
            'iam': ServiceType.SECURITY,
            'vpc': ServiceType.NETWORK,
            'kms': ServiceType.SECURITY
        }
        
        # Map AWS resource type to standard type
        resource_type_mapping = {
            'EC2-Instance': ResourceType.VIRTUAL_MACHINE,
            'S3-Bucket': ResourceType.OBJECT_STORAGE,
            'RDS-Instance': ResourceType.DATABASE,
            'SecurityGroup': ResourceType.FIREWALL,
            'IAM-User': ResourceType.IAM_USER,
            'IAM-RoleIAM-Role': ResourceType.IAM_ROLE,
        }
        
        service = aws_finding.get('service', 'other').lower()
        resource_type_str = aws_finding.get('resource_type', 'Other')
        
        normalized = NormalizedFinding(
            finding_id=f"aws_{aws_finding['resource_id']}_{aws_finding['finding_type']}",
            provider=provider,
            resource_id=aws_finding['resource_id'],
            resource_type=ResourceType(resource_type_mapping.get(resource_type_str, ResourceType.OTHER)),
            service_type=ServiceType(service_mapping.get(service, ServiceType.MANAGEMENT)),
            finding_type=aws_finding['finding_type'],
            severity=Severity(aws_finding['severity']),
            description=aws_finding['description'],
            remediation=aws_finding['remediation'],
            evidence={
                'provider_service': service,
                'resource_type': resource_type_str,
                'original_timestamp': aws_finding['timestamp']
            },
            timestamp=datetime.now().isoformat(),
            last_updated=datetime.now().isoformat()
        )
        
        return normalized
    
    def normalize_aws_resource(self, aws_resource: Dict[str, Any], provider: str = 'aws', account_id: str = 'unknown') -> NormalizedResource:
        """Normalize AWS resource"""
        
        service_mapping = {
            'ec2': ServiceType.COMPUTE,
            's3': ServiceType.STORAGE,
            'rds': ServiceType.DATABASE,
            'iam': ServiceType.SECURITY,
            'vpc': ServiceType.NETWORK
        }
        
        resource_type_mapping = {
            'EC2-Instance': ResourceType.VIRTUAL_MACHINE,
            'S3-Bucket': ResourceType.OBJECT_STORAGE,
            'RDS-Instance': ResourceType.DATABASE,
            'SecurityGroup': ResourceType.FIREWALL,
            'IAM-User': ResourceType.IAM_USER
        }
        
        service = aws_resource.get('service', 'other').lower()
        resource_type_str = aws_resource.get('resource_type', 'Other')
        
        # Extract tags from configuration if available
        tags = aws_resource.get('configuration', {}).get('Tags', {})
        if isinstance(tags, list):
            tags = {tag.get('Key'): tag.get('Value') for tag in tags}
        
        normalized = NormalizedResource(
            resource_id=aws_resource['resource_id'],
            provider=provider,
            resource_type=ResourceType(resource_type_mapping.get(resource_type_str, ResourceType.OTHER)),
            service_type=ServiceType(service_mapping.get(service, ServiceType.MANAGEMENT)),
            name=aws_resource.get('resource_id', 'unknown'),
            region=aws_resource.get('region', 'unknown'),
            account_id=account_id,
            tags=tags,
            configuration=aws_resource.get('configuration', {}),
            timestamp=datetime.now().isoformat()
        )
        
        return normalized
    
    # ============================================
    # BATCH PROCESSING
    # ============================================
    
    def normalize_aws_audit_result(self, audit_result: Dict[str, Any], account_id: str = 'unknown'):
        """Normalize complete AWS audit result"""
        logger.info("Normalizing AWS audit result...")
        
        # Normalize findings
        for finding in audit_result.get('findings', []):
            normalized_finding = self.normalize_aws_finding(finding)
            self.normalized_findings.append(normalized_finding)
        
        # Normalize resources
        for resource in audit_result.get('resources', []):
            normalized_resource = self.normalize_aws_resource(resource, account_id=account_id)
            self.normalized_resources.append(normalized_resource)
        
        logger.info(f"✅ Normalized {len(self.normalized_findings)} findings and {len(self.normalized_resources)} resources")
    
    # ============================================
    # VALIDATION
    # ============================================
    
    def validate_normalized_finding(self, finding: NormalizedFinding) -> bool:
        """Validate normalized finding"""
        required_fields = [
            'finding_id', 'provider', 'resource_id', 'resource_type',
            'service_type', 'finding_type', 'severity', 'description',
            'remediation', 'timestamp'
        ]
        
        for field in required_fields:
            if getattr(finding, field, None) is None:
                logger.error(f"Validation failed: Missing field {field}")
                return False
        
        return True
    
    def validate_normalized_resource(self, resource: NormalizedResource) -> bool:
        """Validate normalized resource"""
        required_fields = [
            'resource_id', 'provider', 'resource_type', 'service_type',
            'name', 'region', 'account_id', 'timestamp'
        ]
        
        for field in required_fields:
            if getattr(resource, field, None) is None:
                logger.error(f"Validation failed: Missing field {field}")
                return False
        
        return True
    
    # ============================================
    # DATA QUALITY CHECKS
    # ============================================
    
    def check_data_quality(self) -> Dict[str, Any]:
        """Perform data quality checks"""
        logger.info("Performing data quality checks...")
        
        issues = {
            'invalid_findings': [],
            'invalid_resources': [],
            'duplicate_findings': [],
            'duplicate_resources': [],
            'missing_mappings': []
        }
        
        # Validate all findings
        for finding in self.normalized_findings:
            if not self.validate_normalized_finding(finding):
                issues['invalid_findings'].append(finding.finding_id)
        
        # Validate all resources
        for resource in self.normalized_resources:
            if not self.validate_normalized_resource(resource):
                issues['invalid_resources'].append(resource.resource_id)
        
        # Check for duplicates
        finding_ids = set()
        for finding in self.normalized_findings:
            if finding.finding_id in finding_ids:
                issues['duplicate_findings'].append(finding.finding_id)
            finding_ids.add(finding.finding_id)
        
        resource_ids = set()
        for resource in self.normalized_resources:
            key = f"{resource.provider}_{resource.resource_id}"
            if key in resource_ids:
                issues['duplicate_resources'].append(resource.resource_id)
            resource_ids.add(key)
        
        logger.info(f"Data quality check complete. Issues: {sum(len(v) for v in issues.values())}")
        return issues
    
    # ============================================
    # EXPORT
    # ============================================
    
    def export_normalized_data(self, filepath_findings: str = 'normalized_findings.json', filepath_resources: str = 'normalized_resources.json'):
        """Export normalized data to JSON"""
        
        # Validate data
        quality_issues = self.check_data_quality()
        
        # Export findings
        findings_data = {
            'timestamp': datetime.now().isoformat(),
            'count': len(self.normalized_findings),
            'quality_issues': quality_issues['invalid_findings'],
            'findings': [f.to_dict() for f in self.normalized_findings]
        }
        
        with open(filepath_findings, 'w') as f:
            json.dump(findings_data, f, indent=2)
        logger.info(f"Exported {len(self.normalized_findings)} findings to {filepath_findings}")
        
        # Export resources
        resources_data = {
            'timestamp': datetime.now().isoformat(),
            'count': len(self.normalized_resources),
            'quality_issues': quality_issues['invalid_resources'],
            'resources': [r.to_dict() for r in self.normalized_resources]
        }
        
        with open(filepath_resources, 'w') as f:
            json.dump(resources_data, f, indent=2)
        logger.info(f"Exported {len(self.normalized_resources)} resources to {filepath_resources}")
    
    # ============================================
    # STATISTICS
    # ============================================
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics on normalized data"""
        
        severity_counts = {}
        for finding in self.normalized_findings:
            severity = finding.severity.value
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        service_counts = {}
        for resource in self.normalized_resources:
            service = resource.service_type.value
            service_counts[service] = service_counts.get(service, 0) + 1
        
        provider_counts = {}
        for resource in self.normalized_resources:
            provider = resource.provider
            provider_counts[provider] = provider_counts.get(provider, 0) + 1
        
        return {
            'total_findings': len(self.normalized_findings),
            'total_resources': len(self.normalized_resources),
            'findings_by_severity': severity_counts,
            'resources_by_service': service_counts,
            'resources_by_provider': provider_counts
        }


if __name__ == "__main__":
    # Example usage
    normalizer = DataNormalizer()
    
    # Load and normalize AWS audit result
    with open('aws_audit.json', 'r') as f:
        aws_audit = json.load(f)
    
    normalizer.normalize_aws_audit_result(aws_audit, account_id='123456789')
    
    # Export normalized data
    normalizer.export_normalized_data()
    
    # Print statistics
    stats = normalizer.get_statistics()
    print("\n" + "=" * 70)
    print("NORMALIZATION STATISTICS")
    print("=" * 70)
    for key, value in stats.items():
        print(f"{key}: {value}")
