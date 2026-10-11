"""
GovernX: Finding Aggregator - Aggregate and deduplicate findings
Combine findings from multiple clouds and audit runs
"""

import logging
import json
from typing import Dict, List, Any, Optional, Set
from datetime import datetime
from dataclasses import dataclass, asdict
from collections import defaultdict
import hashlib

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ============================================
# AGGREGATED FINDING MODEL
# ============================================

@dataclass
class AggregatedFinding:
    """Deduplicated finding from multiple sources"""
    finding_id: str  # Unique hash
    resource_id: str
    resource_type: str
    finding_type: str
    severity: str
    service: str
    description: str
    remediation: str
    
    # Aggregation metadata
    first_seen: str
    last_seen: str
    occurrence_count: int
    sources: List[str]  # Which providers/audits found this
    
    def to_dict(self) -> Dict:
        return asdict(self)


# ============================================
# FINDING AGGREGATOR
# ============================================

class FindingAggregator:
    """Aggregate findings from multiple sources"""
    
    def __init__(self):
        self.findings: Dict[str, AggregatedFinding] = {}  # finding_id -> AggregatedFinding
        self.raw_findings: List[Dict[str, Any]] = []
        self.deduplication_map: Dict[str, str] = {}  # Source finding -> aggregated finding ID
        logger.info("Finding aggregator initialized")
    
    def generate_finding_hash(self, finding: Dict[str, Any]) -> str:
        """Generate unique hash for finding"""
        # Hash based on: resource_id + finding_type + service
        key = f"{finding['resource_id']}_{finding['finding_type']}_{finding['service']}"
        return hashlib.md5(key.encode()).hexdigest()[:12]
    
    def add_finding(self, finding: Dict[str, Any], source: str = 'unknown') -> str:
        """Add a finding from any source"""
        finding_hash = self.generate_finding_hash(finding)
        
        self.raw_findings.append({
            'source': source,
            'timestamp': datetime.now().isoformat(),
            'finding': finding
        })
        
        if finding_hash not in self.findings:
            # New finding
            aggregated = AggregatedFinding(
                finding_id=finding_hash,
                resource_id=finding['resource_id'],
                resource_type=finding.get('resource_type', 'Unknown'),
                finding_type=finding.get('finding_type', 'Unknown'),
                severity=finding.get('severity', 'UNKNOWN'),
                service=finding.get('service', 'unknown'),
                description=finding.get('description', ''),
                remediation=finding.get('remediation', ''),
                first_seen=datetime.now().isoformat(),
                last_seen=datetime.now().isoformat(),
                occurrence_count=1,
                sources=[source]
            )
            self.findings[finding_hash] = aggregated
            logger.info(f"New finding: {finding_hash}")
        else:
            # Duplicate - update
            existing = self.findings[finding_hash]
            existing.last_seen = datetime.now().isoformat()
            existing.occurrence_count += 1
            if source not in existing.sources:
                existing.sources.append(source)
            logger.info(f"Duplicate finding: {finding_hash} (count: {existing.occurrence_count})")
        
        self.deduplication_map[f"{source}_{finding_hash}"] = finding_hash
        return finding_hash
    
    def add_findings_batch(self, findings: List[Dict[str, Any]], source: str = 'unknown'):
        """Add multiple findings from same source"""
        logger.info(f"Adding {len(findings)} findings from {source}")
        for finding in findings:
            self.add_finding(finding, source=source)
    
    def add_findings_from_audit_result(self, audit_result: Dict[str, Any], provider: str = 'unknown'):
        """Add all findings from an audit result"""
        findings = audit_result.get('findings', [])
        source = f"{provider}_{audit_result.get('timestamp', 'unknown')}"
        self.add_findings_batch(findings, source=source)
    
    def get_all_findings(self) -> List[AggregatedFinding]:
        """Get all aggregated findings"""
        return list(self.findings.values())
    
    def get_findings_by_severity(self, severity: str) -> List[AggregatedFinding]:
        """Get findings by severity"""
        return [f for f in self.findings.values() if f.severity == severity]
    
    def get_findings_by_service(self, service: str) -> List[AggregatedFinding]:
        """Get findings by service"""
        return [f for f in self.findings.values() if f.service == service]
    
    def get_findings_by_source(self, source: str) -> List[AggregatedFinding]:
        """Get findings from specific source"""
        return [f for f in self.findings.values() if source in f.sources]
    
    def get_duplicate_findings(self) -> List[AggregatedFinding]:
        """Get findings that occurred multiple times"""
        return [f for f in self.findings.values() if f.occurrence_count > 1]
    
    def get_new_findings(self, since_timestamp: str) -> List[AggregatedFinding]:
        """Get findings first seen after timestamp"""
        since_dt = datetime.fromisoformat(since_timestamp)
        return [f for f in self.findings.values() if datetime.fromisoformat(f.first_seen) > since_dt]
    
    # ============================================
    # DUPLICATE DETECTION
    # ============================================
    
    def detect_duplicates(self, finding1: Dict[str, Any], finding2: Dict[str, Any]) -> bool:
        """Detect if two findings are duplicates"""
        # Same resource, finding type, and service = duplicate
        same_resource = finding1['resource_id'] == finding2['resource_id']
        same_type = finding1['finding_type'] == finding2['finding_type']
        same_service = finding1.get('service', '') == finding2.get('service', '')
        
        return same_resource and same_type and same_service
    
    def merge_findings(self, finding_id: str) -> Optional[AggregatedFinding]:
        """Merge duplicate findings"""
        if finding_id not in self.findings:
            return None
        
        finding = self.findings[finding_id]
        
        # Update timestamps and sources
        finding.last_seen = datetime.now().isoformat()
        
        return finding
    
    # ============================================
    # ENRICHMENT
    # ============================================
    
    def enrich_finding_with_context(self, finding_id: str, context: Dict[str, Any]) -> bool:
        """Add context to a finding"""
        if finding_id not in self.findings:
            return False
        
        # Add context to finding metadata
        self.findings[finding_id].context = context
        return True
    
    # ============================================
    # STATISTICS
    # ============================================
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get aggregation statistics"""
        all_findings = self.get_all_findings()
        
        # Count by severity
        severity_counts = defaultdict(int)
        for finding in all_findings:
            severity_counts[finding.severity] += 1
        
        # Count by service
        service_counts = defaultdict(int)
        for finding in all_findings:
            service_counts[finding.service] += 1
        
        # Count by source
        source_counts = defaultdict(int)
        for finding in all_findings:
            for source in finding.sources:
                source_counts[source] += 1
        
        # Calculate totals
        total_occurrences = sum(f.occurrence_count for f in all_findings)
        
        return {
            'total_unique_findings': len(all_findings),
            'total_occurrences': total_occurrences,
            'duplicate_findings': len(self.get_duplicate_findings()),
            'findings_by_severity': dict(severity_counts),
            'findings_by_service': dict(service_counts),
            'findings_by_source': dict(source_counts),
            'avg_occurrences_per_finding': total_occurrences / len(all_findings) if all_findings else 0
        }
    
    # ============================================
    # DEDUPLICATION VALIDATION
    # ============================================
    
    def validate_deduplication(self) -> Dict[str, Any]:
        """Validate deduplication logic"""
        validation_results = {
            'total_raw_findings': len(self.raw_findings),
            'total_unique_findings': len(self.findings),
            'total_occurrences': sum(f.occurrence_count for f in self.findings.values()),
            'deduplication_ratio': 0.0,
            'issues': []
        }
        
        # Calculate deduplication ratio
        if self.raw_findings:
            unique = len(self.findings)
            raw = len(self.raw_findings)
            validation_results['deduplication_ratio'] = (1 - (unique / raw)) * 100
        
        # Validate occurrence counts
        total_occurrences = sum(f.occurrence_count for f in self.findings.values())
        if total_occurrences != len(self.raw_findings):
            validation_results['issues'].append(
                f"Occurrence count mismatch: {total_occurrences} vs {len(self.raw_findings)}"
            )
        
        return validation_results
    
    # ============================================
    # EXPORT & REPORTING
    # ============================================
    
    def export_aggregated_findings(self, filepath: str = 'aggregated_findings.json'):
        """Export aggregated findings to JSON"""
        findings_data = {
            'timestamp': datetime.now().isoformat(),
            'total_findings': len(self.findings),
            'statistics': self.get_statistics(),
            'findings': [f.to_dict() for f in self.findings.values()]
        }
        
        with open(filepath, 'w') as f:
            json.dump(findings_data, f, indent=2)
        
        logger.info(f"Exported aggregated findings to: {filepath}")
    
    def export_raw_findings(self, filepath: str = 'raw_findings.json'):
        """Export all raw findings (before deduplication)"""
        data = {
            'timestamp': datetime.now().isoformat(),
            'total_raw_findings': len(self.raw_findings),
            'findings': self.raw_findings
        }
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        
        logger.info(f"Exported raw findings to: {filepath}")
    
    def generate_deduplication_report(self, filepath: str = 'deduplication_report.json'):
        """Generate deduplication report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'validation': self.validate_deduplication(),
            'statistics': self.get_statistics(),
            'duplicates': [f.to_dict() for f in self.get_duplicate_findings()]
        }
        
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Generated deduplication report: {filepath}")
    
    def print_summary(self):
        """Print aggregation summary"""
        stats = self.get_statistics()
        
        logger.info("=" * 70)
        logger.info("FINDING AGGREGATION SUMMARY")
        logger.info("=" * 70)
        logger.info(f"Raw Findings: {len(self.raw_findings)}")
        logger.info(f"Unique Findings: {stats['total_unique_findings']}")
        logger.info(f"Total Occurrences: {stats['total_occurrences']}")
        logger.info(f"Deduplication Ratio: {(1 - stats['total_unique_findings']/len(self.raw_findings))*100:.1f}%" if self.raw_findings else "N/A")
        logger.info("")
        logger.info("By Severity:")
        for severity, count in sorted(stats['findings_by_severity'].items()):
            logger.info(f"  {severity}: {count}")
        logger.info("")
        logger.info("By Service:")
        for service, count in sorted(stats['findings_by_service'].items()):
            logger.info(f"  {service}: {count}")
        logger.info("=" * 70)


if __name__ == "__main__":
    # Example usage
    aggregator = FindingAggregator()
    
    # Simulate findings from AWS audit 1
    aws_findings_1 = [
        {
            'resource_id': 'i-12345',
            'resource_type': 'EC2-Instance',
            'finding_type': 'IMDSv1-Enabled',
            'severity': 'MEDIUM',
            'service': 'ec2',
            'description': 'EC2 instance does not require IMDSv2',
            'remediation': 'Enable IMDSv2'
        },
        {
            'resource_id': 'bucket-prod',
            'resource_type': 'S3-Bucket',
            'finding_type': 'Public-Access-Allowed',
            'severity': 'CRITICAL',
            'service': 's3',
            'description': 'S3 bucket allows public access',
            'remediation': 'Enable Block Public Access'
        }
    ]
    
    # Simulate findings from AWS audit 2 (with duplicates)
    aws_findings_2 = [
        {
            'resource_id': 'i-12345',
            'resource_type': 'EC2-Instance',
            'finding_type': 'IMDSv1-Enabled',  # Duplicate
            'severity': 'MEDIUM',
            'service': 'ec2',
            'description': 'EC2 instance does not require IMDSv2',
            'remediation': 'Enable IMDSv2'
        },
        {
            'resource_id': 'rds-db-1',
            'resource_type': 'RDS-Instance',
            'finding_type': 'Encryption-Disabled',
            'severity': 'CRITICAL',
            'service': 'rds',
            'description': 'RDS instance does not have encryption',
            'remediation': 'Enable RDS encryption'
        }
    ]
    
    # Add findings
    aggregator.add_findings_batch(aws_findings_1, source='aws_audit_1')
    aggregator.add_findings_batch(aws_findings_2, source='aws_audit_2')
    
    # Print summary
    aggregator.print_summary()
    
    # Export reports
    aggregator.export_aggregated_findings()
    aggregator.export_raw_findings()
    aggregator.generate_deduplication_report()
