"""
GovernX Week 3 - Organizational Policy Engine (Person 1: Backend Lead)

Parses corporate governance security policies, maps them to technical controls
(NIST CSF 2.0 Govern Function GV.PO: Policy), and evaluates cloud misconfigurations
against organizational compliance mandates.
"""

import json
import logging
from dataclasses import dataclass, asdict
from datetime import date
from typing import Dict, List, Any, Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class PolicyRule:
    """Individual rule within an organizational security policy"""
    rule_id: str
    title: str
    description: str
    mandatory: bool
    target_service: str            # 'ec2', 's3', 'rds', 'iam', 'vpc', 'all'
    target_finding_type: str       # Finding type from cloud scanner that breaches this
    csf_ref: str                   # NIST CSF 2.0 subcategory (e.g., GV.PO-01, PR.DS-01)
    severity: str                  # CRITICAL, HIGH, MEDIUM, LOW


@dataclass
class PolicyDocument:
    """Enterprise policy document specification"""
    policy_id: str
    title: str
    category: str                  # Governance, Access Control, Data Protection, etc.
    version: str
    effective_date: str
    review_date: str
    status: str                    # Active, Pending Review, Deprecated
    owner: str                     # Responsible stakeholder role (e.g., CISO, DPO)
    rules: List[PolicyRule]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PolicyViolation:
    """Recorded violation of an enterprise policy rule by a cloud asset"""
    violation_id: str
    policy_id: str
    policy_title: str
    rule_id: str
    resource_id: str
    service: str
    severity: str
    csf_ref: str
    details: str
    remediation_required: str
    detected_at: str


def get_default_policies() -> List[PolicyDocument]:
    """Seed enterprise organizational policies mapped to NIST CSF 2.0"""
    return [
        PolicyDocument(
            policy_id="POL-GOV-001",
            title="Enterprise Cloud Data Protection & Encryption Policy",
            category="Data Protection",
            version="2.1.0",
            effective_date="2026-01-15",
            review_date="2027-01-15",
            status="Active",
            owner="Chief Information Security Officer (CISO)",
            rules=[
                PolicyRule(
                    rule_id="RULE-DP-01",
                    title="Mandatory At-Rest Storage Encryption",
                    description="All persistent block volumes (EBS) and database instances (RDS) must employ KMS encryption at rest.",
                    mandatory=True,
                    target_service="ec2",
                    target_finding_type="Unencrypted-Volume",
                    csf_ref="GV.PO-01",
                    severity="HIGH"
                ),
                PolicyRule(
                    rule_id="RULE-DP-02",
                    title="Relational Database Encryption at Rest",
                    description="Production RDS databases storing customer or corporate data must be encrypted.",
                    mandatory=True,
                    target_service="rds",
                    target_finding_type="Encryption-Disabled",
                    csf_ref="GV.PO-01",
                    severity="CRITICAL"
                ),
                PolicyRule(
                    rule_id="RULE-DP-03",
                    title="Object Storage Bucket Encryption",
                    description="All S3 object storage buckets must enforce default server-side encryption.",
                    mandatory=True,
                    target_service="s3",
                    target_finding_type="Encryption-Disabled",
                    csf_ref="GV.PO-02",
                    severity="HIGH"
                )
            ]
        ),
        PolicyDocument(
            policy_id="POL-GOV-002",
            title="Public Cloud Perimeter & Exposure Control Policy",
            category="Network Security",
            version="1.4.0",
            effective_date="2026-02-01",
            review_date="2027-02-01",
            status="Active",
            owner="Cloud Security Architect",
            rules=[
                PolicyRule(
                    rule_id="RULE-EXP-01",
                    title="S3 Public Access Block Requirement",
                    description="Public write or read permissions on cloud buckets are strictly prohibited without documented executive approval.",
                    mandatory=True,
                    target_service="s3",
                    target_finding_type="Public-Access-Allowed",
                    csf_ref="GV.PO-01",
                    severity="CRITICAL"
                ),
                PolicyRule(
                    rule_id="RULE-EXP-02",
                    title="Database Public Exposure Prohibition",
                    description="Database endpoints must reside strictly within private subnets with no public IPv4 routing.",
                    mandatory=True,
                    target_service="rds",
                    target_finding_type="Publicly-Accessible",
                    csf_ref="GV.PO-02",
                    severity="CRITICAL"
                ),
                PolicyRule(
                    rule_id="RULE-EXP-03",
                    title="Administrative Port Exposure Ingress Restriction",
                    description="Administrative protocols (SSH port 22, RDP port 3389) must not be accessible to 0.0.0.0/0.",
                    mandatory=True,
                    target_service="vpc",
                    target_finding_type="Open-Port-22",
                    csf_ref="GV.PO-01",
                    severity="HIGH"
                )
            ]
        ),
        PolicyDocument(
            policy_id="POL-GOV-003",
            title="Identity Governance and Credential Management Policy",
            category="Identity & Access Management",
            version="3.0.0",
            effective_date="2026-01-01",
            review_date="2026-12-31",
            status="Active",
            owner="Identity & SecOps Lead",
            rules=[
                PolicyRule(
                    rule_id="RULE-IAM-01",
                    title="Multi-Factor Authentication Mandate",
                    description="All interactive user accounts with console access must enforce MFA hardware/software tokens.",
                    mandatory=True,
                    target_service="iam",
                    target_finding_type="No-MFA",
                    csf_ref="GV.PO-01",
                    severity="HIGH"
                ),
                PolicyRule(
                    rule_id="RULE-IAM-02",
                    title="Access Key Lifecycle & 90-Day Rotation",
                    description="Programmatic access keys must be rotated at minimum every 90 days to mitigate credential leakage.",
                    mandatory=False,
                    target_service="iam",
                    target_finding_type="Old-Access-Key",
                    csf_ref="GV.PO-02",
                    severity="MEDIUM"
                )
            ]
        ),
        PolicyDocument(
            policy_id="POL-GOV-004",
            title="Business Continuity & Data Resilience Policy",
            category="Resilience & Recovery",
            version="1.2.0",
            effective_date="2026-03-10",
            review_date="2027-03-10",
            status="Active",
            owner="Director of IT Infrastructure",
            rules=[
                PolicyRule(
                    rule_id="RULE-RES-01",
                    title="Database Multi-AZ High Availability Requirement",
                    description="Tier-1 production database clusters must configure Multi-AZ failover replicas.",
                    mandatory=True,
                    target_service="rds",
                    target_finding_type="No-Multi-AZ",
                    csf_ref="GV.PO-01",
                    severity="MEDIUM"
                ),
                PolicyRule(
                    rule_id="RULE-RES-02",
                    title="Automated Backup Retention Minimum",
                    description="Automated snapshot retention for databases must meet or exceed 7 days retention.",
                    mandatory=True,
                    target_service="rds",
                    target_finding_type="Low-Backup-Retention",
                    csf_ref="GV.PO-02",
                    severity="MEDIUM"
                ),
                PolicyRule(
                    rule_id="RULE-RES-03",
                    title="Bucket Object Versioning Protection",
                    description="Buckets storing critical records must enable object versioning to protect against accidental overwrite.",
                    mandatory=False,
                    target_service="s3",
                    target_finding_type="Versioning-Disabled",
                    csf_ref="GV.PO-02",
                    severity="MEDIUM"
                )
            ]
        )
    ]


class OrganizationalPolicyEngine:
    """Evaluates cloud infrastructure findings against organizational policies"""

    def __init__(self, policies: Optional[List[PolicyDocument]] = None):
        self.policies = policies or get_default_policies()
        self.violations: List[PolicyViolation] = []
        logger.info(f"Organizational Policy Engine initialized with {len(self.policies)} policies")

    def evaluate_findings(self, findings: List[Dict[str, Any]]) -> List[PolicyViolation]:
        """Cross-reference cloud scanner findings against active organizational policy rules"""
        self.violations.clear()

        # Build index of rules: (service, finding_type) -> list of (policy, rule)
        rule_index = {}
        for pol in self.policies:
            if pol.status != "Active":
                continue
            for r in pol.rules:
                key = (r.target_service.lower(), r.target_finding_type.lower())
                rule_index.setdefault(key, []).append((pol, r))

        for f in findings:
            svc = f.get('service', '').lower()
            ftype = f.get('finding_type', '').lower()
            res_id = f.get('resource_id', 'unknown')

            matched = rule_index.get((svc, ftype), [])
            for pol, rule in matched:
                violation = PolicyViolation(
                    violation_id=f"VIOL-{rule.rule_id}-{res_id[:12]}",
                    policy_id=pol.policy_id,
                    policy_title=pol.title,
                    rule_id=rule.rule_id,
                    resource_id=res_id,
                    service=svc,
                    severity=rule.severity,
                    csf_ref=rule.csf_ref,
                    details=f.get('description', rule.description),
                    remediation_required=f.get('remediation', 'Align asset configuration with policy requirement'),
                    detected_at=date.today().isoformat()
                )
                self.violations.append(violation)

        logger.info(f"Policy evaluation complete: Identified {len(self.violations)} policy violations")
        return self.violations

    def get_compliance_summary(self) -> Dict[str, Any]:
        """Generate high-level compliance scorecard across all organizational policies"""
        total_rules = sum(len(p.rules) for p in self.policies)
        violated_rule_ids = {v.rule_id for v in self.violations}
        violated_policy_ids = {v.policy_id for v in self.violations}

        policy_summaries = []
        for p in self.policies:
            p_rules = len(p.rules)
            p_violations = [v for v in self.violations if v.policy_id == p.policy_id]
            p_violated_rules = len({v.rule_id for v in p_violations})
            p_score = round(((p_rules - p_violated_rules) / p_rules * 100), 1) if p_rules else 100.0

            policy_summaries.append({
                "policy_id": p.policy_id,
                "title": p.title,
                "category": p.category,
                "owner": p.owner,
                "total_rules": p_rules,
                "violations_count": len(p_violations),
                "compliance_score": p_score,
                "status": "COMPLIANT" if len(p_violations) == 0 else "NON_COMPLIANT"
            })

        overall_score = round(((total_rules - len(violated_rule_ids)) / total_rules * 100), 1) if total_rules else 100.0

        by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for v in self.violations:
            by_severity[v.severity] = by_severity.get(v.severity, 0) + 1

        return {
            "total_policies": len(self.policies),
            "compliant_policies": len(self.policies) - len(violated_policy_ids),
            "non_compliant_policies": len(violated_policy_ids),
            "total_rules": total_rules,
            "violated_rules": len(violated_rule_ids),
            "overall_policy_compliance_score": overall_score,
            "violations_by_severity": by_severity,
            "total_violations": len(self.violations),
            "policy_breakdown": policy_summaries
        }


if __name__ == "__main__":
    engine = OrganizationalPolicyEngine()

    # Simulate sample findings from week 1 audit
    sample_findings = [
        {"service": "ec2", "finding_type": "Unencrypted-Volume", "resource_id": "i-09ab12cd", "severity": "HIGH"},
        {"service": "rds", "finding_type": "Encryption-Disabled", "resource_id": "prod-db-01", "severity": "CRITICAL"},
        {"service": "s3", "finding_type": "Public-Access-Allowed", "resource_id": "customer-data-bucket", "severity": "CRITICAL"},
        {"service": "iam", "finding_type": "No-MFA", "resource_id": "admin-user", "severity": "HIGH"},
    ]

    violations = engine.evaluate_findings(sample_findings)
    summary = engine.get_compliance_summary()

    print(f"\n[POLICY ENGINE] Total Policies: {summary['total_policies']} | Overall Score: {summary['overall_policy_compliance_score']}%")
    print(f"[VIOLATIONS] Total Identified: {summary['total_violations']}")
    for p in summary['policy_breakdown']:
        print(f"  {p['policy_id']}: {p['title'][:35]:<35} Score: {p['compliance_score']:>5}% [{p['status']}]")
