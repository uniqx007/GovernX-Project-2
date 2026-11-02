"""
GovernX Week 3 - Stakeholder Registry & Escalation Engine (Person 1: Backend Lead)

Manages risk ownership, accountable security stakeholders, SLA escalation matrices,
and automated notification routing in compliance with NIST CSF 2.0 GV.RR
(Roles, Responsibilities, and Authorities).
"""

import json
import logging
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Dict, List, Any, Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class Stakeholder:
    """Enterprise risk owner or technical contact"""
    stakeholder_id: str
    name: str
    title: str
    department: str
    email: str
    phone: str
    assigned_domains: List[str]     # 'ec2', 's3', 'rds', 'iam', 'vpc', 'supply_chain', 'policies'
    notification_tier: str         # 'IMMEDIATE', 'DAILY_DIGEST', 'CRITICAL_ONLY'
    active: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EscalationLevel:
    """Escalation tier with SLA and contact chain"""
    severity: str                  # CRITICAL, HIGH, MEDIUM, LOW
    sla_hours: int                 # Response SLA in hours
    primary_role: str
    secondary_role: str
    tertiary_role: str
    notification_channel: str      # 'SMS + PagerDuty', 'Email + Slack', 'Jira Ticket'
    csf_ref: str                   # GV.RR-02, RS.CO-02


@dataclass
class DispatchedAlert:
    """Log record of notification dispatched to risk owner"""
    alert_id: str
    finding_id: str
    resource_id: str
    service: str
    severity: str
    assigned_stakeholder: str
    email: str
    sla_deadline: str
    dispatched_at: str


def get_default_stakeholders() -> List[Stakeholder]:
    """Predefined organizational security stakeholders across cloud & GRC domains"""
    return [
        Stakeholder(
            stakeholder_id="STK-001",
            name="Sarah Jenkins",
            title="Chief Information Security Officer (CISO)",
            department="Information Security",
            email="ciso@governx.internal",
            phone="+1-555-0100",
            assigned_domains=["all", "policies", "governance"],
            notification_tier="CRITICAL_ONLY"
        ),
        Stakeholder(
            stakeholder_id="STK-002",
            name="Alex Rivera",
            title="Lead Cloud Security Architect",
            department="Cloud Infrastructure & SecOps",
            email="alex.rivera@governx.internal",
            phone="+1-555-0102",
            assigned_domains=["ec2", "s3", "vpc"],
            notification_tier="IMMEDIATE"
        ),
        Stakeholder(
            stakeholder_id="STK-003",
            name="Priya Sharma",
            title="Principal Database Administrator",
            department="Data Platform Engineering",
            email="priya.sharma@governx.internal",
            phone="+1-555-0103",
            assigned_domains=["rds"],
            notification_tier="IMMEDIATE"
        ),
        Stakeholder(
            stakeholder_id="STK-004",
            name="David Chen",
            title="IAM & Identity Governance Lead",
            department="Identity Security",
            email="david.chen@governx.internal",
            phone="+1-555-0104",
            assigned_domains=["iam"],
            notification_tier="IMMEDIATE"
        ),
        Stakeholder(
            stakeholder_id="STK-005",
            name="Marcus Vance",
            title="Director of Vendor & Supply Chain Risk",
            department="Procurement & Third-Party Risk",
            email="marcus.vance@governx.internal",
            phone="+1-555-0105",
            assigned_domains=["supply_chain"],
            notification_tier="DAILY_DIGEST"
        )
    ]


def get_default_escalation_matrix() -> List[EscalationLevel]:
    """Organizational SLA escalation tiers mapped to finding severity"""
    return [
        EscalationLevel(
            severity="CRITICAL",
            sla_hours=4,
            primary_role="Domain Specialist",
            secondary_role="Lead Cloud Architect",
            tertiary_role="Chief Information Security Officer (CISO)",
            notification_channel="SMS + PagerDuty (24/7)",
            csf_ref="GV.RR-02"
        ),
        EscalationLevel(
            severity="HIGH",
            sla_hours=24,
            primary_role="Domain Specialist",
            secondary_role="Lead Cloud Architect",
            tertiary_role="Director of SecOps",
            notification_channel="Slack #security-ops + Email Alert",
            csf_ref="GV.RR-02"
        ),
        EscalationLevel(
            severity="MEDIUM",
            sla_hours=72,
            primary_role="Domain Specialist",
            secondary_role="Team Lead",
            tertiary_role="None",
            notification_channel="Jira Security Backlog + Daily Digest",
            csf_ref="GV.RR-01"
        ),
        EscalationLevel(
            severity="LOW",
            sla_hours=168,  # 7 days
            primary_role="Domain Specialist",
            secondary_role="None",
            tertiary_role="None",
            notification_channel="Weekly Sprint Review",
            csf_ref="GV.RR-01"
        )
    ]


class StakeholderRegistry:
    """Orchestrates risk ownership assignment and incident escalation"""

    def __init__(self, stakeholders: Optional[List[Stakeholder]] = None):
        self.stakeholders = stakeholders or get_default_stakeholders()
        self.escalations = get_default_escalation_matrix()
        self.dispatched_alerts: List[DispatchedAlert] = []
        logger.info(f"Stakeholder Registry initialized with {len(self.stakeholders)} stakeholders")

    def find_owner_for_service(self, service: str) -> Stakeholder:
        """Assign accountability for a specific cloud or governance service"""
        service_lower = service.lower()
        for s in self.stakeholders:
            if service_lower in s.assigned_domains and s.active:
                return s

        # Fallback to CISO if unassigned
        return next((s for s in self.stakeholders if s.stakeholder_id == "STK-001"), self.stakeholders[0])

    def get_escalation_policy(self, severity: str) -> Optional[EscalationLevel]:
        """Lookup SLA escalation details for given finding severity"""
        return next((e for e in self.escalations if e.severity.upper() == severity.upper()), None)

    def route_finding_alert(self, finding: Dict[str, Any]) -> DispatchedAlert:
        """Route security finding to assigned stakeholder with SLA response deadline"""
        svc = finding.get('service', 'unknown')
        sev = finding.get('severity', 'MEDIUM')
        res_id = finding.get('resource_id', 'unknown')
        finding_id = finding.get('finding_id', f"f-{res_id[:8]}")

        owner = self.find_owner_for_service(svc)
        esc = self.get_escalation_policy(sev)
        sla_hours = esc.sla_hours if esc else 24

        alert = DispatchedAlert(
            alert_id=f"ALT-{len(self.dispatched_alerts) + 1:04d}",
            finding_id=finding_id,
            resource_id=res_id,
            service=svc,
            severity=sev,
            assigned_stakeholder=f"{owner.name} ({owner.title})",
            email=owner.email,
            sla_deadline=f"Within {sla_hours} hour(s)",
            dispatched_at=datetime.now().isoformat()
        )
        self.dispatched_alerts.append(alert)
        logger.info(f"Routed {sev} finding {res_id} on {svc} -> {owner.name} [SLA: {sla_hours}h]")
        return alert

    def get_registry_summary(self) -> Dict[str, Any]:
        """Export registry posture and escalation rules for executive view"""
        return {
            "total_stakeholders": len(self.stakeholders),
            "stakeholders": [asdict(s) for s in self.stakeholders],
            "escalation_matrix": [asdict(e) for e in self.escalations],
            "total_dispatched_alerts": len(self.dispatched_alerts),
            "recent_alerts": [asdict(a) for a in self.dispatched_alerts[-10:]]
        }


if __name__ == "__main__":
    registry = StakeholderRegistry()
    sample_finding = {
        "finding_id": "FIND-RDS-001",
        "resource_id": "prod-customer-db",
        "service": "rds",
        "severity": "CRITICAL"
    }

    alert = registry.route_finding_alert(sample_finding)
    summary = registry.get_registry_summary()

    print(f"\n[STAKEHOLDER REGISTRY] Registered Owners: {summary['total_stakeholders']}")
    print(f"[ALERT ROUTED] {alert.alert_id} | Resource: {alert.resource_id}")
    print(f"  Assigned: {alert.assigned_stakeholder}")
    print(f"  Email: {alert.email} | SLA: {alert.sla_deadline}")
