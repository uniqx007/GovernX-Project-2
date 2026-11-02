"""
GovernX Week 3 - Governance Data Collector (Person 1: Backend Lead)

Ingests board-level governance parameters, risk appetite thresholds,
strategic business initiatives, and business continuity objectives
to support the NIST CSF 2.0 Govern Function (GV.OC, GV.OV, GV.RM).
"""

import json
import logging
from dataclasses import dataclass, asdict
from datetime import date
from typing import Dict, List, Any, Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class RiskAppetiteThreshold:
    """Enterprise risk appetite statement per domain"""
    category: str                   # Financial, Operational, Regulatory, Reputational
    max_tolerated_loss_usd: float   # Board-approved loss threshold in USD
    residual_risk_usd: float        # Current measured risk from Person 3's engine
    risk_tolerance: str             # LOW, MEDIUM, HIGH
    breach_status: bool             # True if residual > tolerated
    csf_ref: str                    # e.g., GV.RM-01, GV.RM-02


@dataclass
class StrategicInitiative:
    """Strategic organizational projects and their cyber dependencies"""
    initiative_id: str
    name: str
    business_unit: str
    target_completion: str
    criticality: str                # CRITICAL, HIGH, MEDIUM
    cloud_hosted: bool
    cyber_signoff: bool
    data_classification: str        # Highly Confidential, Confidential, Internal, Public


@dataclass
class BusinessContinuityTarget:
    """Tier-1 systems business continuity & disaster recovery parameters"""
    system_name: str
    service_type: str               # Database, API Gateway, Storage, Auth
    rto_hours: float                # Recovery Time Objective
    rpo_hours: float                # Recovery Point Objective
    dr_tested_date: Optional[str]
    backup_encrypted: bool
    csf_ref: str                    # GV.OC-03, RC.RP-01


@dataclass
class BoardGovernanceProfile:
    """Executive & Board oversight summary"""
    organization_name: str
    ciso_name: str
    board_reporting_cycle: str      # Monthly, Quarterly, Bi-Annual
    last_board_review: str
    cyber_insurance_coverage_usd: float
    security_budget_usd: float
    target_nist_tier: str           # Tier 1 (Partial) to Tier 4 (Adaptive)


def get_default_governance_profile() -> BoardGovernanceProfile:
    """Default enterprise board oversight profile"""
    return BoardGovernanceProfile(
        organization_name="GovernX Global Enterprise",
        ciso_name="Sarah Jenkins (CISO)",
        board_reporting_cycle="Quarterly",
        last_board_review="2026-09-15",
        cyber_insurance_coverage_usd=15_000_000.0,
        security_budget_usd=3_500_000.0,
        target_nist_tier="Tier 3 (Repeatable)"
    )


def get_default_risk_appetite() -> List[RiskAppetiteThreshold]:
    """Default enterprise risk appetite thresholds approved by Board"""
    return [
        RiskAppetiteThreshold(
            category="Financial Loss (Direct)",
            max_tolerated_loss_usd=2_000_000.0,
            residual_risk_usd=1_450_000.0,
            risk_tolerance="LOW",
            breach_status=False,
            csf_ref="GV.RM-01"
        ),
        RiskAppetiteThreshold(
            category="Regulatory Sanctions & Fines",
            max_tolerated_loss_usd=1_000_000.0,
            residual_risk_usd=850_000.0,
            risk_tolerance="LOW",
            breach_status=False,
            csf_ref="GV.RM-02"
        ),
        RiskAppetiteThreshold(
            category="Operational Disruption / Cloud Outage",
            max_tolerated_loss_usd=3_000_000.0,
            residual_risk_usd=3_400_000.0,
            risk_tolerance="MEDIUM",
            breach_status=True,     # Alert: exceeds appetite due to Multi-AZ / backup gaps
            csf_ref="GV.OC-03"
        ),
        RiskAppetiteThreshold(
            category="Third-Party Supply Chain Failure",
            max_tolerated_loss_usd=1_500_000.0,
            residual_risk_usd=1_850_000.0,
            risk_tolerance="LOW",
            breach_status=True,     # Alert: exceeds appetite due to vendor gaps
            csf_ref="GV.SC-01"
        )
    ]


def get_default_strategic_initiatives() -> List[StrategicInitiative]:
    """Key digital transformation initiatives dependent on cybersecurity"""
    return [
        StrategicInitiative(
            initiative_id="INIT-2026-01",
            name="Cloud Native Customer Data Platform",
            business_unit="Digital Banking",
            target_completion="2026-12-31",
            criticality="CRITICAL",
            cloud_hosted=True,
            cyber_signoff=True,
            data_classification="Highly Confidential"
        ),
        StrategicInitiative(
            initiative_id="INIT-2026-02",
            name="AI/ML Automated Risk Scoring API",
            business_unit="Core Risk Engine",
            target_completion="2027-03-31",
            criticality="HIGH",
            cloud_hosted=True,
            cyber_signoff=False,
            data_classification="Confidential"
        ),
        StrategicInitiative(
            initiative_id="INIT-2026-03",
            name="Global Vendor Integration Hub",
            business_unit="Supply Chain Operations",
            target_completion="2026-11-30",
            criticality="HIGH",
            cloud_hosted=True,
            cyber_signoff=True,
            data_classification="Confidential"
        )
    ]


def get_default_continuity_targets() -> List[BusinessContinuityTarget]:
    """Continuity and Disaster Recovery benchmarks"""
    return [
        BusinessContinuityTarget(
            system_name="Core Relational DB (RDS Postgres)",
            service_type="Database",
            rto_hours=4.0,
            rpo_hours=1.0,
            dr_tested_date="2026-08-20",
            backup_encrypted=True,
            csf_ref="GV.OC-03"
        ),
        BusinessContinuityTarget(
            system_name="Object Storage Lake (S3 Customer Lake)",
            service_type="Storage",
            rto_hours=2.0,
            rpo_hours=0.5,
            dr_tested_date="2026-07-15",
            backup_encrypted=True,
            csf_ref="GV.OC-03"
        ),
        BusinessContinuityTarget(
            system_name="API Gateway & Auth Token Service",
            service_type="Compute",
            rto_hours=0.5,
            rpo_hours=0.0,
            dr_tested_date="2026-09-01",
            backup_encrypted=True,
            csf_ref="GV.OC-03"
        )
    ]


class GovernanceDataCollector:
    """Collects and organizes board-level governance posture"""

    def __init__(self):
        self.profile = get_default_governance_profile()
        self.risk_appetites = get_default_risk_appetite()
        self.initiatives = get_default_strategic_initiatives()
        self.continuity_targets = get_default_continuity_targets()
        logger.info("Governance Data Collector initialized")

    def update_residual_risk(self, category: str, measured_loss_usd: float):
        """Update measured financial residual risk from Person 3's engine"""
        for item in self.risk_appetites:
            if item.category.lower() == category.lower():
                item.residual_risk_usd = measured_loss_usd
                item.breach_status = item.residual_risk_usd > item.max_tolerated_loss_usd
                logger.info(f"Updated {category} residual risk to ${measured_loss_usd:,.2f} (Breach: {item.breach_status})")

    def get_board_scorecard(self) -> Dict[str, Any]:
        """Aggregate governance metrics for board and executive reporting"""
        total_tolerated = sum(r.max_tolerated_loss_usd for r in self.risk_appetites)
        total_residual = sum(r.residual_risk_usd for r in self.risk_appetites)
        breached_appetites = [r for r in self.risk_appetites if r.breach_status]

        approved_initiatives = [i for i in self.initiatives if i.cyber_signoff]

        return {
            "profile": asdict(self.profile),
            "appetite_summary": {
                "total_tolerated_loss_usd": total_tolerated,
                "total_residual_risk_usd": total_residual,
                "appetite_breach_count": len(breached_appetites),
                "overall_appetite_status": "EXCEEDED" if breached_appetites else "WITHIN_APPETITE",
                "categories": [asdict(r) for r in self.risk_appetites]
            },
            "strategic_alignment": {
                "total_initiatives": len(self.initiatives),
                "signed_off_initiatives": len(approved_initiatives),
                "cyber_alignment_percentage": round(len(approved_initiatives) / len(self.initiatives) * 100, 1) if self.initiatives else 100.0,
                "initiatives": [asdict(i) for i in self.initiatives]
            },
            "business_continuity": {
                "monitored_systems": len(self.continuity_targets),
                "targets": [asdict(t) for t in self.continuity_targets]
            }
        }


if __name__ == "__main__":
    collector = GovernanceDataCollector()
    scorecard = collector.get_board_scorecard()
    print(f"\n[GOVERNANCE SCORECARD] Org: {scorecard['profile']['organization_name']}")
    print(f"CISO: {scorecard['profile']['ciso_name']} | Target: {scorecard['profile']['target_nist_tier']}")
    print(f"Appetite Status: {scorecard['appetite_summary']['overall_appetite_status']} ({scorecard['appetite_summary']['appetite_breach_count']} breach(es))")
    print(f"Total Residual: ${scorecard['appetite_summary']['total_residual_risk_usd']:,.2f} vs Tolerated: ${scorecard['appetite_summary']['total_tolerated_loss_usd']:,.2f}")
    print(f"Initiative Alignment: {scorecard['strategic_alignment']['cyber_alignment_percentage']}%")
