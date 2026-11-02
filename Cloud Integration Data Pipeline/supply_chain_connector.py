"""
GovernX Week 3 - Supply Chain Connector (Person 1)

Third-party / vendor risk data for the CSF 2.0 Govern function (GV.SC).
Vendor inventory is MOCK data (hard-coded below). In production, replace
`load_vendors()` with a call to your GRC / vendor-management system.

NOTE: csf_ref values are provisional - Person 2 should validate them against
the official NIST CSF 2.0 reference.
"""

import json
import logging
from dataclasses import dataclass, asdict
from datetime import date
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

SENSITIVE_CERTS = {"SOC2-TYPE2", "ISO27001"}
CRIT_LEVELS = ("CRITICAL", "HIGH")


@dataclass
class Vendor:
    vendor_id: str
    name: str
    category: str
    criticality: str                 # CRITICAL / HIGH / MEDIUM / LOW
    handles_sensitive_data: bool
    certifications: List[str]
    last_assessment: Optional[str]   # ISO date or None
    has_dpa: bool                    # data processing agreement signed
    open_findings: int
    in_incident_plan: bool
    exit_plan_defined: bool


@dataclass
class VendorAssessment:
    vendor_id: str
    name: str
    criticality: str
    score: int                       # 0-100, higher = safer
    tier: str                        # LOW / MEDIUM / HIGH / CRITICAL risk
    gaps: List[Dict]


def mock_vendors() -> List[Vendor]:
    return [
        Vendor("v-001", "CloudHost Inc", "Infrastructure", "CRITICAL", True,
               ["SOC2-TYPE2", "ISO27001"], "2026-05-10", True, 1, True, True),
        Vendor("v-002", "PayFlow", "Payments", "CRITICAL", True,
               ["SOC2-TYPE2"], "2025-03-01", True, 4, False, False),
        Vendor("v-003", "MailBlast", "Marketing SaaS", "MEDIUM", True,
               [], None, False, 0, False, False),
        Vendor("v-004", "OfficeSuite Co", "Productivity", "HIGH", True,
               ["ISO27001"], "2026-02-20", True, 2, True, True),
        Vendor("v-005", "PrintWorks", "Facilities", "LOW", False,
               [], "2024-11-01", False, 0, False, False),
        Vendor("v-006", "DataLake Analytics", "Analytics", "HIGH", True,
               ["SOC2-TYPE1"], "2026-07-01", True, 3, True, False),
    ]


def assess_vendor(v: Vendor, today: Optional[date] = None) -> VendorAssessment:
    """Score one vendor. Each deduction is recorded as a gap with a CSF ref."""
    today = today or date.today()
    gaps: List[Dict] = []

    def gap(issue: str, penalty: int, ref: str):
        gaps.append({"issue": issue, "penalty": penalty, "csf_ref": ref})

    if v.handles_sensitive_data and not (SENSITIVE_CERTS & set(v.certifications)):
        gap("No SOC2 Type II / ISO27001 despite handling sensitive data", 25, "GV.SC-05")

    if v.last_assessment is None:
        gap("Never assessed", 30, "GV.SC-06")
    elif (today - date.fromisoformat(v.last_assessment)).days > 365:
        gap("Last assessment older than 12 months", 20, "GV.SC-06")

    if v.handles_sensitive_data and not v.has_dpa:
        gap("No data processing agreement", 20, "GV.SC-05")

    if v.open_findings:
        gap(f"{v.open_findings} open security finding(s)", min(15, 3 * v.open_findings), "GV.SC-07")

    if v.criticality in CRIT_LEVELS and not v.in_incident_plan:
        gap("Not included in incident response planning", 10, "GV.SC-08")

    if v.criticality in CRIT_LEVELS and not v.exit_plan_defined:
        gap("No exit / termination plan", 10, "GV.SC-10")

    score = max(0, 100 - sum(g["penalty"] for g in gaps))
    tier = "LOW" if score >= 80 else "MEDIUM" if score >= 60 else "HIGH" if score >= 40 else "CRITICAL"
    return VendorAssessment(v.vendor_id, v.name, v.criticality, score, tier, gaps)


class SupplyChainConnector:
    def __init__(self, vendors: Optional[List[Vendor]] = None):
        self.vendors = vendors if vendors is not None else mock_vendors()

    def load_vendors_from_json(self, path: str):
        with open(path) as f:
            self.vendors = [Vendor(**row) for row in json.load(f)]

    def assess_all(self, today: Optional[date] = None) -> List[VendorAssessment]:
        return [assess_vendor(v, today) for v in self.vendors]

    def summary(self, today: Optional[date] = None) -> Dict:
        assessments = self.assess_all(today)
        if not assessments:
            return {"vendor_count": 0, "average_score": 0, "tiers": {}, "single_source_categories": [],
                    "assessments": []}

        tiers: Dict[str, int] = {}
        for a in assessments:
            tiers[a.tier] = tiers.get(a.tier, 0) + 1

        # Concentration risk: a category where exactly one critical vendor exists
        crit_by_cat: Dict[str, int] = {}
        for v in self.vendors:
            if v.criticality == "CRITICAL":
                crit_by_cat[v.category] = crit_by_cat.get(v.category, 0) + 1
        single_source = sorted(c for c, n in crit_by_cat.items() if n == 1)

        # Weight average by criticality so critical vendors count more
        w = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        total_w = sum(w[a.criticality] for a in assessments)
        weighted = sum(a.score * w[a.criticality] for a in assessments) / total_w

        return {
            "vendor_count": len(assessments),
            "average_score": round(weighted, 1),
            "tiers": tiers,
            "single_source_categories": single_source,
            "assessments": [asdict(a) for a in assessments],
        }


if __name__ == "__main__":
    s = SupplyChainConnector().summary()
    print(f"Vendors: {s['vendor_count']}  Weighted score: {s['average_score']}  Tiers: {s['tiers']}")
    for a in s["assessments"]:
        print(f"  {a['name']:<20} {a['score']:>3}  {a['tier']:<8} gaps={len(a['gaps'])}")
