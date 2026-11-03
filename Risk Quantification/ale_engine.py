"""
ale_engine.py - GovernX Risk Quantification (Week 2)

The ALE engine turns a LIST of scanner findings into dollar risk for the whole
company. It builds on the Week 1 formulas (ale_calculator.py) and adds:

  * ARO (how often) adjusted by "assumptions" you can change (what-if / scenarios)
  * SLE (loss each time) from the asset's value and sensitivity
  * control effectiveness (how much risk a fix removes)
  * PORTFOLIO aggregation that does NOT double count:
        two gaps that make the same threat worse on the same asset (e.g. "no MFA"
        AND "too many permissions" on the admin accounts) share ONE risk, so
        their combined effect is   1 - (1 - e1) x (1 - e2)   not   e1 + e2.
  * breakdowns by asset, threat, NIST function (GV/ID/PR/DE/RS/RC) and category
  * "what if we fix these?" -> remaining risk

Words:
  ARO  = Annual Rate of Occurrence (times per year)
  SLE  = Single Loss Expectancy (dollars lost each time)
  ALE  = ARO x SLE (expected dollars lost per year)
  Value at risk (here) = yearly dollars removed if the gap is fixed

Run the demo:   python ale_engine.py
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, replace
from typing import Dict, Iterable, List, Optional, Set, Tuple

from ale_calculator import (
    annualized_loss_expectancy,
    format_usd,
    residual_ale,
    single_loss_expectancy,
)
from asset_registry import Asset, AssetRegistry, sample_registry
from threat_library import Threat, get_control_gap, get_threat

NIST_FUNCTIONS = {
    "GV": "Govern",
    "ID": "Identify",
    "PR": "Protect",
    "DE": "Detect",
    "RS": "Respond",
    "RC": "Recover",
}


# ----------------------------------------------------------------------
# Assumptions: the dials you can turn for scenarios and sensitivity tests
# ----------------------------------------------------------------------
@dataclass(frozen=True)
class Assumptions:
    """All multipliers default to 1.0 (= use the library numbers as they are)."""

    aro_multiplier: float = 1.0            # x how often attacks happen (all threats)
    exposure_multiplier: float = 1.0       # x share of asset value lost per incident
    value_multiplier: float = 1.0          # x asset dollar values
    effectiveness_multiplier: float = 1.0  # x how well fixes work (result capped at 100%)
    threat_aro_multipliers: Dict[str, float] = field(default_factory=dict)  # per-threat ARO dial

    def __post_init__(self) -> None:
        for name in ("aro_multiplier", "exposure_multiplier", "value_multiplier",
                     "effectiveness_multiplier"):
            if getattr(self, name) < 0:
                raise ValueError(f"{name} cannot be negative")
        for threat_id, mult in self.threat_aro_multipliers.items():
            if mult < 0:
                raise ValueError(f"threat_aro_multipliers[{threat_id}] cannot be negative")

    def aro_for(self, threat: Threat) -> float:
        return threat.base_aro * self.aro_multiplier * self.threat_aro_multipliers.get(threat.threat_id, 1.0)

    def scaled(self, **changes: float) -> "Assumptions":
        """Return a copy with the given multipliers MULTIPLIED in (used by sensitivity tests)."""
        updated = {name: getattr(self, name) * factor for name, factor in changes.items()}
        return replace(self, **updated)


# ----------------------------------------------------------------------
# Result objects
# ----------------------------------------------------------------------
def _round(data: dict) -> dict:
    for key, value in data.items():
        if isinstance(value, float):
            data[key] = round(value, 4 if abs(value) < 1 else 2)
    return data


@dataclass
class FindingAssessment:
    """Risk of ONE finding on ONE asset, looked at on its own."""

    asset_id: str
    asset_name: str
    finding_type: str
    finding_title: str
    nist_subcategory: str
    nist_function: str            # GV / ID / PR / DE / RS / RC
    threat_id: str
    asset_value: float
    exposure_factor: float
    sle: float                    # dollars lost per incident
    aro: float                    # incidents per year
    ale_current: float            # expected loss per year while the gap is open
    control_effectiveness: float
    ale_after_fix: float
    value_at_risk: float          # ale_current - ale_after_fix, if this were the only gap
    group_key: str = ""           # findings sharing asset+threat share a group
    allocated_ale: float = 0.0            # this finding's share of its group's ALE (sums with no double count)
    allocated_value_at_risk: float = 0.0  # this finding's share of its group's combined value at risk

    def to_dict(self) -> dict:
        return _round(asdict(self))


@dataclass
class RiskGroup:
    """One asset + one threat. Several findings can feed the same group."""

    asset_id: str
    asset_name: str
    threat_id: str
    asset_value: float
    exposure_factor: float
    aro: float
    ale: float                          # counted ONCE for the group
    members: List[Tuple[str, float]]    # (finding_type, control_effectiveness)
    combined_effectiveness: float       # 1 - product(1 - e)
    ale_after_fix: float
    value_at_risk: float

    @property
    def key(self) -> str:
        return f"{self.asset_id}|{self.threat_id}"

    def to_dict(self) -> dict:
        data = asdict(self)
        data["key"] = self.key
        return _round(data)


@dataclass
class PortfolioResult:
    assumptions: Assumptions
    assessments: List[FindingAssessment]
    groups: List[RiskGroup]
    skipped: List[dict]
    total_ale: float                 # company-wide expected yearly loss (no double counting)
    total_ale_after_fix: float
    total_value_at_risk: float       # yearly dollars removed if ALL gaps are fixed (no double counting)
    naive_total_value_at_risk: float # plain sum of per-finding numbers (overstates when gaps overlap)
    by_asset: Dict[str, dict]
    by_threat: Dict[str, dict]
    by_function: Dict[str, dict]
    by_category: Dict[str, dict]

    def top_risks(self, n: int = 5) -> List[FindingAssessment]:
        return sorted(self.assessments, key=lambda a: a.allocated_value_at_risk, reverse=True)[:n]

    def to_dict(self) -> dict:
        """JSON-friendly output for the API / dashboard (Persons 1, 4)."""
        return {
            "total_ale": round(self.total_ale, 2),
            "total_ale_after_fix": round(self.total_ale_after_fix, 2),
            "total_value_at_risk": round(self.total_value_at_risk, 2),
            "naive_total_value_at_risk": round(self.naive_total_value_at_risk, 2),
            "findings": [a.to_dict() for a in self.assessments],
            "groups": [g.to_dict() for g in self.groups],
            "by_asset": {k: _round(dict(v)) for k, v in self.by_asset.items()},
            "by_threat": {k: _round(dict(v)) for k, v in self.by_threat.items()},
            "by_function": {k: _round(dict(v)) for k, v in self.by_function.items()},
            "by_category": {k: _round(dict(v)) for k, v in self.by_category.items()},
            "skipped": self.skipped,
        }


def _breakdown(items: List[FindingAssessment], key_fn) -> Dict[str, dict]:
    out: Dict[str, dict] = {}
    for item in items:
        entry = out.setdefault(key_fn(item), {"ale": 0.0, "value_at_risk": 0.0, "findings": 0})
        entry["ale"] += item.allocated_ale
        entry["value_at_risk"] += item.allocated_value_at_risk
        entry["findings"] += 1
    return dict(sorted(out.items(), key=lambda kv: kv[1]["value_at_risk"], reverse=True))


# ----------------------------------------------------------------------
# The engine
# ----------------------------------------------------------------------
class ALEEngine:
    def __init__(self, registry: AssetRegistry, assumptions: Optional[Assumptions] = None) -> None:
        self.registry = registry
        self.assumptions = assumptions or Assumptions()

    # -- finding -> asset ------------------------------------------------
    def resolve_asset(self, finding: dict) -> Asset:
        """
        Find the asset a finding is about. Accepts either our own "asset_id" or
        the cloud resource id the scanner reports ("cloud_resource_id" or
        "resource_id", e.g. an AWS ARN) - so Person 1's output can plug straight in.
        """
        if finding.get("asset_id"):
            return self.registry.get(finding["asset_id"])
        for key in ("cloud_resource_id", "resource_id"):
            if finding.get(key):
                asset = self.registry.find_by_cloud_id(finding[key])
                if asset is None:
                    raise KeyError(f"No asset registered for cloud resource {finding[key]}")
                return asset
        raise KeyError("Finding needs 'asset_id' or 'cloud_resource_id'")

    # -- one finding on its own -------------------------------------------
    def assess(self, asset: Asset, finding_type: str,
               assumptions: Optional[Assumptions] = None) -> FindingAssessment:
        a = assumptions or self.assumptions
        gap = get_control_gap(finding_type)
        threat = get_threat(gap.threat_id)
        if not threat.applies_to(asset.asset_type):
            raise ValueError(
                f"Threat {threat.threat_id} does not apply to asset type "
                f"'{asset.asset_type.value}' ({asset.asset_id})"
            )
        exposure = min(1.0, threat.exposure_factor * a.exposure_multiplier * asset.impact_weight)
        sle = single_loss_expectancy(asset.value_usd * a.value_multiplier, exposure)
        aro = a.aro_for(threat)
        ale = annualized_loss_expectancy(aro, sle)
        effectiveness = min(1.0, gap.control_effectiveness * a.effectiveness_multiplier)
        after = residual_ale(ale, effectiveness)
        return FindingAssessment(
            asset_id=asset.asset_id,
            asset_name=asset.name,
            finding_type=gap.finding_type,
            finding_title=gap.title,
            nist_subcategory=gap.nist_subcategory,
            nist_function=gap.nist_subcategory.split(".")[0],
            threat_id=threat.threat_id,
            asset_value=asset.value_usd * a.value_multiplier,
            exposure_factor=exposure,
            sle=sle,
            aro=aro,
            ale_current=ale,
            control_effectiveness=effectiveness,
            ale_after_fix=after,
            value_at_risk=ale - after,
            group_key=f"{asset.asset_id}|{threat.threat_id}",
            allocated_ale=ale,
            allocated_value_at_risk=ale - after,
        )

    def assess_finding(self, finding: dict, assumptions: Optional[Assumptions] = None) -> FindingAssessment:
        """finding = {"finding_type": "...", "asset_id": "..."}  (or "cloud_resource_id" instead of asset_id)."""
        return self.assess(self.resolve_asset(finding), finding["finding_type"], assumptions)

    # -- many findings, no double counting -----------------------------------
    def assess_portfolio(self, findings: Iterable[dict],
                         assumptions: Optional[Assumptions] = None) -> PortfolioResult:
        a = assumptions or self.assumptions
        items: List[FindingAssessment] = []
        skipped: List[dict] = []
        seen: Set[Tuple[str, str]] = set()

        for finding in findings:
            try:
                asset = self.resolve_asset(finding)
                key = (asset.asset_id, finding["finding_type"])
                if key in seen:
                    skipped.append({"finding": finding, "reason": "duplicate finding for the same asset"})
                    continue
                item = self.assess(asset, finding["finding_type"], a)
            except (KeyError, ValueError) as err:
                skipped.append({"finding": finding, "reason": str(err).strip("'\"")})
                continue
            seen.add(key)
            items.append(item)

        by_group: Dict[str, List[FindingAssessment]] = {}
        for item in items:
            by_group.setdefault(item.group_key, []).append(item)

        groups: List[RiskGroup] = []
        for members in by_group.values():
            first = members[0]
            remaining = 1.0
            for m in members:
                remaining *= 1.0 - m.control_effectiveness
            combined = 1.0 - remaining
            group_var = first.ale_current * combined
            total_e = sum(m.control_effectiveness for m in members)
            for m in members:
                m.allocated_ale = first.ale_current / len(members)
                m.allocated_value_at_risk = group_var * m.control_effectiveness / total_e if total_e else 0.0
            groups.append(RiskGroup(
                asset_id=first.asset_id,
                asset_name=first.asset_name,
                threat_id=first.threat_id,
                asset_value=first.asset_value,
                exposure_factor=first.exposure_factor,
                aro=first.aro,
                ale=first.ale_current,
                members=[(m.finding_type, m.control_effectiveness) for m in members],
                combined_effectiveness=combined,
                ale_after_fix=first.ale_current * remaining,
                value_at_risk=group_var,
            ))

        return PortfolioResult(
            assumptions=a,
            assessments=items,
            groups=groups,
            skipped=skipped,
            total_ale=sum(g.ale for g in groups),
            total_ale_after_fix=sum(g.ale_after_fix for g in groups),
            total_value_at_risk=sum(g.value_at_risk for g in groups),
            naive_total_value_at_risk=sum(i.value_at_risk for i in items),
            by_asset=_breakdown(items, lambda i: i.asset_name),
            by_threat=_breakdown(items, lambda i: i.threat_id),
            by_function=_breakdown(items, lambda i: NIST_FUNCTIONS.get(i.nist_function, i.nist_function)),
            by_category=_breakdown(items, lambda i: i.nist_subcategory.split("-")[0]),
        )

    # -- what if we fix these? --------------------------------------------------
    @staticmethod
    def risk_after_fixing(result: PortfolioResult, fixed: Iterable[Tuple[str, str]]) -> dict:
        """
        fixed = [(asset_id, finding_type), ...]. Returns company-wide risk before/after.
        Correct for overlaps: fixing only ONE of two gaps on the same asset+threat
        removes only that gap's share.
        """
        fixed_set = set(fixed)
        valid = {(g.asset_id, ft) for g in result.groups for ft, _ in g.members}
        unknown = fixed_set - valid
        if unknown:
            raise ValueError(f"Not in this portfolio: {sorted(unknown)}")
        after = 0.0
        for g in result.groups:
            factor = 1.0
            for finding_type, effectiveness in g.members:
                if (g.asset_id, finding_type) in fixed_set:
                    factor *= 1.0 - effectiveness
            after += g.ale * factor
        return {
            "ale_before": result.total_ale,
            "ale_after": after,
            "risk_reduced": result.total_ale - after,
            "fixes": len(fixed_set),
        }


if __name__ == "__main__":
    engine = ALEEngine(sample_registry())
    mock_findings = [
        {"finding_type": "iam_mfa_disabled", "asset_id": "A-005"},
        {"finding_type": "iam_overly_permissive_policy", "asset_id": "A-005"},  # overlaps with MFA
        {"finding_type": "s3_bucket_public", "asset_id": "A-003"},
        {"finding_type": "rds_unencrypted", "asset_id": "A-001"},
        {"finding_type": "rds_unencrypted", "asset_id": "A-002"},
        {"finding_type": "backup_unencrypted", "asset_id": "A-006"},
        {"finding_type": "vpc_flow_logs_disabled", "asset_id": "A-007"},
        {"finding_type": "iam_mfa_disabled", "asset_id": "A-005"},               # duplicate
        {"finding_type": "made_up_finding", "asset_id": "A-001"},                # unknown
    ]
    result = engine.assess_portfolio(mock_findings)

    print(f"{'Asset':30} {'Finding':42} {'ALE share':>10} {'Risk removed':>13}")
    print("-" * 99)
    for a in result.top_risks(20):
        print(f"{a.asset_name:30} {a.finding_title:42} "
              f"{format_usd(a.allocated_ale):>10} {format_usd(a.allocated_value_at_risk):>13}")
    print("-" * 99)
    print(f"Company-wide yearly risk (ALE):            {format_usd(result.total_ale)}")
    print(f"Risk removed if everything is fixed:       {format_usd(result.total_value_at_risk)}")
    print(f"  (a plain sum would wrongly say           {format_usd(result.naive_total_value_at_risk)})")
    print(f"Risk left after fixing everything:         {format_usd(result.total_ale_after_fix)}")

    print("\nBy NIST function:")
    for name, row in result.by_function.items():
        print(f"  {name:10} risk removed {format_usd(row['value_at_risk']):>9}   findings {row['findings']}")

    print("\nSkipped findings:")
    for s in result.skipped:
        print(f"  {s['finding']['finding_type']:20} -> {s['reason']}")

    only_mfa = engine.risk_after_fixing(result, [("A-005", "iam_mfa_disabled")])
    print(f"\nWhat if we ONLY turn on MFA for admins? Risk drops by {format_usd(only_mfa['risk_reduced'])} per year.")
