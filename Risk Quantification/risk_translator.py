"""
risk_translator.py - GovernX Risk Quantification (Week 2)

Translates a TECHNICAL finding into a FINANCIAL statement a board can read:

    "MFA not enabled on accounts" on "Financial Database"
        ->  "$580K expected loss per year; fixing it avoids about $464K per year"

For every finding you get:
  * the yearly expected loss (ALE) and the part a fix would remove
  * a likely range (from the Monte Carlo simulation)
  * a scenario analysis: best case / likely case / worst case
  * a CONFIDENCE level (Low / Medium / High) with the reason

About confidence (important!): it describes how well-sourced the INPUT
numbers are, not how good the maths is. Right now the threat numbers are
illustrative placeholders, so confidence is honestly "Low". It rises when you
replace them with real sources:
  - put the real source in the `source` field of the threat in threat_library.py
    (e.g. "IBM Cost of a Data Breach 2025")  -> evidence becomes "industry report"
  - record an owner on the asset (asset_registry.py `owner=`) when the business
    confirms the asset's dollar value
  - use set_validated(threat_id) only if you have company-specific incident data

    score = evidence (illustrative 0, industry report 1, validated 2)
            + 1 if the asset's value is confirmed by an owner
    score 3 -> High, 2 -> Medium, otherwise Low

Run the demo:   python risk_translator.py
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Dict, Iterable, List, Optional, Set, Tuple

from ale_calculator import format_usd
from ale_engine import ALEEngine, Assumptions, FindingAssessment, PortfolioResult
from asset_registry import Asset, sample_registry
from monte_carlo_risk import simulate_ale
from threat_library import get_threat

# Scenario analysis: how pessimistic / optimistic are best and worst case?
SCENARIOS: Dict[str, Assumptions] = {
    "best": Assumptions(aro_multiplier=0.5, exposure_multiplier=0.75),
    "likely": Assumptions(),
    "worst": Assumptions(aro_multiplier=2.0, exposure_multiplier=1.25),
}

_VALIDATED_THREATS: Set[str] = set()


def set_validated(threat_id: str) -> None:
    """Mark a threat's numbers as validated against the company's OWN incident data."""
    get_threat(threat_id)  # raises if unknown
    _VALIDATED_THREATS.add(threat_id)


def evidence_level(threat_id: str) -> str:
    if threat_id in _VALIDATED_THREATS:
        return "validated"
    source = get_threat(threat_id).source.lower()
    return "illustrative" if "illustrative" in source else "industry_report"


def confidence_for(asset: Asset, threat_id: str) -> Tuple[str, str]:
    """Returns (Low | Medium | High, plain-English reason)."""
    level = evidence_level(threat_id)
    points = {"illustrative": 0, "industry_report": 1, "validated": 2}[level]
    owner_confirmed = bool(asset.owner)
    score = points + (1 if owner_confirmed else 0)
    label = "High" if score >= 3 else "Medium" if score == 2 else "Low"

    parts = {
        "illustrative": "threat numbers are illustrative assumptions (not yet sourced)",
        "industry_report": "threat numbers come from a published source",
        "validated": "threat numbers are validated against company incident data",
    }[level]
    parts += "; asset value confirmed by its owner" if owner_confirmed else "; asset value not yet confirmed by an owner"
    return label, parts


@dataclass
class FinancialImpact:
    asset_id: str
    asset_name: str
    finding_type: str
    finding_title: str
    nist_subcategory: str
    threat_id: str
    threat_name: str
    sle: float                       # loss each time it happens
    ale: float                       # expected loss per year
    value_at_risk: float             # yearly loss removed if fixed
    ale_range_90: Tuple[float, float]  # 90% confidence interval for the ALE (Monte Carlo)
    scenarios: Dict[str, float]      # best / likely / worst yearly loss
    confidence: str                  # Low / Medium / High
    confidence_reason: str
    statement: str                   # board-ready sentence

    def to_dict(self) -> dict:
        data = asdict(self)
        data["ale_range_90"] = [round(x, 2) for x in self.ale_range_90]
        for key in ("sle", "ale", "value_at_risk"):
            data[key] = round(data[key], 2)
        data["scenarios"] = {k: round(v, 2) for k, v in self.scenarios.items()}
        return data


class RiskTranslator:
    def __init__(self, engine: ALEEngine, iterations: int = 10_000, seed: Optional[int] = None) -> None:
        self.engine = engine
        self.iterations = iterations
        self.seed = seed

    def translate(self, finding: dict) -> FinancialImpact:
        asset = self.engine.resolve_asset(finding)
        base = self.engine.assess(asset, finding["finding_type"])
        threat = get_threat(base.threat_id)

        scenarios = {
            name: self.engine.assess(asset, finding["finding_type"], assumptions).ale_current
            for name, assumptions in SCENARIOS.items()
        }

        single = self.engine.assess_portfolio([finding])
        mc = simulate_ale(single.groups, iterations=self.iterations, seed=self.seed)
        low, high = mc["current"]["intervals"]["90%"]

        confidence, reason = confidence_for(asset, base.threat_id)
        return FinancialImpact(
            asset_id=base.asset_id,
            asset_name=base.asset_name,
            finding_type=base.finding_type,
            finding_title=base.finding_title,
            nist_subcategory=base.nist_subcategory,
            threat_id=base.threat_id,
            threat_name=threat.name,
            sle=base.sle,
            ale=base.ale_current,
            value_at_risk=base.value_at_risk,
            ale_range_90=(low, high),
            scenarios=scenarios,
            confidence=confidence,
            confidence_reason=reason,
            statement=board_statement(base, (low, high), confidence),
        )

    def translate_many(self, findings: Iterable[dict]) -> Tuple[List[FinancialImpact], List[dict]]:
        done: List[FinancialImpact] = []
        skipped: List[dict] = []
        for finding in findings:
            try:
                done.append(self.translate(finding))
            except (KeyError, ValueError) as err:
                skipped.append({"finding": finding, "reason": str(err).strip("'\"")})
        return done, skipped

    def translate_portfolio(self, findings: Iterable[dict]) -> dict:
        """Per-finding statements PLUS the company-wide total without double counting."""
        findings = list(findings)
        impacts, skipped = self.translate_many(findings)
        portfolio: PortfolioResult = self.engine.assess_portfolio(findings)
        ranked = sorted(impacts, key=lambda i: i.value_at_risk, reverse=True)
        return {
            "impacts": ranked,
            "skipped": skipped,
            "total_ale": portfolio.total_ale,
            "total_value_at_risk": portfolio.total_value_at_risk,
            "portfolio": portfolio,
        }


def board_statement(a: FindingAssessment, ale_range_90: Tuple[float, float], confidence: str) -> str:
    low, high = ale_range_90
    return (
        f"{a.asset_name}: {a.finding_title}. Expected loss about {format_usd(a.ale_current)} per year "
        f"(90% likely range {format_usd(low)} to {format_usd(high)}). "
        f"Fixing it avoids about {format_usd(a.value_at_risk)} per year. Confidence: {confidence}."
    )


if __name__ == "__main__":
    translator = RiskTranslator(ALEEngine(sample_registry()), seed=42)

    # The three examples from the project plan, run on our mock assets.
    plan_examples = [
        {"finding_type": "iam_mfa_disabled", "asset_id": "A-002"},   # missing MFA on financial DB
        {"finding_type": "backup_unencrypted", "asset_id": "A-006"}, # unencrypted backup
        {"finding_type": "dlp_not_configured", "asset_id": "A-001"}, # no DLP -> data exfiltration
    ]
    for finding in plan_examples:
        impact = translator.translate(finding)
        print(impact.statement)
        s = impact.scenarios
        print(f"   Scenarios per year: best {format_usd(s['best'])} | likely {format_usd(s['likely'])} "
              f"| worst {format_usd(s['worst'])}")
        print(f"   Confidence is {impact.confidence} because {impact.confidence_reason}.\n")

    print("-" * 80)
    print("Whole mock audit, ranked by yearly risk removed:\n")
    audit = plan_examples + [
        {"finding_type": "s3_bucket_public", "asset_id": "A-003"},
        {"finding_type": "iam_overly_permissive_policy", "asset_id": "A-005"},
    ]
    out = translator.translate_portfolio(audit)
    for impact in out["impacts"]:
        print(f"  {format_usd(impact.value_at_risk):>9}  {impact.asset_name} - {impact.finding_title}")
    print(f"\nCompany-wide yearly risk: {format_usd(out['total_ale'])}; "
          f"removable by fixing all: {format_usd(out['total_value_at_risk'])}")
