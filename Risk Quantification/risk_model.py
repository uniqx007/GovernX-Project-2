"""
risk_model.py - GovernX Risk Quantification (Week 1)

This is the "brain" that connects everything:

    finding (from Person 1's scanner)  +  asset (asset_registry.py)
        -> which threat does it worsen?  (threat_library.py)
        -> SLE, ALE, and "value at risk" in dollars  (ale_calculator.py)

It also contains the SETUP for Monte Carlo simulation (the full version
with 10,000 iterations and confidence intervals is Week 2).

Run the demo:   python risk_model.py
"""

from __future__ import annotations

import random
from dataclasses import dataclass, asdict
from typing import Dict, Iterable, List, Optional, Tuple

from ale_calculator import (
    annualized_loss_expectancy,
    format_usd,
    portfolio_ale,
    residual_ale,
    single_loss_expectancy,
)
from asset_registry import Asset, AssetRegistry, sample_registry
from threat_library import Threat, get_control_gap, get_threat


@dataclass
class RiskAssessment:
    """The result for ONE finding on ONE asset."""

    asset_id: str
    asset_name: str
    finding_type: str
    finding_title: str
    nist_subcategory: str
    threat_id: str
    asset_value: float
    exposure_factor: float      # after adjusting for how sensitive/critical the asset is
    sle: float                  # loss per incident
    aro: float                  # incidents per year
    ale_current: float          # expected yearly loss while the gap is open
    control_effectiveness: float
    ale_after_fix: float        # expected yearly loss once the gap is fixed
    value_at_risk: float        # ale_current - ale_after_fix  <- the number for the board

    def to_dict(self) -> dict:
        data = asdict(self)
        for key, value in data.items():
            if isinstance(value, float):
                data[key] = round(value, 4 if value < 1 else 2)
        return data


class RiskModel:
    def __init__(self, registry: AssetRegistry) -> None:
        self.registry = registry

    @staticmethod
    def effective_exposure(asset: Asset, threat: Threat) -> float:
        """Threat's base exposure scaled by the asset's sensitivity/criticality, capped at 100%."""
        return min(1.0, threat.exposure_factor * asset.impact_weight)

    def assess(self, asset: Asset, finding_type: str) -> RiskAssessment:
        gap = get_control_gap(finding_type)
        threat = get_threat(gap.threat_id)
        if not threat.applies_to(asset.asset_type):
            raise ValueError(
                f"Threat {threat.threat_id} does not apply to asset type "
                f"'{asset.asset_type.value}' ({asset.asset_id})"
            )
        exposure = self.effective_exposure(asset, threat)
        sle = single_loss_expectancy(asset.value_usd, exposure)
        ale = annualized_loss_expectancy(threat.base_aro, sle)
        after = residual_ale(ale, gap.control_effectiveness)
        return RiskAssessment(
            asset_id=asset.asset_id,
            asset_name=asset.name,
            finding_type=gap.finding_type,
            finding_title=gap.title,
            nist_subcategory=gap.nist_subcategory,
            threat_id=threat.threat_id,
            asset_value=asset.value_usd,
            exposure_factor=exposure,
            sle=sle,
            aro=threat.base_aro,
            ale_current=ale,
            control_effectiveness=gap.control_effectiveness,
            ale_after_fix=after,
            value_at_risk=ale - after,
        )

    def assess_finding(self, finding: dict) -> RiskAssessment:
        """finding = {"finding_type": "...", "asset_id": "..."} (agree the exact format with Person 1/2)."""
        asset = self.registry.get(finding["asset_id"])
        return self.assess(asset, finding["finding_type"])

    def assess_findings(self, findings: Iterable[dict]) -> Tuple[List[RiskAssessment], List[dict]]:
        """Process many findings. Bad ones are skipped (and reported), not fatal."""
        done: List[RiskAssessment] = []
        skipped: List[dict] = []
        for finding in findings:
            try:
                done.append(self.assess_finding(finding))
            except (KeyError, ValueError) as err:
                skipped.append({"finding": finding, "reason": str(err)})
        return done, skipped

    @staticmethod
    def summarize(assessments: List[RiskAssessment], top_n: int = 5) -> dict:
        by_threat: Dict[str, float] = {}
        for a in assessments:
            by_threat[a.threat_id] = by_threat.get(a.threat_id, 0.0) + a.value_at_risk
        ranked = sorted(assessments, key=lambda a: a.value_at_risk, reverse=True)
        return {
            "findings": len(assessments),
            "total_ale": portfolio_ale(a.ale_current for a in assessments),
            "total_value_at_risk": portfolio_ale(a.value_at_risk for a in assessments),
            "value_at_risk_by_threat": by_threat,
            "top_risks": [(a.asset_name, a.finding_title, a.value_at_risk) for a in ranked[:top_n]],
        }

    # ------------------------------------------------------------------
    # Monte Carlo SETUP (Week 2 extends this to full analysis)
    # ------------------------------------------------------------------
    def monte_carlo(
        self,
        asset: Asset,
        finding_type: str,
        iterations: int = 10_000,
        seed: Optional[int] = None,
    ) -> dict:
        """
        We don't know the exact likelihood or loss, only a plausible range.
        So we 'roll the dice' many times: each round picks a random ARO and
        exposure from a triangle-shaped range (most likely value at the peak),
        computes the ALE, and we study the spread of all the results.
        """
        if iterations <= 0:
            raise ValueError("iterations must be positive")
        gap = get_control_gap(finding_type)
        threat = get_threat(gap.threat_id)
        base_exposure = self.effective_exposure(asset, threat)
        rng = random.Random(seed)

        results = []
        for _ in range(iterations):
            aro = rng.triangular(threat.aro_low, threat.aro_high, threat.base_aro)
            exposure = rng.triangular(base_exposure * 0.5, min(1.0, base_exposure * 1.5), base_exposure)
            results.append(aro * asset.value_usd * exposure)
        results.sort()

        return {
            "iterations": iterations,
            "analytical_ale": self.assess(asset, finding_type).ale_current,
            "mean": sum(results) / iterations,
            "p5": _percentile(results, 5),
            "p50": _percentile(results, 50),
            "p95": _percentile(results, 95),
            "p99": _percentile(results, 99),
        }


def _percentile(sorted_values: List[float], pct: float) -> float:
    k = (len(sorted_values) - 1) * pct / 100
    lower = int(k)
    upper = min(lower + 1, len(sorted_values) - 1)
    return sorted_values[lower] + (sorted_values[upper] - sorted_values[lower]) * (k - lower)


if __name__ == "__main__":
    model = RiskModel(sample_registry())

    # Pretend these came from Person 1's scanner on the mock AWS account.
    mock_findings = [
        {"finding_type": "iam_mfa_disabled", "asset_id": "A-005"},
        {"finding_type": "s3_bucket_public", "asset_id": "A-003"},
        {"finding_type": "rds_unencrypted", "asset_id": "A-001"},
        {"finding_type": "rds_unencrypted", "asset_id": "A-002"},
        {"finding_type": "ec2_volume_unencrypted", "asset_id": "A-004"},
        {"finding_type": "backup_unencrypted", "asset_id": "A-006"},
        {"finding_type": "vpc_flow_logs_disabled", "asset_id": "A-007"},
    ]
    assessments, skipped = model.assess_findings(mock_findings)

    print(f"{'Asset':32} {'Finding':40} {'ALE/yr':>10} {'Value at risk':>14}")
    print("-" * 100)
    for a in sorted(assessments, key=lambda x: x.value_at_risk, reverse=True):
        print(f"{a.asset_name:32} {a.finding_title:40} "
              f"{format_usd(a.ale_current):>10} {format_usd(a.value_at_risk):>14}")

    summary = model.summarize(assessments)
    print("-" * 100)
    print(f"Total yearly risk (ALE):      {format_usd(summary['total_ale'])}")
    print(f"Total value at risk (fixable): {format_usd(summary['total_value_at_risk'])}")
    if skipped:
        print("Skipped:", skipped)

    mc = model.monte_carlo(model.registry.get("A-005"), "iam_mfa_disabled", seed=42)
    print("\nMonte Carlo setup check - Admin accounts, MFA disabled (10,000 runs):")
    print(f"  formula ALE {format_usd(mc['analytical_ale'])} | mean {format_usd(mc['mean'])} | "
          f"likely range (5th-95th pct) {format_usd(mc['p5'])} to {format_usd(mc['p95'])}")
