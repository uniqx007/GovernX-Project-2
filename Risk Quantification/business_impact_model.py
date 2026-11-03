"""
business_impact_model.py - GovernX Risk Quantification (Week 2)

Answers the question every CISO gets from the CFO:
        "We want to spend money on this fix. Is it worth it?"

For each fix we compare the money it SAVES (risk removed per year) with the
money it COSTS, using standard measures:

  Annual benefit      = yearly risk removed by the fix (from the ALE engine)
  Total benefit       = annual benefit x years (the planning horizon, default 3)
  Total cost          = one-time cost + running cost per year x years
  Net benefit         = total benefit - total cost
  ROI %               = net benefit / total cost x 100
  Benefit-cost ratio  = total benefit / total cost   ("$ saved per $1 spent")
  Payback period      = years until the savings repay the one-time cost
  NPV                 = today's value of the savings minus costs, with future
                        money discounted (default 8%/year) because $1 next year
                        is worth less than $1 today

It also builds a BUDGET JUSTIFICATION: given a budget, which fixes should be
bought first (best return per dollar) and how much risk disappears.

!! The control costs below are ILLUSTRATIVE placeholders (US dollars). Replace
them with real quotes / cloud pricing / staff time before presenting. !!

Note: some fixes are required by law or contract (compliance) even when the
financial case is weak. A low ratio here means "weak on risk reduction alone",
not "ignore it".

Run the demo:   python business_impact_model.py
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Dict, Iterable, List, Optional, Tuple

from ale_calculator import format_usd
from ale_engine import ALEEngine, PortfolioResult
from asset_registry import sample_registry
from threat_library import CONTROL_GAPS


@dataclass(frozen=True)
class ControlCost:
    one_time: float   # setup / rollout cost, paid once
    annual: float     # running cost per year (licences, storage, staff time)
    note: str = ""


# Illustrative placeholders, USD. finding_type -> cost of fixing it.
DEFAULT_CONTROL_COSTS: Dict[str, ControlCost] = {
    "iam_mfa_disabled": ControlCost(12_000, 6_000, "MFA rollout + tokens/licences + support"),
    "iam_overly_permissive_policy": ControlCost(15_000, 2_000, "access review + least-privilege redesign"),
    "s3_bucket_public": ControlCost(1_500, 0, "block public access setting + review"),
    "ec2_volume_unencrypted": ControlCost(4_000, 500, "snapshot, re-create volumes encrypted"),
    "rds_unencrypted": ControlCost(18_000, 2_000, "migrate to an encrypted instance + key management"),
    "backup_unencrypted": ControlCost(6_000, 1_000, "re-create backups with encryption"),
    "backup_missing": ControlCost(10_000, 12_000, "backup tooling + storage"),
    "security_group_open_to_world": ControlCost(2_500, 0, "tighten rules + test"),
    "vpc_flow_logs_disabled": ControlCost(3_000, 5_000, "enable logging + log storage"),
    "root_account_no_mfa": ControlCost(1_000, 0, "hardware key / authenticator for root"),
    "weak_password_policy": ControlCost(1_000, 0, "policy change + user comms"),
    "access_keys_not_rotated": ControlCost(4_000, 1_000, "rotation automation"),
    "s3_unencrypted": ControlCost(2_000, 200, "default encryption + re-encrypt objects"),
    "tls_not_enforced": ControlCost(5_000, 500, "enforce TLS + certificate management"),
    "rds_publicly_accessible": ControlCost(3_000, 0, "move into private subnet + access path"),
    "cloudtrail_disabled": ControlCost(3_000, 4_000, "enable audit logging + log storage"),
    "dlp_not_configured": ControlCost(80_000, 30_000, "DLP tooling + tuning + analyst time"),
}
FALLBACK_COST = ControlCost(10_000, 2_000, "generic placeholder - no specific cost recorded")


@dataclass
class BusinessCase:
    asset_id: str
    asset_name: str
    finding_type: str
    finding_title: str
    annual_benefit: float
    one_time_cost: float
    annual_cost: float
    horizon_years: int
    total_benefit: float
    total_cost: float
    net_benefit: float
    roi_pct: Optional[float]               # None when the fix costs nothing
    benefit_cost_ratio: Optional[float]    # None when the fix costs nothing
    payback_years: Optional[float]         # None = never pays back
    npv: float
    recommendation: str
    cost_note: str = ""

    @property
    def key(self) -> Tuple[str, str]:
        return (self.asset_id, self.finding_type)

    @property
    def year_one_spend(self) -> float:
        return self.one_time_cost + self.annual_cost

    def to_dict(self) -> dict:
        data = asdict(self)
        for name, value in data.items():
            if isinstance(value, float):
                data[name] = round(value, 2)
        return data


def recommendation_for(ratio: Optional[float]) -> str:
    if ratio is None or ratio >= 3:
        return "Do first - strong return"
    if ratio >= 1:
        return "Worth doing"
    return "Weak financial case (may still be required for compliance)"


class BusinessImpactModel:
    def __init__(
        self,
        engine: ALEEngine,
        costs: Optional[Dict[str, ControlCost]] = None,
        horizon_years: int = 3,
        discount_rate: float = 0.08,
    ) -> None:
        if horizon_years <= 0:
            raise ValueError("horizon_years must be positive")
        if discount_rate < 0:
            raise ValueError("discount_rate cannot be negative")
        self.engine = engine
        self.costs = dict(DEFAULT_CONTROL_COSTS)
        if costs:
            self.costs.update(costs)
        self.horizon_years = horizon_years
        self.discount_rate = discount_rate

    # ---- one fix ----------------------------------------------------------
    def case_for(self, asset_id: str, asset_name: str, finding_type: str, finding_title: str,
                 annual_benefit: float) -> BusinessCase:
        cost = self.costs.get(finding_type, FALLBACK_COST)
        years = self.horizon_years
        total_benefit = annual_benefit * years
        total_cost = cost.one_time + cost.annual * years
        net = total_benefit - total_cost

        ratio = total_benefit / total_cost if total_cost > 0 else None
        roi = net / total_cost * 100 if total_cost > 0 else None

        yearly_net = annual_benefit - cost.annual
        if cost.one_time == 0:
            payback: Optional[float] = 0.0
        elif yearly_net > 0:
            payback = cost.one_time / yearly_net
        else:
            payback = None

        npv = -cost.one_time + sum(
            yearly_net / (1 + self.discount_rate) ** t for t in range(1, years + 1)
        )
        return BusinessCase(
            asset_id=asset_id, asset_name=asset_name,
            finding_type=finding_type, finding_title=finding_title,
            annual_benefit=annual_benefit,
            one_time_cost=cost.one_time, annual_cost=cost.annual, horizon_years=years,
            total_benefit=total_benefit, total_cost=total_cost, net_benefit=net,
            roi_pct=roi, benefit_cost_ratio=ratio, payback_years=payback, npv=npv,
            recommendation=recommendation_for(ratio), cost_note=cost.note,
        )

    # ---- all fixes in a portfolio -------------------------------------------
    def build_cases(self, portfolio: PortfolioResult) -> List[BusinessCase]:
        """One case per finding, best return per dollar first. Uses each finding's
        share of the combined risk removed, so overlapping gaps are not double counted."""
        cases = [
            self.case_for(a.asset_id, a.asset_name, a.finding_type, a.finding_title,
                          a.allocated_value_at_risk)
            for a in portfolio.assessments
        ]
        cases.sort(key=lambda c: (float("inf") if c.benefit_cost_ratio is None else c.benefit_cost_ratio),
                   reverse=True)
        return cases

    # ---- budget justification --------------------------------------------------
    def budget_justification(self, portfolio: PortfolioResult, budget: float) -> dict:
        """
        Spend a year-one budget on the fixes with the best return per dollar.
        Only fixes whose benefit exceeds their total cost are bought; the rest are
        listed with the reason. Risk left is computed exactly (overlap-aware).
        """
        if budget < 0:
            raise ValueError("budget cannot be negative")
        cases = self.build_cases(portfolio)
        chosen: List[BusinessCase] = []
        passed_over: List[dict] = []
        remaining = budget

        for case in cases:
            if case.net_benefit <= 0:
                passed_over.append({"case": case, "reason": "weak financial case - costs more than the risk it removes"})
            elif case.year_one_spend > remaining:
                passed_over.append({"case": case, "reason": "does not fit in the remaining budget"})
            else:
                chosen.append(case)
                remaining -= case.year_one_spend

        outcome = self.engine.risk_after_fixing(portfolio, [c.key for c in chosen]) if chosen else {
            "ale_before": portfolio.total_ale, "ale_after": portfolio.total_ale,
            "risk_reduced": 0.0, "fixes": 0}

        years = self.horizon_years
        spend_year_one = sum(c.year_one_spend for c in chosen)
        total_cost = sum(c.total_cost for c in chosen)
        total_benefit = outcome["risk_reduced"] * years
        ratio = total_benefit / total_cost if total_cost else None
        pct = outcome["risk_reduced"] / portfolio.total_ale * 100 if portfolio.total_ale else 0.0

        if chosen:
            statement = (
                f"With a year-one budget of {format_usd(budget)} we recommend {len(chosen)} fix"
                f"{'es' if len(chosen) != 1 else ''} (year-one spend {format_usd(spend_year_one)}). "
                f"They cut expected yearly loss from {format_usd(outcome['ale_before'])} to "
                f"{format_usd(outcome['ale_after'])} ({pct:.0f}% lower). Over {years} years that avoids about "
                f"{format_usd(total_benefit)} of losses for {format_usd(total_cost)} of cost"
                + (f" - roughly ${ratio:,.1f} saved for every $1 spent." if ratio else ".")
            )
        else:
            statement = f"No fix has a positive financial case within a {format_usd(budget)} year-one budget."

        return {
            "budget": budget,
            "spent_year_one": spend_year_one,
            "budget_left": remaining,
            "chosen": chosen,
            "passed_over": passed_over,
            "ale_before": outcome["ale_before"],
            "ale_after": outcome["ale_after"],
            "risk_reduced_per_year": outcome["risk_reduced"],
            "risk_reduced_pct": pct,
            "horizon_years": years,
            "total_benefit": total_benefit,
            "total_cost": total_cost,
            "benefit_cost_ratio": ratio,
            "cost_of_doing_nothing": portfolio.total_ale * years,
            "statement": statement,
        }


def _fmt_ratio(value: Optional[float]) -> str:
    return "n/a" if value is None else f"{value:,.1f}x"


def _fmt_payback(value: Optional[float]) -> str:
    if value is None:
        return "never"
    if value < 1:
        return f"{max(1, round(value * 12))} mo"
    return f"{value:.1f} yrs"


if __name__ == "__main__":
    engine = ALEEngine(sample_registry())
    model = BusinessImpactModel(engine)
    findings = [
        {"finding_type": "iam_mfa_disabled", "asset_id": "A-005"},
        {"finding_type": "iam_overly_permissive_policy", "asset_id": "A-005"},
        {"finding_type": "s3_bucket_public", "asset_id": "A-003"},
        {"finding_type": "rds_unencrypted", "asset_id": "A-001"},
        {"finding_type": "rds_unencrypted", "asset_id": "A-002"},
        {"finding_type": "backup_unencrypted", "asset_id": "A-006"},
        {"finding_type": "ec2_volume_unencrypted", "asset_id": "A-004"},
        {"finding_type": "vpc_flow_logs_disabled", "asset_id": "A-007"},
        {"finding_type": "dlp_not_configured", "asset_id": "A-002"},
    ]
    portfolio = engine.assess_portfolio(findings)

    print(f"Return on each fix over {model.horizon_years} years (best first)\n")
    print(f"{'Asset':28} {'Fix':40} {'Saves/yr':>9} {'Costs 1st yr':>12} {'Ratio':>7} {'Payback':>9}  Verdict")
    print("-" * 140)
    for c in model.build_cases(portfolio):
        print(f"{c.asset_name:28} {c.finding_title:40} {format_usd(c.annual_benefit):>9} "
              f"{format_usd(c.year_one_spend):>12} {_fmt_ratio(c.benefit_cost_ratio):>7} "
              f"{_fmt_payback(c.payback_years):>9}  {c.recommendation}")

    print("\nBudget justification")
    for budget in (30_000, 100_000):
        plan = model.budget_justification(portfolio, budget)
        print(f"\n  Budget {format_usd(budget)}:")
        print("  " + plan["statement"])
        for c in plan["chosen"]:
            print(f"    buy: {c.asset_name} - {c.finding_title}")
        for p in plan["passed_over"]:
            print(f"    skip: {p['case'].asset_name} - {p['case'].finding_title} ({p['reason']})")
