"""
ale_calculator.py - GovernX Risk Quantification (Week 1)

The core money formulas. Pure functions only, so they are easy to test.

  SLE (Single Loss Expectancy)      = asset value x exposure factor
        "How much do we lose EACH TIME this goes wrong?"

  ALE (Annualized Loss Expectancy)  = ARO x SLE
        "How much do we expect to lose PER YEAR?"
        ARO = Annual Rate of Occurrence (how many times per year it happens)

  Control effectiveness: a fixed control removes a share of the risk.
        residual ALE = ALE x (1 - effectiveness)
"""

from __future__ import annotations

from typing import Iterable


def _check_fraction(name: str, value: float) -> None:
    if not 0 <= value <= 1:
        raise ValueError(f"{name} must be between 0 and 1, got {value}")


def single_loss_expectancy(asset_value: float, exposure_factor: float) -> float:
    """SLE = asset value x exposure factor (share of value lost per incident)."""
    if asset_value < 0:
        raise ValueError("asset_value cannot be negative")
    _check_fraction("exposure_factor", exposure_factor)
    return asset_value * exposure_factor


def annualized_loss_expectancy(aro: float, sle: float) -> float:
    """ALE = ARO x SLE."""
    if aro < 0:
        raise ValueError("aro cannot be negative")
    if sle < 0:
        raise ValueError("sle cannot be negative")
    return aro * sle


def residual_ale(ale: float, control_effectiveness: float) -> float:
    """Risk left AFTER a control is in place (or a gap is fixed)."""
    _check_fraction("control_effectiveness", control_effectiveness)
    return ale * (1 - control_effectiveness)


def risk_reduction(ale: float, control_effectiveness: float) -> float:
    """Dollars of yearly risk removed by the control. This is the 'Value at Risk' of the gap."""
    _check_fraction("control_effectiveness", control_effectiveness)
    return ale * control_effectiveness


def portfolio_ale(ales: Iterable[float]) -> float:
    """
    Total yearly risk across many findings (simple sum).
    Caveat: this assumes the risks add up independently. Overlapping risks can
    make the true total a bit lower. Week 2 (Monte Carlo) can refine this.
    """
    return sum(ales)


def format_usd(amount: float) -> str:
    if abs(amount) >= 1_000_000:
        return f"${amount / 1_000_000:,.2f}M"
    if abs(amount) >= 1_000:
        return f"${amount / 1_000:,.1f}K"
    return f"${amount:,.0f}"


if __name__ == "__main__":
    # Worked example: $5M database, 60% of value lost per breach, breach once per 10 years.
    sle = single_loss_expectancy(5_000_000, 0.60)
    ale = annualized_loss_expectancy(0.10, sle)
    print(f"SLE = {format_usd(sle)} per incident")
    print(f"ALE = {format_usd(ale)} per year")
    print(f"If an 80%-effective control is added, residual ALE = {format_usd(residual_ale(ale, 0.80))}")
