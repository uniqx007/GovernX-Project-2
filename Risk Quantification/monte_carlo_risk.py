"""
monte_carlo_risk.py - GovernX Risk Quantification (Week 2)

We never know the exact numbers (will attacks come once in 5 years or once in
10? will a breach cost 20% of an asset or 40%?). Monte Carlo simulation
handles that: the computer "replays" the year 10,000 times, each time with
slightly different random-but-realistic numbers, and we study ALL the outcomes.

This file offers three tools (pure Python, no extra packages):

 1. simulate_ale()          UNCERTAINTY about the yearly risk number.
        "Our best estimate is $917K/year, but we are 90% sure the true value
         is somewhere between $X and $Y."   -> confidence intervals 90/95/99%

 2. simulate_annual_loss()  what ACTUALLY happens in a simulated year.
        Most years nothing happens, some years one incident hits, rarely two.
        "In a bad year (1 in 20) we lose $Z or more."   -> loss percentiles

 3. sensitivity_analysis()  which assumption moves the answer most.
        "If the account-takeover likelihood is wrong by 2x, the total changes
         by $W" -> tells you which numbers deserve a real source first.

Probability distributions used (all simple and explainable):
  * likelihood (ARO):  LOGNORMAL with mean = the library ARO. A lognormal is
        always positive and has a long right tail ("sometimes much worse than
        expected"). sigma = 0.5 means roughly "within a factor of 2 either way".
  * loss per incident (exposure): TRIANGULAR, from 50% to 150% of the estimate,
        peaking at the estimate (capped at 100% of the asset's value).
  * number of incidents in a year: POISSON with the sampled ARO as its rate.
  * a fix: removes each incident with probability = control effectiveness.

Assumption to remember: the risks are simulated as independent of each other.

Run the demo:   python monte_carlo_risk.py
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from ale_calculator import format_usd
from ale_engine import ALEEngine, Assumptions, PortfolioResult, RiskGroup
from asset_registry import sample_registry

DEFAULT_ITERATIONS = 10_000
DEFAULT_ARO_SIGMA = 0.5
CONFIDENCE_LEVELS = (0.90, 0.95, 0.99)


# ----------------------------------------------------------------------
# small statistics helpers
# ----------------------------------------------------------------------
def percentile(sorted_values: Sequence[float], pct: float) -> float:
    """pct from 0 to 100, with linear interpolation. Input must already be sorted."""
    if not sorted_values:
        raise ValueError("no values")
    k = (len(sorted_values) - 1) * pct / 100
    lower = int(k)
    upper = min(lower + 1, len(sorted_values) - 1)
    return sorted_values[lower] + (sorted_values[upper] - sorted_values[lower]) * (k - lower)


def summarize(values: Iterable[float], levels: Sequence[float] = CONFIDENCE_LEVELS) -> dict:
    """Mean, spread, key percentiles and central confidence intervals of a list of simulated results."""
    s = sorted(values)
    n = len(s)
    mean = sum(s) / n
    std = math.sqrt(sum((x - mean) ** 2 for x in s) / (n - 1)) if n > 1 else 0.0
    intervals = {}
    for level in levels:
        tail = (1 - level) / 2 * 100
        intervals[f"{round(level * 100)}%"] = (percentile(s, tail), percentile(s, 100 - tail))
    return {
        "mean": mean,
        "std": std,
        "min": s[0],
        "max": s[-1],
        "p05": percentile(s, 5),
        "p25": percentile(s, 25),
        "p50": percentile(s, 50),
        "p75": percentile(s, 75),
        "p90": percentile(s, 90),
        "p95": percentile(s, 95),
        "p99": percentile(s, 99),
        "intervals": intervals,
    }


def _poisson(rng: random.Random, lam: float) -> int:
    """Random whole number of events with average `lam` (Knuth's method)."""
    if lam <= 0:
        return 0
    if lam > 30:  # normal approximation keeps big rates fast and safe
        return max(0, round(rng.gauss(lam, math.sqrt(lam))))
    limit, k, p = math.exp(-lam), 0, 1.0
    while True:
        p *= rng.random()
        if p <= limit:
            return k
        k += 1


def _sample_aro(rng: random.Random, aro: float, sigma: float) -> float:
    """Lognormal draw whose AVERAGE equals `aro` (so the simulation agrees with the formula)."""
    if aro <= 0 or sigma <= 0:
        return aro
    return rng.lognormvariate(math.log(aro) - sigma * sigma / 2, sigma)


def _sample_exposure(rng: random.Random, exposure: float) -> float:
    """Triangular draw: 50%..150% of the estimate (capped at 100% of the asset), peak at the estimate."""
    if exposure <= 0:
        return 0.0
    return rng.triangular(exposure * 0.5, min(1.0, exposure * 1.5), min(1.0, exposure))


# ----------------------------------------------------------------------
# 1. Uncertainty of the yearly risk (ALE)
# ----------------------------------------------------------------------
def simulate_ale(
    groups: Sequence[RiskGroup],
    iterations: int = DEFAULT_ITERATIONS,
    seed: Optional[int] = None,
    aro_sigma: float = DEFAULT_ARO_SIGMA,
) -> dict:
    """
    Each round: pick a random likelihood and a random loss size for every risk
    group, compute that round's yearly risk, and add up. After `iterations`
    rounds we summarise the spread. The same random draws are used for the
    "now" and "after fixing everything" totals, so their difference is meaningful.
    """
    if iterations <= 0:
        raise ValueError("iterations must be positive")
    if not groups:
        raise ValueError("no risk groups to simulate")
    rng = random.Random(seed)

    per_group: Dict[str, List[float]] = {g.key: [] for g in groups}
    current: List[float] = []
    after: List[float] = []
    reduction: List[float] = []

    for _ in range(iterations):
        total_now = total_after = 0.0
        for g in groups:
            ale = _sample_aro(rng, g.aro, aro_sigma) * g.asset_value * _sample_exposure(rng, g.exposure_factor)
            per_group[g.key].append(ale)
            total_now += ale
            total_after += ale * (1.0 - g.combined_effectiveness)
        current.append(total_now)
        after.append(total_after)
        reduction.append(total_now - total_after)

    return {
        "iterations": iterations,
        "seed": seed,
        "analytical_ale": sum(g.ale for g in groups),
        "current": summarize(current),
        "after_fix": summarize(after),
        "risk_reduction": summarize(reduction),
        "per_group": {key: summarize(vals) for key, vals in per_group.items()},
    }


# ----------------------------------------------------------------------
# 2. What actually happens in a simulated year
# ----------------------------------------------------------------------
def simulate_annual_loss(
    groups: Sequence[RiskGroup],
    iterations: int = DEFAULT_ITERATIONS,
    seed: Optional[int] = None,
    aro_sigma: float = DEFAULT_ARO_SIGMA,
    thresholds: Sequence[float] = (100_000, 500_000, 1_000_000, 5_000_000),
) -> dict:
    """
    Simulates `iterations` separate years. In each year every risk group has a
    random number of incidents (usually 0). Each incident costs a random share
    of the asset's value. The same incident is "prevented" in the after-fix
    world with probability = the fix's combined effectiveness.
    """
    if iterations <= 0:
        raise ValueError("iterations must be positive")
    if not groups:
        raise ValueError("no risk groups to simulate")
    rng = random.Random(seed)

    losses_now: List[float] = []
    losses_after: List[float] = []
    years_with_incident = 0

    for _ in range(iterations):
        year_now = year_after = 0.0
        incidents = 0
        for g in groups:
            count = _poisson(rng, _sample_aro(rng, g.aro, aro_sigma))
            for _ in range(count):
                loss = g.asset_value * _sample_exposure(rng, g.exposure_factor)
                year_now += loss
                if rng.random() >= g.combined_effectiveness:  # the fix did NOT stop this one
                    year_after += loss
            incidents += count
        years_with_incident += 1 if incidents else 0
        losses_now.append(year_now)
        losses_after.append(year_after)

    return {
        "iterations": iterations,
        "seed": seed,
        "analytical_ale": sum(g.ale for g in groups),
        "probability_of_any_incident": years_with_incident / iterations,
        "current": summarize(losses_now),
        "after_fix": summarize(losses_after),
        "exceedance_now": {t: sum(1 for x in losses_now if x >= t) / iterations for t in thresholds},
        "exceedance_after_fix": {t: sum(1 for x in losses_after if x >= t) / iterations for t in thresholds},
    }


# ----------------------------------------------------------------------
# 3. Sensitivity analysis: which assumption matters most?
# ----------------------------------------------------------------------
def sensitivity_analysis(
    engine: ALEEngine,
    findings: Sequence[dict],
    base: Optional[Assumptions] = None,
) -> List[dict]:
    """
    Change ONE assumption at a time (low and high), recompute the company
    totals, and rank by how much the answer swings. The top rows are the numbers
    you should back with a real source (IBM / Verizon DBIR) first.
    """
    base = base or engine.assumptions
    reference = engine.assess_portfolio(findings, base)

    tests: List[Tuple[str, str, str, Assumptions, Assumptions]] = [
        ("How often attacks happen (all threats)", "x0.5", "x2.0",
         base.scaled(aro_multiplier=0.5), base.scaled(aro_multiplier=2.0)),
        ("Loss per incident (share of asset lost)", "x0.5", "x1.5",
         base.scaled(exposure_multiplier=0.5), base.scaled(exposure_multiplier=1.5)),
        ("Asset dollar values", "x0.8", "x1.2",
         base.scaled(value_multiplier=0.8), base.scaled(value_multiplier=1.2)),
        ("How well fixes work (control effectiveness)", "x0.8", "x1.2",
         base.scaled(effectiveness_multiplier=0.8), base.scaled(effectiveness_multiplier=1.2)),
    ]
    for threat_id in sorted({g.threat_id for g in reference.groups}):
        low = dict(base.threat_aro_multipliers)
        high = dict(base.threat_aro_multipliers)
        low[threat_id] = low.get(threat_id, 1.0) * 0.5
        high[threat_id] = high.get(threat_id, 1.0) * 2.0
        tests.append((f"How often '{threat_id}' happens", "x0.5", "x2.0",
                      Assumptions(base.aro_multiplier, base.exposure_multiplier, base.value_multiplier,
                                  base.effectiveness_multiplier, low),
                      Assumptions(base.aro_multiplier, base.exposure_multiplier, base.value_multiplier,
                                  base.effectiveness_multiplier, high)))

    rows = []
    for label, low_label, high_label, low_a, high_a in tests:
        low_r = engine.assess_portfolio(findings, low_a)
        high_r = engine.assess_portfolio(findings, high_a)
        rows.append({
            "assumption": label,
            "low_case": low_label,
            "high_case": high_label,
            "ale_low": low_r.total_ale,
            "ale_high": high_r.total_ale,
            "value_at_risk_low": low_r.total_value_at_risk,
            "value_at_risk_high": high_r.total_value_at_risk,
            "swing_ale": abs(high_r.total_ale - low_r.total_ale),
            "swing_value_at_risk": abs(high_r.total_value_at_risk - low_r.total_value_at_risk),
            "base_ale": reference.total_ale,
            "base_value_at_risk": reference.total_value_at_risk,
        })
    rows.sort(key=lambda r: (r["swing_value_at_risk"], r["swing_ale"]), reverse=True)
    return rows


if __name__ == "__main__":
    engine = ALEEngine(sample_registry())
    findings = [
        {"finding_type": "iam_mfa_disabled", "asset_id": "A-005"},
        {"finding_type": "iam_overly_permissive_policy", "asset_id": "A-005"},
        {"finding_type": "s3_bucket_public", "asset_id": "A-003"},
        {"finding_type": "rds_unencrypted", "asset_id": "A-001"},
        {"finding_type": "rds_unencrypted", "asset_id": "A-002"},
        {"finding_type": "backup_unencrypted", "asset_id": "A-006"},
        {"finding_type": "vpc_flow_logs_disabled", "asset_id": "A-007"},
    ]
    portfolio = engine.assess_portfolio(findings)

    mc = simulate_ale(portfolio.groups, seed=42)
    cur = mc["current"]
    print(f"1) HOW SURE ARE WE ABOUT THE YEARLY RISK? ({mc['iterations']:,} simulated runs)")
    print(f"   Formula answer:        {format_usd(mc['analytical_ale'])}")
    print(f"   Simulation average:    {format_usd(cur['mean'])}   (should be close to the formula)")
    for level, (lo, hi) in cur["intervals"].items():
        print(f"   {level} confident it is between {format_usd(lo)} and {format_usd(hi)}")
    red = mc["risk_reduction"]
    print(f"   Fixing everything removes about {format_usd(red['mean'])} per year "
          f"(90% range {format_usd(red['intervals']['90%'][0])} - {format_usd(red['intervals']['90%'][1])})")

    yr = simulate_annual_loss(portfolio.groups, seed=42)
    print("\n2) WHAT HAPPENS IN A SIMULATED YEAR?")
    print(f"   Chance at least one incident happens in a year: {yr['probability_of_any_incident']:.0%}")
    print(f"   Typical year (median) loss:   {format_usd(yr['current']['p50'])}")
    print(f"   Bad year (1 in 10) loss:      {format_usd(yr['current']['p90'])} or more")
    print(f"   Very bad year (1 in 100):     {format_usd(yr['current']['p99'])} or more")
    print(f"   Chance of losing >= $1M in a year: now {yr['exceedance_now'][1_000_000]:.1%}, "
          f"after fixes {yr['exceedance_after_fix'][1_000_000]:.1%}")

    print("\n3) WHICH ASSUMPTIONS MATTER MOST? (change of 'risk removed by fixes')")
    for row in sensitivity_analysis(engine, findings)[:6]:
        print(f"   {row['assumption']:48} {row['low_case']:>5}/{row['high_case']:<5} "
              f"swing {format_usd(row['swing_value_at_risk'])}")
