"""
Tests for the Week 2 risk modules (ale_engine, monte_carlo_risk, risk_translator,
business_impact_model). Week 1 tests live in test_risk_week1.py.

Run with either:
    python test_risk_week2.py
    python -m pytest -q
"""

import math

from ale_engine import ALEEngine, Assumptions
from asset_registry import Asset, AssetRegistry, AssetType, Criticality, Sensitivity, sample_registry
from business_impact_model import (
    DEFAULT_CONTROL_COSTS,
    BusinessImpactModel,
    ControlCost,
    recommendation_for,
)
from monte_carlo_risk import (
    percentile,
    sensitivity_analysis,
    simulate_ale,
    simulate_annual_loss,
    summarize,
)
from risk_translator import RiskTranslator, confidence_for, evidence_level, set_validated
from threat_library import CONTROL_GAPS, THREATS


def _raises(exc, fn, *args, **kwargs):
    try:
        fn(*args, **kwargs)
    except exc:
        return True
    return False


def _engine():
    return ALEEngine(sample_registry())


OVERLAP = [
    {"finding_type": "iam_mfa_disabled", "asset_id": "A-005"},
    {"finding_type": "iam_overly_permissive_policy", "asset_id": "A-005"},
]
MIXED = OVERLAP + [
    {"finding_type": "s3_bucket_public", "asset_id": "A-003"},
    {"finding_type": "rds_unencrypted", "asset_id": "A-001"},
    {"finding_type": "rds_unencrypted", "asset_id": "A-002"},
    {"finding_type": "backup_unencrypted", "asset_id": "A-006"},
    {"finding_type": "vpc_flow_logs_disabled", "asset_id": "A-007"},
]


# ---------------- threat library additions ----------------
def test_library_still_consistent_after_week2_additions():
    assert len(CONTROL_GAPS) == 17
    assert "T-DATA-EXFIL" in THREATS
    for gap in CONTROL_GAPS.values():
        assert gap.threat_id in THREATS


# ---------------- ale_engine ----------------
def test_single_finding_matches_week1_hand_calculation():
    a = _engine().assess_finding({"finding_type": "iam_mfa_disabled", "asset_id": "A-005"})
    assert math.isclose(a.ale_current, 217_500)
    assert math.isclose(a.value_at_risk, 174_000)
    assert a.nist_function == "PR"


def test_overlapping_gaps_are_not_double_counted():
    result = _engine().assess_portfolio(OVERLAP)
    # ALE 217,500 once. Combined effectiveness = 1 - (1-0.8)*(1-0.5) = 0.9
    assert math.isclose(result.total_ale, 217_500)
    assert math.isclose(result.total_value_at_risk, 217_500 * 0.9)
    assert math.isclose(result.naive_total_value_at_risk, 217_500 * 1.3)
    assert result.total_value_at_risk < result.naive_total_value_at_risk


def test_allocated_numbers_add_up_to_totals():
    result = _engine().assess_portfolio(MIXED)
    assert math.isclose(sum(a.allocated_value_at_risk for a in result.assessments), result.total_value_at_risk)
    assert math.isclose(sum(a.allocated_ale for a in result.assessments), result.total_ale)
    for breakdown in (result.by_asset, result.by_threat, result.by_function, result.by_category):
        assert math.isclose(sum(v["value_at_risk"] for v in breakdown.values()), result.total_value_at_risk)
        assert math.isclose(sum(v["ale"] for v in breakdown.values()), result.total_ale)


def test_duplicates_and_bad_findings_are_skipped_not_fatal():
    findings = MIXED + [
        {"finding_type": "iam_mfa_disabled", "asset_id": "A-005"},   # duplicate
        {"finding_type": "nonsense", "asset_id": "A-005"},           # unknown finding
        {"finding_type": "iam_mfa_disabled", "asset_id": "ZZZ"},     # unknown asset
        {"finding_type": "iam_mfa_disabled"},                        # no asset at all
        {"finding_type": "s3_bucket_public", "asset_id": "A-005"},   # threat does not fit asset type
    ]
    result = _engine().assess_portfolio(findings)
    assert len(result.assessments) == len(MIXED)
    assert len(result.skipped) == 5


def test_finding_can_be_matched_by_cloud_resource_id():
    arn = "arn:aws:s3:::customer-uploads-prod"
    a = _engine().assess_finding({"finding_type": "s3_bucket_public", "cloud_resource_id": arn})
    assert a.asset_id == "A-003"
    assert _raises(KeyError, _engine().assess_finding,
                   {"finding_type": "s3_bucket_public", "resource_id": "arn:aws:s3:::nope"})


def test_assumption_multipliers():
    engine = _engine()
    finding = {"finding_type": "iam_mfa_disabled", "asset_id": "A-005"}
    base = engine.assess_finding(finding).ale_current
    assert math.isclose(engine.assess_finding(finding, Assumptions(aro_multiplier=2)).ale_current, base * 2)
    assert math.isclose(engine.assess_finding(finding, Assumptions(value_multiplier=0.5)).ale_current, base * 0.5)
    only_threat = Assumptions(threat_aro_multipliers={"T-ACCOUNT-TAKEOVER": 3})
    assert math.isclose(engine.assess_finding(finding, only_threat).ale_current, base * 3)
    assert _raises(ValueError, Assumptions, aro_multiplier=-1)


def test_effectiveness_is_capped_at_100_percent():
    a = _engine().assess_finding({"finding_type": "s3_bucket_public", "asset_id": "A-003"},
                                 Assumptions(effectiveness_multiplier=5))
    assert a.control_effectiveness == 1.0
    assert math.isclose(a.ale_after_fix, 0.0, abs_tol=1e-9)


def test_risk_after_fixing_is_overlap_aware():
    engine = _engine()
    result = engine.assess_portfolio(OVERLAP)
    only_mfa = engine.risk_after_fixing(result, [("A-005", "iam_mfa_disabled")])
    both = engine.risk_after_fixing(result, [("A-005", "iam_mfa_disabled"),
                                             ("A-005", "iam_overly_permissive_policy")])
    none = engine.risk_after_fixing(result, [])
    assert math.isclose(only_mfa["risk_reduced"], 217_500 * 0.8)
    assert math.isclose(both["risk_reduced"], result.total_value_at_risk)
    assert none["risk_reduced"] == 0
    assert _raises(ValueError, engine.risk_after_fixing, result, [("A-001", "iam_mfa_disabled")])


def test_portfolio_to_dict_is_json_friendly():
    import json

    result = _engine().assess_portfolio(MIXED)
    text = json.dumps(result.to_dict())
    assert "total_value_at_risk" in text


# ---------------- monte_carlo_risk ----------------
def test_percentile_and_summary_basics():
    assert percentile([1, 2, 3, 4, 5], 50) == 3
    s = summarize(range(1, 1001))
    assert s["min"] == 1 and s["max"] == 1000
    lo90, hi90 = s["intervals"]["90%"]
    lo99, hi99 = s["intervals"]["99%"]
    assert lo99 < lo90 < hi90 < hi99


def test_monte_carlo_is_reproducible_with_seed():
    groups = _engine().assess_portfolio(MIXED).groups
    a = simulate_ale(groups, iterations=2000, seed=11)
    b = simulate_ale(groups, iterations=2000, seed=11)
    c = simulate_ale(groups, iterations=2000, seed=12)
    assert a["current"]["mean"] == b["current"]["mean"]
    assert a["current"]["mean"] != c["current"]["mean"]


def test_monte_carlo_average_matches_formula():
    groups = _engine().assess_portfolio(MIXED).groups
    mc = simulate_ale(groups, iterations=10_000, seed=1)
    assert abs(mc["current"]["mean"] / mc["analytical_ale"] - 1) < 0.05


def test_confidence_intervals_nest_and_contain_the_estimate():
    groups = _engine().assess_portfolio(MIXED).groups
    cur = simulate_ale(groups, iterations=10_000, seed=2)["current"]
    (lo90, hi90), (lo95, hi95), (lo99, hi99) = (cur["intervals"][k] for k in ("90%", "95%", "99%"))
    assert lo99 <= lo95 <= lo90 < hi90 <= hi95 <= hi99
    assert lo90 < sum(g.ale for g in groups) < hi90


def test_fixing_reduces_simulated_risk():
    groups = _engine().assess_portfolio(MIXED).groups
    mc = simulate_ale(groups, iterations=3000, seed=3)
    assert mc["after_fix"]["mean"] < mc["current"]["mean"]
    expected_reduction = sum(g.value_at_risk for g in groups)
    assert abs(mc["risk_reduction"]["mean"] / expected_reduction - 1) < 0.08


def test_annual_loss_simulation():
    groups = _engine().assess_portfolio(MIXED).groups
    yr = simulate_annual_loss(groups, iterations=10_000, seed=4)
    total_aro = sum(g.aro for g in groups)
    expected_p_any = 1 - math.exp(-total_aro)
    assert abs(yr["probability_of_any_incident"] - expected_p_any) < 0.03
    assert abs(yr["current"]["mean"] / yr["analytical_ale"] - 1) < 0.12
    assert yr["after_fix"]["mean"] < yr["current"]["mean"]
    assert yr["current"]["p50"] <= yr["current"]["p90"] <= yr["current"]["p99"]
    assert yr["exceedance_now"][100_000] >= yr["exceedance_now"][1_000_000]


def test_simulation_input_checks():
    groups = _engine().assess_portfolio(MIXED).groups
    assert _raises(ValueError, simulate_ale, groups, iterations=0)
    assert _raises(ValueError, simulate_ale, [], iterations=10)
    assert _raises(ValueError, simulate_annual_loss, [], iterations=10)


def test_sensitivity_analysis_is_ranked_and_consistent():
    engine = _engine()
    rows = sensitivity_analysis(engine, MIXED)
    swings = [r["swing_value_at_risk"] for r in rows]
    assert swings == sorted(swings, reverse=True)
    base = engine.assess_portfolio(MIXED)
    assert all(math.isclose(r["base_ale"], base.total_ale) for r in rows)
    aro_row = next(r for r in rows if r["assumption"].startswith("How often attacks happen"))
    # ALE is proportional to ARO, so x0.5 and x2.0 give exactly half and double
    assert math.isclose(aro_row["ale_low"], base.total_ale * 0.5)
    assert math.isclose(aro_row["ale_high"], base.total_ale * 2.0)


# ---------------- risk_translator ----------------
def test_translation_statement_and_scenarios():
    translator = RiskTranslator(_engine(), iterations=2000, seed=5)
    impact = translator.translate({"finding_type": "iam_mfa_disabled", "asset_id": "A-002"})
    assert math.isclose(impact.ale, 580_000)          # 8M x (0.25 x 1.45) x 0.20
    assert math.isclose(impact.value_at_risk, 464_000)
    assert impact.scenarios["best"] < impact.scenarios["likely"] < impact.scenarios["worst"]
    assert math.isclose(impact.scenarios["likely"], impact.ale)
    assert impact.ale_range_90[0] < impact.ale < impact.ale_range_90[1]
    assert "$580.0K" in impact.statement and "Financial Database" in impact.statement


def test_translate_many_skips_bad_findings_and_portfolio_total_dedups():
    translator = RiskTranslator(_engine(), iterations=500, seed=6)
    out = translator.translate_portfolio(OVERLAP + [{"finding_type": "bogus", "asset_id": "A-005"}])
    assert len(out["impacts"]) == 2 and len(out["skipped"]) == 1
    assert math.isclose(out["total_value_at_risk"], 217_500 * 0.9)
    assert out["impacts"][0].value_at_risk >= out["impacts"][1].value_at_risk


def test_confidence_levels_follow_evidence():
    asset = sample_registry().get("A-005")
    assert evidence_level("T-ACCOUNT-TAKEOVER") == "illustrative"
    assert confidence_for(asset, "T-ACCOUNT-TAKEOVER")[0] == "Low"
    owned = Asset("X-1", "Owned", AssetType.IDENTITY, 1_000_000, Sensitivity.INTERNAL,
                  Criticality.MEDIUM, owner="CFO")
    assert confidence_for(owned, "T-ACCOUNT-TAKEOVER")[0] == "Low"      # 0 + 1
    set_validated("T-ACCOUNT-TAKEOVER")
    try:
        assert evidence_level("T-ACCOUNT-TAKEOVER") == "validated"
        assert confidence_for(owned, "T-ACCOUNT-TAKEOVER")[0] == "High"  # 2 + 1
        assert confidence_for(asset, "T-ACCOUNT-TAKEOVER")[0] == "Medium"  # 2 + 0
    finally:
        from risk_translator import _VALIDATED_THREATS
        _VALIDATED_THREATS.discard("T-ACCOUNT-TAKEOVER")
    assert _raises(KeyError, set_validated, "T-NOPE")


# ---------------- business_impact_model ----------------
def test_every_known_finding_type_has_a_cost():
    assert set(CONTROL_GAPS) <= set(DEFAULT_CONTROL_COSTS)


def test_roi_payback_and_npv_hand_calculation():
    model = BusinessImpactModel(_engine(), costs={"x": ControlCost(10_000, 2_000)},
                                horizon_years=3, discount_rate=0.10)
    case = model.case_for("A", "Asset", "x", "Title", annual_benefit=20_000)
    assert case.total_benefit == 60_000
    assert case.total_cost == 16_000                     # 10,000 + 2,000 x 3
    assert case.net_benefit == 44_000
    assert math.isclose(case.roi_pct, 275.0)
    assert math.isclose(case.benefit_cost_ratio, 3.75)
    assert math.isclose(case.payback_years, 10_000 / 18_000)
    expected_npv = -10_000 + sum(18_000 / 1.1 ** t for t in (1, 2, 3))
    assert math.isclose(case.npv, expected_npv)
    assert case.recommendation.startswith("Do first")


def test_fix_that_never_pays_back():
    model = BusinessImpactModel(_engine(), costs={"y": ControlCost(5_000, 9_000)})
    case = model.case_for("A", "Asset", "y", "Title", annual_benefit=4_000)
    assert case.payback_years is None
    assert case.net_benefit < 0
    assert case.recommendation.startswith("Weak")


def test_free_fix_does_not_divide_by_zero():
    model = BusinessImpactModel(_engine(), costs={"z": ControlCost(0, 0)})
    case = model.case_for("A", "Asset", "z", "Title", annual_benefit=1_000)
    assert case.roi_pct is None and case.benefit_cost_ratio is None and case.payback_years == 0.0


def test_recommendation_thresholds():
    assert recommendation_for(5).startswith("Do first")
    assert recommendation_for(1.5) == "Worth doing"
    assert recommendation_for(0.5).startswith("Weak")


def test_cases_sorted_best_return_first():
    engine = _engine()
    model = BusinessImpactModel(engine)
    cases = model.build_cases(engine.assess_portfolio(MIXED))
    ratios = [c.benefit_cost_ratio for c in cases]
    assert ratios == sorted(ratios, reverse=True)


def test_budget_is_never_exceeded_and_risk_is_consistent():
    engine = _engine()
    model = BusinessImpactModel(engine)
    portfolio = engine.assess_portfolio(MIXED)
    for budget in (0, 5_000, 30_000, 100_000, 1_000_000):
        plan = model.budget_justification(portfolio, budget)
        assert plan["spent_year_one"] <= budget + 1e-9
        assert math.isclose(plan["spent_year_one"] + plan["budget_left"], budget)
        assert math.isclose(plan["ale_before"] - plan["ale_after"], plan["risk_reduced_per_year"])
        assert all(c.net_benefit > 0 for c in plan["chosen"])
    small = model.budget_justification(portfolio, 5_000)
    big = model.budget_justification(portfolio, 1_000_000)
    assert big["risk_reduced_per_year"] >= small["risk_reduced_per_year"]
    assert model.budget_justification(portfolio, 0)["chosen"] == []
    assert _raises(ValueError, model.budget_justification, portfolio, -1)


def test_unlimited_budget_skips_only_uneconomic_fixes():
    engine = _engine()
    model = BusinessImpactModel(engine)
    portfolio = engine.assess_portfolio(MIXED)
    plan = model.budget_justification(portfolio, 10_000_000)
    skipped = {p["case"].finding_type for p in plan["passed_over"]}
    assert skipped == {"vpc_flow_logs_disabled"}       # costs more than the $5.8K/yr it removes
    assert plan["statement"].startswith("With a year-one budget")


if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"PASS  {name}")
        except Exception as err:  # noqa: BLE001
            failed += 1
            print(f"FAIL  {name}: {err!r}")
    print(f"\n{len(tests) - failed}/{len(tests)} tests passed")
    raise SystemExit(1 if failed else 0)
