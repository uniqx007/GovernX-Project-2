"""
Tests for the Week 1 risk quantification modules.

Run with either:
    python test_risk_week1.py
    python -m pytest -q          (if you have pytest installed)
"""

import math

from ale_calculator import (
    annualized_loss_expectancy,
    format_usd,
    portfolio_ale,
    residual_ale,
    risk_reduction,
    single_loss_expectancy,
)
from asset_registry import Asset, AssetRegistry, AssetType, Criticality, Sensitivity, sample_registry
from risk_model import RiskModel
from threat_library import (
    CONTROL_GAPS,
    THREATS,
    gaps_for_nist,
    supported_finding_types,
    threat_for_finding,
    threats_for_asset_type,
)


def _raises(exc, fn, *args, **kwargs):
    try:
        fn(*args, **kwargs)
    except exc:
        return True
    return False


# ---------------- ale_calculator ----------------
def test_sle_and_ale_formula():
    sle = single_loss_expectancy(5_000_000, 0.6)
    assert math.isclose(sle, 3_000_000)
    assert math.isclose(annualized_loss_expectancy(0.1, sle), 300_000)


def test_control_effectiveness():
    assert math.isclose(residual_ale(300_000, 0.8), 60_000)
    assert math.isclose(risk_reduction(300_000, 0.8), 240_000)


def test_invalid_inputs_rejected():
    assert _raises(ValueError, single_loss_expectancy, 1000, 1.5)
    assert _raises(ValueError, annualized_loss_expectancy, -1, 100)
    assert _raises(ValueError, residual_ale, 100, 2)


def test_portfolio_and_format():
    assert portfolio_ale([1, 2, 3]) == 6
    assert format_usd(1_200_000) == "$1.20M"
    assert format_usd(450_000) == "$450.0K"
    assert format_usd(500) == "$500"


# ---------------- asset_registry ----------------
def test_registry_add_get_total():
    reg = sample_registry()
    assert len(reg) == 7
    assert reg.get("A-001").asset_type == AssetType.DATABASE
    assert reg.total_value() == 19_700_000
    assert len(reg.by_type(AssetType.DATABASE)) == 2


def test_registry_errors():
    reg = sample_registry()
    assert _raises(KeyError, reg.get, "NOPE")
    dup = Asset("A-001", "dup", AssetType.SERVER, 1)
    assert _raises(ValueError, reg.add, dup)
    assert _raises(ValueError, Asset, "X", "bad", AssetType.SERVER, 0)


def test_impact_weight_range():
    low = Asset("L", "low", AssetType.SERVER, 1, Sensitivity.PUBLIC, Criticality.LOW)
    high = Asset("H", "high", AssetType.SERVER, 1, Sensitivity.RESTRICTED, Criticality.CRITICAL)
    assert math.isclose(low.impact_weight, 1.0)
    assert math.isclose(high.impact_weight, 1.45)


def test_registry_json_roundtrip(tmp_path=None):
    import os
    import tempfile

    reg = sample_registry()
    folder = str(tmp_path) if tmp_path else tempfile.mkdtemp()
    path = os.path.join(folder, "assets.json")
    reg.save_json(path)
    loaded = AssetRegistry.load_json(path)
    assert len(loaded) == len(reg)
    assert loaded.get("A-005").sensitivity == Sensitivity.RESTRICTED


# ---------------- threat_library ----------------
def test_every_gap_points_to_real_threat():
    for gap in CONTROL_GAPS.values():
        assert gap.threat_id in THREATS


def test_lookups():
    threat, gap = threat_for_finding("iam_mfa_disabled")
    assert threat.threat_id == "T-ACCOUNT-TAKEOVER"
    assert gap.nist_subcategory == "PR.AA-03"
    assert gaps_for_nist("PR.DS-01")
    assert threats_for_asset_type(AssetType.IDENTITY)
    assert "s3_bucket_public" in supported_finding_types()


# ---------------- risk_model ----------------
def test_assess_matches_hand_calculation():
    model = RiskModel(sample_registry())
    a = model.assess(model.registry.get("A-005"), "iam_mfa_disabled")
    # exposure = 0.25 * 1.45 = 0.3625 ; SLE = 3M * 0.3625 = 1,087,500 ; ALE = 0.20 * SLE = 217,500
    assert math.isclose(a.exposure_factor, 0.3625)
    assert math.isclose(a.sle, 1_087_500)
    assert math.isclose(a.ale_current, 217_500)
    assert math.isclose(a.value_at_risk, 217_500 * 0.8)
    assert math.isclose(a.ale_current - a.ale_after_fix, a.value_at_risk)


def test_wrong_asset_type_rejected():
    model = RiskModel(sample_registry())
    # S3 public-access threat does not apply to an identity asset
    assert _raises(ValueError, model.assess, model.registry.get("A-005"), "s3_bucket_public")


def test_batch_skips_bad_findings():
    model = RiskModel(sample_registry())
    findings = [
        {"finding_type": "iam_mfa_disabled", "asset_id": "A-005"},
        {"finding_type": "made_up_finding", "asset_id": "A-005"},
        {"finding_type": "iam_mfa_disabled", "asset_id": "ZZZ"},
    ]
    done, skipped = model.assess_findings(findings)
    assert len(done) == 1 and len(skipped) == 2


def test_summary_totals():
    model = RiskModel(sample_registry())
    done, _ = model.assess_findings([
        {"finding_type": "iam_mfa_disabled", "asset_id": "A-005"},
        {"finding_type": "rds_unencrypted", "asset_id": "A-001"},
    ])
    s = model.summarize(done)
    assert s["findings"] == 2
    assert math.isclose(s["total_value_at_risk"], sum(a.value_at_risk for a in done))
    assert s["top_risks"][0][2] >= s["top_risks"][1][2]


def test_monte_carlo_reproducible_and_ordered():
    model = RiskModel(sample_registry())
    asset = model.registry.get("A-005")
    r1 = model.monte_carlo(asset, "iam_mfa_disabled", iterations=2000, seed=7)
    r2 = model.monte_carlo(asset, "iam_mfa_disabled", iterations=2000, seed=7)
    assert r1 == r2
    assert r1["p5"] <= r1["p50"] <= r1["p95"] <= r1["p99"]
    # the simulated mean should land near the formula answer (same order of magnitude)
    assert 0.5 * r1["analytical_ale"] < r1["mean"] < 2 * r1["analytical_ale"]


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
