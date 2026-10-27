# Risk Quantification (Person 3)

Turns technical security findings into dollar figures for the GovernX board dashboard.
Week 1 built the foundation. Week 2 adds the full ALE engine, risk translation, Monte Carlo simulation and business-case maths.

## Files

| File | Week | What it does |
|---|---|---|
| `asset_registry.py` | 1 | Valuable assets (databases, buckets, servers...) with dollar value, sensitivity, criticality |
| `threat_library.py` | 1, updated 2 | Threats (likelihood + damage), and the map from scanner finding types / NIST subcategories to threats. Now 17 finding types |
| `ale_calculator.py` | 1 | Basic formulas: SLE, ALE, control effectiveness |
| `risk_model.py` | 1 | Simple finding + asset -> ALE, first Monte Carlo setup |
| `ale_engine.py` | 2 | Company-wide ALE for a list of findings, **no double counting** of overlapping gaps, what-if scenarios, breakdowns by asset / threat / NIST function / category |
| `risk_translator.py` | 2 | Finding -> board-ready financial statement, best/likely/worst scenarios, Low/Medium/High confidence |
| `monte_carlo_risk.py` | 2 | 10,000-run simulation: 90/95/99% confidence intervals, simulated years of losses, sensitivity analysis |
| `business_impact_model.py` | 2 | ROI, payback, NPV, benefit-cost ratio per fix, and a budget justification |
| `test_risk_week1.py`, `test_risk_week2.py` | 1, 2 | Tests (44 in total) |

## The maths

```
SLE = asset value x exposure factor            loss each time it happens
ALE = ARO x SLE                                expected loss per year
Value at risk of a fix = ALE x control effectiveness   yearly risk removed

Two gaps on the same asset+threat:  combined effect = 1 - (1 - e1) x (1 - e2)   (not e1 + e2)

ROI %              = (total benefit - total cost) / total cost x 100
Benefit-cost ratio = total benefit / total cost
Payback            = one-time cost / (yearly benefit - yearly running cost)
```

## Run it

Needs only Python 3.9+ (no extra packages). Keep all files in one folder.

```bash
python ale_engine.py              # company-wide risk, overlap handling, what-if
python risk_translator.py         # the plan's three examples as board statements
python monte_carlo_risk.py        # 10,000-run simulation + sensitivity ranking
python business_impact_model.py   # ROI per fix + budget justification
python test_risk_week1.py         # Week 1 tests
python test_risk_week2.py         # Week 2 tests
```

On Mac or Linux use `python3`.

## How other people's code plugs in

```python
from asset_registry import sample_registry
from ale_engine import ALEEngine
from risk_translator import RiskTranslator
from business_impact_model import BusinessImpactModel

engine = ALEEngine(sample_registry())
findings = [
    {"finding_type": "iam_mfa_disabled", "asset_id": "A-005"},
    {"finding_type": "s3_bucket_public", "cloud_resource_id": "arn:aws:s3:::customer-uploads-prod"},
]

portfolio = engine.assess_portfolio(findings)
portfolio.to_dict()                       # JSON for the API / dashboard (totals + breakdowns)

RiskTranslator(engine).translate(findings[0]).to_dict()      # one finding, with statement
BusinessImpactModel(engine).budget_justification(portfolio, 50_000)["statement"]
```

A finding identifies its asset with either `asset_id` or the scanner's `cloud_resource_id` / `resource_id` (e.g. an AWS ARN).
Bad findings (unknown type, unknown asset, duplicates) are skipped and listed in `skipped` instead of crashing.

- **Person 1 (scanner):** use the labels from `threat_library.supported_finding_types()` as `finding_type`.
- **Person 2 (NIST mapping):** NIST IDs live in `CONTROL_GAPS` in `threat_library.py`; please confirm them. `by_function` / `by_category` in the portfolio output use these.
- **Person 4 (dashboard):** use `PortfolioResult.to_dict()` (`total_ale`, `total_value_at_risk`, `by_function`, `by_category`, `by_asset`), `FinancialImpact.to_dict()` and `BusinessCase.to_dict()`.

## Assumptions to replace before the final demo

All of these are illustrative placeholders:

1. Threat likelihood (ARO), loss per incident and control effectiveness in `threat_library.py`. Replace with figures from IBM Cost of a Data Breach / Verizon DBIR and write the source in each threat's `source` field. Confidence in `risk_translator.py` rises automatically when the source is no longer "illustrative".
2. Asset values in `asset_registry.py`. Set `owner=` once the business confirms a value.
3. Control costs in `business_impact_model.py` (`DEFAULT_CONTROL_COSTS`). Replace with real quotes / pricing.

Modelling assumptions: the simulated risks are independent of each other; likelihood uncertainty is lognormal (sigma 0.5, roughly "within a factor of 2"); loss per incident is triangular from 50% to 150% of the estimate; fixes remove incidents with probability equal to their effectiveness.
