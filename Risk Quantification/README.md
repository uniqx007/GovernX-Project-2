# Risk Quantification (Person 3) - Week 1

Turns technical security findings into dollar figures (ALE / "value at risk") for the GovernX board dashboard.

## Files

| File | What it does |
|---|---|
| `asset_registry.py` | List of valuable assets (databases, buckets, servers...) with dollar values, sensitivity and criticality |
| `threat_library.py` | Threats (likelihood + damage), and the map from scanner findings / NIST subcategories to threats |
| `ale_calculator.py` | The formulas: SLE, ALE, control effectiveness, portfolio total |
| `risk_model.py` | Combines the three above: finding + asset -> ALE and value at risk. Includes Monte Carlo setup |
| `test_risk_week1.py` | Tests |

## The maths

```
SLE = asset value x exposure factor        (loss per incident)
ALE = ARO x SLE                            (expected loss per year)
Value at risk of a gap = ALE x control effectiveness   (yearly risk removed if the gap is fixed)
```

## Run it

Needs only Python 3.9+ (no extra packages).

```bash
cd risk_quantification
python ale_calculator.py      # tiny worked example
python risk_model.py          # full demo on the mock AWS environment
python test_risk_week1.py     # run tests
```

## How other people's code plugs in

```python
from asset_registry import sample_registry
from risk_model import RiskModel

model = RiskModel(sample_registry())
assessment = model.assess_finding({"finding_type": "iam_mfa_disabled", "asset_id": "A-005"})
print(assessment.to_dict())     # JSON-friendly dict for the API / dashboard
```

- Person 1 (scanner): use the labels from `threat_library.supported_finding_types()` as `finding_type`.
- Person 2 (NIST mapping): the NIST IDs live in `CONTROL_GAPS` in `threat_library.py`; please confirm them.
- Person 4 (dashboard): consume `RiskAssessment.to_dict()` and `RiskModel.summarize()`.

## Assumptions

All probabilities, exposure factors and control-effectiveness values are illustrative baselines.
They will be replaced / justified with published sources (IBM Cost of a Data Breach, Verizon DBIR) and cited in the `source` field.
