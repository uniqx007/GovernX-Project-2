"""
threat_library.py - GovernX Risk Quantification (Week 1 & 2)

A THREAT is something bad that could happen (data breach, ransomware...).
A CONTROL is a protection that reduces the chance/impact of a threat (MFA, encryption...).
A CONTROL GAP is a missing control. Person 1's scanner reports gaps as "findings".

This file answers three questions:
  1. What threats exist, how likely are they, and how much damage do they do?
  2. Which threat does each kind of finding (e.g. "MFA disabled") make worse?
  3. If we fix that finding, by what % does the risk drop?

!! IMPORTANT !!
Every number below is an ILLUSTRATIVE BASELINE ASSUMPTION so the model runs.
Before the final demo, replace/justify them with real sources such as the
IBM "Cost of a Data Breach" report and the Verizon DBIR, and note the source
in the `source` field. Defensible numbers are what make this credible.

The NIST CSF 2.0 IDs are in ONE place (CONTROL_GAPS) so they are easy to
change after you sync with Person 2 (NIST mapping owner).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Tuple

from asset_registry import AssetType


@dataclass(frozen=True)
class Threat:
    threat_id: str
    name: str
    description: str
    base_aro: float          # expected incidents per year (0.10 = about once every 10 years)
    exposure_factor: float   # share of an asset's value lost per incident (0.30 = 30%)
    applicable_asset_types: Tuple[AssetType, ...]
    source: str = "Illustrative assumption - validate with IBM Cost of a Data Breach / Verizon DBIR"

    def __post_init__(self) -> None:
        if self.base_aro <= 0:
            raise ValueError(f"{self.threat_id}: base_aro must be positive")
        if not 0 < self.exposure_factor <= 1:
            raise ValueError(f"{self.threat_id}: exposure_factor must be in (0, 1]")

    @property
    def aro_low(self) -> float:
        """Optimistic end of the likelihood range (used by Monte Carlo)."""
        return self.base_aro * 0.5

    @property
    def aro_high(self) -> float:
        """Pessimistic end of the likelihood range (used by Monte Carlo)."""
        return self.base_aro * 2.0

    def applies_to(self, asset_type: AssetType) -> bool:
        return AssetType(asset_type) in self.applicable_asset_types


@dataclass(frozen=True)
class ControlGap:
    finding_type: str            # the label the scanner puts on a finding
    title: str
    nist_subcategory: str        # NIST CSF 2.0 ID - confirm with Person 2
    threat_id: str               # the threat this gap makes worse
    control_effectiveness: float # fraction of the risk removed if the gap is fixed (0.8 = 80%)

    def __post_init__(self) -> None:
        if not 0 < self.control_effectiveness <= 1:
            raise ValueError(f"{self.finding_type}: control_effectiveness must be in (0, 1]")


_ALL = tuple(AssetType)

THREATS: Dict[str, Threat] = {
    t.threat_id: t
    for t in [
        Threat("T-DATA-BREACH", "Data breach / data theft",
               "Attacker steals sensitive data from storage, a database, a server or a backup.",
               base_aro=0.10, exposure_factor=0.30,
               applicable_asset_types=(AssetType.DATABASE, AssetType.STORAGE,
                                       AssetType.SERVER, AssetType.BACKUP)),
        Threat("T-DATA-EXPOSURE", "Accidental public data exposure",
               "Data is left open to the internet by a misconfiguration and gets found.",
               base_aro=0.15, exposure_factor=0.25,
               applicable_asset_types=(AssetType.STORAGE, AssetType.DATABASE, AssetType.BACKUP)),
        Threat("T-ACCOUNT-TAKEOVER", "Account / credential takeover",
               "Attacker logs in with stolen or guessed credentials and abuses the access.",
               base_aro=0.20, exposure_factor=0.25,
               applicable_asset_types=(AssetType.IDENTITY, AssetType.DATABASE,
                                       AssetType.STORAGE, AssetType.SERVER)),
        Threat("T-NETWORK-INTRUSION", "Network intrusion",
               "Attacker gets in through exposed network services and moves around.",
               base_aro=0.12, exposure_factor=0.20,
               applicable_asset_types=(AssetType.SERVER, AssetType.DATABASE, AssetType.NETWORK)),
        Threat("T-UNDETECTED-INTRUSION", "Intrusion goes undetected",
               "Without logging/monitoring an attack lasts longer and costs more.",
               base_aro=0.10, exposure_factor=0.20,
               applicable_asset_types=_ALL),
        Threat("T-DATA-LOSS", "Data loss / no recovery",
               "Data is destroyed (ransomware, mistake, outage) and cannot be restored.",
               base_aro=0.05, exposure_factor=0.50,
               applicable_asset_types=(AssetType.BACKUP, AssetType.DATABASE, AssetType.STORAGE)),
        # ---- added in Week 2 ----
        Threat("T-DATA-EXFIL", "Data exfiltration",
               "Someone (outsider or insider) copies large amounts of data out of the company unnoticed.",
               base_aro=0.08, exposure_factor=0.35,
               applicable_asset_types=(AssetType.DATABASE, AssetType.STORAGE,
                                       AssetType.SERVER, AssetType.BACKUP)),
    ]
}

# finding_type -> which threat it worsens, its NIST CSF 2.0 subcategory, and
# how much risk disappears when it is fixed.
CONTROL_GAPS: Dict[str, ControlGap] = {
    g.finding_type: g
    for g in [
        ControlGap("iam_mfa_disabled", "MFA not enabled on accounts",
                   "PR.AA-03", "T-ACCOUNT-TAKEOVER", 0.80),
        ControlGap("iam_overly_permissive_policy", "IAM policy grants excessive permissions",
                   "PR.AA-05", "T-ACCOUNT-TAKEOVER", 0.50),
        ControlGap("s3_bucket_public", "S3 bucket is publicly accessible",
                   "PR.AA-05", "T-DATA-EXPOSURE", 0.90),
        ControlGap("ec2_volume_unencrypted", "EC2 disk volume not encrypted",
                   "PR.DS-01", "T-DATA-BREACH", 0.50),
        ControlGap("rds_unencrypted", "RDS database not encrypted at rest",
                   "PR.DS-01", "T-DATA-BREACH", 0.50),
        ControlGap("backup_unencrypted", "Backups are not encrypted",
                   "PR.DS-11", "T-DATA-BREACH", 0.50),
        ControlGap("backup_missing", "No backups configured",
                   "PR.DS-11", "T-DATA-LOSS", 0.80),
        ControlGap("security_group_open_to_world", "Security group open to the whole internet",
                   "PR.IR-01", "T-NETWORK-INTRUSION", 0.70),
        ControlGap("vpc_flow_logs_disabled", "VPC flow logs disabled",
                   "DE.CM-01", "T-UNDETECTED-INTRUSION", 0.40),
        # ---- added in Week 2 (matches the wider check library Person 1 is building) ----
        ControlGap("root_account_no_mfa", "Root account has no MFA",
                   "PR.AA-03", "T-ACCOUNT-TAKEOVER", 0.85),
        ControlGap("weak_password_policy", "Weak password policy",
                   "PR.AA-01", "T-ACCOUNT-TAKEOVER", 0.35),
        ControlGap("access_keys_not_rotated", "Access keys not rotated",
                   "PR.AA-01", "T-ACCOUNT-TAKEOVER", 0.30),
        ControlGap("s3_unencrypted", "S3 bucket not encrypted at rest",
                   "PR.DS-01", "T-DATA-BREACH", 0.50),
        ControlGap("tls_not_enforced", "Encryption in transit (TLS) not enforced",
                   "PR.DS-02", "T-DATA-BREACH", 0.40),
        ControlGap("rds_publicly_accessible", "RDS database reachable from the internet",
                   "PR.IR-01", "T-DATA-EXPOSURE", 0.80),
        ControlGap("cloudtrail_disabled", "CloudTrail audit logging disabled",
                   "DE.CM-03", "T-UNDETECTED-INTRUSION", 0.50),
        ControlGap("dlp_not_configured", "No data loss prevention (DLP) controls",
                   "PR.DS-02", "T-DATA-EXFIL", 0.60),
    ]
}


def _validate_library() -> None:
    for gap in CONTROL_GAPS.values():
        if gap.threat_id not in THREATS:
            raise ValueError(f"{gap.finding_type} points to unknown threat {gap.threat_id}")


_validate_library()


def get_threat(threat_id: str) -> Threat:
    try:
        return THREATS[threat_id]
    except KeyError:
        raise KeyError(f"Unknown threat_id: {threat_id}") from None


def get_control_gap(finding_type: str) -> ControlGap:
    try:
        return CONTROL_GAPS[finding_type]
    except KeyError:
        raise KeyError(f"Unknown finding_type: {finding_type}") from None


def threat_for_finding(finding_type: str) -> Tuple[Threat, ControlGap]:
    gap = get_control_gap(finding_type)
    return get_threat(gap.threat_id), gap


def threats_for_asset_type(asset_type: AssetType) -> List[Threat]:
    return [t for t in THREATS.values() if t.applies_to(asset_type)]


def gaps_for_nist(nist_subcategory: str) -> List[ControlGap]:
    """NIST control -> the gaps (and so threats) linked to it."""
    return [g for g in CONTROL_GAPS.values() if g.nist_subcategory == nist_subcategory]


def supported_finding_types() -> List[str]:
    """Share this list with Person 1 so scanner labels match exactly."""
    return sorted(CONTROL_GAPS)
