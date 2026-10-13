"""
asset_registry.py - GovernX Risk Quantification (Week 1)

An ASSET is anything valuable the company owns that an attacker could harm:
a database, a storage bucket, a server, admin accounts, backups...

This file answers: "What do we own, and how much is it worth?"
Every risk number later in the project starts from an asset's dollar value.

Values below are MOCK numbers for the demo environment. In a real company
they would come from finance / business owners.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum, IntEnum
from typing import Dict, Iterable, List, Optional


class AssetType(str, Enum):
    """Kinds of assets. Threats (threat_library.py) say which kinds they apply to."""

    DATABASE = "database"
    STORAGE = "storage"
    SERVER = "server"
    IDENTITY = "identity"  # user / admin accounts
    NETWORK = "network"
    BACKUP = "backup"


class Sensitivity(IntEnum):
    """How private is the data? Higher = worse if it leaks."""

    PUBLIC = 1
    INTERNAL = 2
    CONFIDENTIAL = 3
    RESTRICTED = 4


class Criticality(IntEnum):
    """How badly does the business suffer if this asset stops working?"""

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class Asset:
    asset_id: str
    name: str
    asset_type: AssetType
    value_usd: float
    sensitivity: Sensitivity = Sensitivity.INTERNAL
    criticality: Criticality = Criticality.MEDIUM
    cloud_resource_id: Optional[str] = None  # e.g. an AWS ARN; links Person 1's findings to this asset
    owner: Optional[str] = None
    notes: str = ""

    def __post_init__(self) -> None:
        self.asset_type = AssetType(self.asset_type)
        self.sensitivity = Sensitivity(self.sensitivity)
        self.criticality = Criticality(self.criticality)
        if not self.asset_id:
            raise ValueError("asset_id is required")
        if self.value_usd <= 0:
            raise ValueError(f"{self.asset_id}: value_usd must be positive")

    @property
    def impact_weight(self) -> float:
        """
        Modelling assumption: more sensitive / more critical assets lose
        MORE of their value in an incident. Ranges from 1.00 (public + low)
        to 1.45 (restricted + critical). Used by risk_model.py to scale impact.
        """
        return 1.0 + 0.10 * (int(self.sensitivity) - 1) + 0.05 * (int(self.criticality) - 1)

    def to_dict(self) -> dict:
        return {
            "asset_id": self.asset_id,
            "name": self.name,
            "asset_type": self.asset_type.value,
            "value_usd": self.value_usd,
            "sensitivity": self.sensitivity.name,
            "criticality": self.criticality.name,
            "cloud_resource_id": self.cloud_resource_id,
            "owner": self.owner,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Asset":
        data = dict(data)
        for key, enum_cls in (("sensitivity", Sensitivity), ("criticality", Criticality)):
            value = data.get(key)
            if isinstance(value, str):
                data[key] = enum_cls[value.upper()]
        return cls(**data)


class AssetRegistry:
    """A simple in-memory list of assets with lookup helpers."""

    def __init__(self, assets: Optional[Iterable[Asset]] = None) -> None:
        self._assets: Dict[str, Asset] = {}
        for asset in assets or []:
            self.add(asset)

    def add(self, asset: Asset) -> None:
        if asset.asset_id in self._assets:
            raise ValueError(f"Duplicate asset_id: {asset.asset_id}")
        self._assets[asset.asset_id] = asset

    def get(self, asset_id: str) -> Asset:
        try:
            return self._assets[asset_id]
        except KeyError:
            raise KeyError(f"Unknown asset_id: {asset_id}") from None

    def find_by_cloud_id(self, cloud_resource_id: str) -> Optional[Asset]:
        for asset in self._assets.values():
            if asset.cloud_resource_id == cloud_resource_id:
                return asset
        return None

    def remove(self, asset_id: str) -> None:
        self.get(asset_id)  # raises if unknown
        del self._assets[asset_id]

    def all(self) -> List[Asset]:
        return list(self._assets.values())

    def by_type(self, asset_type: AssetType) -> List[Asset]:
        return [a for a in self._assets.values() if a.asset_type == AssetType(asset_type)]

    def total_value(self) -> float:
        return sum(a.value_usd for a in self._assets.values())

    def __len__(self) -> int:
        return len(self._assets)

    def __contains__(self, asset_id: str) -> bool:
        return asset_id in self._assets

    # ---- save / load so the team can share a registry as a JSON file ----
    def save_json(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump([a.to_dict() for a in self._assets.values()], f, indent=2)

    @classmethod
    def load_json(cls, path: str) -> "AssetRegistry":
        with open(path, "r", encoding="utf-8") as f:
            return cls(Asset.from_dict(item) for item in json.load(f))


def sample_registry() -> AssetRegistry:
    """Mock assets that match the mock AWS environment used in Week 1 demos."""
    return AssetRegistry(
        [
            Asset("A-001", "Customer Database (RDS)", AssetType.DATABASE, 5_000_000,
                  Sensitivity.RESTRICTED, Criticality.CRITICAL,
                  "arn:aws:rds:us-east-1:123456789012:db:customers-prod"),
            Asset("A-002", "Financial Database (RDS)", AssetType.DATABASE, 8_000_000,
                  Sensitivity.RESTRICTED, Criticality.CRITICAL,
                  "arn:aws:rds:us-east-1:123456789012:db:finance-prod"),
            Asset("A-003", "Customer Uploads (S3)", AssetType.STORAGE, 1_500_000,
                  Sensitivity.CONFIDENTIAL, Criticality.HIGH,
                  "arn:aws:s3:::customer-uploads-prod"),
            Asset("A-004", "Web Application Server (EC2)", AssetType.SERVER, 400_000,
                  Sensitivity.INTERNAL, Criticality.HIGH,
                  "arn:aws:ec2:us-east-1:123456789012:instance/i-0abc123"),
            Asset("A-005", "Admin IAM Accounts", AssetType.IDENTITY, 3_000_000,
                  Sensitivity.RESTRICTED, Criticality.CRITICAL,
                  "arn:aws:iam::123456789012:group/admins"),
            Asset("A-006", "Backup Vault", AssetType.BACKUP, 1_200_000,
                  Sensitivity.CONFIDENTIAL, Criticality.HIGH,
                  "arn:aws:backup:us-east-1:123456789012:backup-vault:prod"),
            Asset("A-007", "Production VPC", AssetType.NETWORK, 600_000,
                  Sensitivity.INTERNAL, Criticality.HIGH,
                  "arn:aws:ec2:us-east-1:123456789012:vpc/vpc-0prod"),
        ]
    )
