"""Domain vocabulary for Hydra's persistent EASM layer."""

from __future__ import annotations

from enum import Enum


class AssetType(str, Enum):
    DOMAIN = "domain"
    HOSTNAME = "hostname"
    IP_ADDRESS = "ip_address"
    CIDR = "cidr"
    ASN = "asn"
    CERTIFICATE = "certificate"
    CLOUD_RESOURCE = "cloud_resource"
    REPOSITORY = "repository"
    APPLICATION = "application"
    OTHER = "other"


class AssetStatus(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    UNKNOWN = "unknown"
    RETIRED = "retired"


class OwnershipState(str, Enum):
    CONFIRMED = "confirmed"
    LIKELY = "likely"
    POSSIBLE = "possible"
    UNLIKELY = "unlikely"
    REJECTED = "rejected"
    UNKNOWN = "unknown"


class AssetCriticality(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    NORMAL = "normal"
    LOW = "low"
    UNKNOWN = "unknown"


class Environment(str, Enum):
    PRODUCTION = "production"
    STAGING = "staging"
    DEVELOPMENT = "development"
    TEST = "test"
    SANDBOX = "sandbox"
    UNKNOWN = "unknown"


class AssetEventType(str, Enum):
    NEW_ASSET = "new_asset"
    ASSET_REAPPEARED = "asset_reappeared"
    ASSET_INACTIVE = "asset_inactive"
    ASSET_RETIRED = "asset_retired"
    DNS_CHANGED = "dns_changed"
    IP_CHANGED = "ip_changed"
    PORT_OPENED = "port_opened"
    PORT_CLOSED = "port_closed"
    HTTP_CHANGED = "http_changed"
    TECHNOLOGY_CHANGED = "technology_changed"
    CERTIFICATE_CHANGED = "certificate_changed"
    CERTIFICATE_EXPIRING = "certificate_expiring"
    FINDING_OPENED = "finding_opened"
    FINDING_RESOLVED = "finding_resolved"
    FINDING_REOPENED = "finding_reopened"
    OWNERSHIP_CHANGED = "ownership_changed"
    RISK_CHANGED = "risk_changed"
    CONTEXT_CHANGED = "context_changed"
