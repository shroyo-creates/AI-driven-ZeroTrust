"""Signal model (Table II): identity, device, context, behavior, threat intel.

Each dataclass carries only what the framework needs. Raw values that could
identify a person (IP address, precise location) are minimized in
:mod:`pbca.privacy` before they reach the risk engine or the audit log.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import IntEnum


class Sensitivity(IntEnum):
    LOW = 0       # intranet, HR self-service
    MEDIUM = 1    # internal reporting
    HIGH = 2      # customer records, payments


@dataclass(frozen=True)
class Identity:
    """Identity-provider attributes. Role level only, no personal profile."""

    user_id: str
    role: str
    peer_group: str
    account_age_days: int = 365
    mfa_method: str = "passkey"          # passkey | totp | sms | none
    privileged: bool = False
    entitlements: tuple[str, ...] = ()


@dataclass(frozen=True)
class DevicePosture:
    """Posture flags from the endpoint management agent."""

    managed: bool
    os_patch_age_days: int = 0
    edr_running: bool = True

    @property
    def compliant(self) -> bool:
        return self.managed and self.edr_running and self.os_patch_age_days <= 30


@dataclass(frozen=True)
class LoginContext:
    """Login features used by Layer 1 (IP hierarchy and user-agent hierarchy).

    ``ip`` holds a salted hash once minimized; ``asn`` and ``country`` are the
    broader levels used for smoothing unseen values.
    """

    ip: str
    asn: str
    country: str
    browser: str
    os: str
    device_type: str
    timestamp: datetime = field(default_factory=datetime.now)

    @property
    def hour(self) -> int:
        return self.timestamp.hour


@dataclass(frozen=True)
class ThreatIntel:
    """Yes/no matches only."""

    bad_ip: bool = False
    leaked_credential: bool = False


@dataclass(frozen=True)
class SessionWindow:
    """Counts and rates for one sliding behavior window (e.g. 5 minutes).

    No content of what the user looked at is kept, only how much.
    """

    records_opened: float = 0
    distinct_record_types: float = 0
    exports: float = 0
    prints: float = 0
    unusual_app_requests: float = 0
    request_rate_ratio: float = 1.0      # request rate / peer-group median

    FEATURES = (
        "records_opened",
        "distinct_record_types",
        "exports",
        "prints",
        "unusual_app_requests",
        "request_rate_ratio",
    )

    def vector(self) -> list[float]:
        return [float(getattr(self, f)) for f in self.FEATURES]

    def as_dict(self) -> dict[str, float]:
        return {k: float(v) for k, v in asdict(self).items()}


@dataclass(frozen=True)
class Resource:
    name: str
    sensitivity: Sensitivity
    customer_records: bool = False      # holds unmasked customer data


@dataclass(frozen=True)
class AccessRequest:
    """Everything signal collection gathers for one decision."""

    identity: Identity
    device: DevicePosture
    context: LoginContext
    resource: Resource
    threat: ThreatIntel = ThreatIntel()
    action: str = "read"                  # read | export | write
    mfa_satisfied: str | None = None      # factor used in this session, if any
    session_id: str | None = None
