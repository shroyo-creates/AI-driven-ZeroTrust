"""PBCA: Policy-Bounded Continuous Authorization for Zero Trust IAM.

The AI risk engine supplies evidence, the policy decision point decides, and
the policy enforcement point applies the decision. The final decision is
``stricter(d_P, d_R)``, so the model can tighten access but never loosen a
mandatory rule.
"""

from .decisions import Decision, is_policy_bounded, stricter
from .policy import DEFAULT_THRESHOLDS, PolicyDecisionPoint
from .risk import LoginRiskModel, RiskEngine, SessionAnomalyModel
from .system import PBCASystem

__all__ = [
    "DEFAULT_THRESHOLDS",
    "Decision",
    "LoginRiskModel",
    "PBCASystem",
    "PolicyDecisionPoint",
    "RiskEngine",
    "SessionAnomalyModel",
    "is_policy_bounded",
    "stricter",
]

__version__ = "0.1.0"
