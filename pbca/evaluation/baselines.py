"""The four compared setups (Section V-I).

B0    MFA at every login, no risk scoring.
B1    Fixed conditional-access rules: country mismatch, unmanaged device,
      known bad IP (close to the baseline in Freeman et al.).
B2    The same two-layer risk model as PBCA, but it decides access directly,
      including relaxing the mandatory policy decision d_P.
PBCA  The policy-bounded framework: d = stricter(d_P, d_R).

B0 and B1 contain no learned component, so they also enforce the
organization's mandatory rules (``stricter`` with d_P). Neither re-evaluates
a session after login.

Every setup answers the same question for an event: which decision, and with
what continuous score (for ROC curves).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from ..decisions import Decision, stricter
from ..policy import PolicyDecisionPoint
from ..risk.engine import RiskAssessment
from ..signals import AccessRequest


@dataclass
class Verdict:
    decision: Decision
    score: float
    d_policy: Decision


class Setup(Protocol):
    name: str

    def evaluate(self, req: AccessRequest, assessment: RiskAssessment, home_country: str) -> Verdict: ...


class B0MfaEverywhere:
    name = "B0 MFA always"
    sees_sessions = False

    def __init__(self, pdp: PolicyDecisionPoint):
        self.pdp = pdp

    def evaluate(self, req, assessment, home_country):
        d_p, _ = self.pdp.policy_decision(req)
        return Verdict(stricter(d_p, Decision.STEP_UP), 1.0, d_p)


class B1StaticRules:
    name = "B1 static rules"
    sees_sessions = False

    def __init__(self, pdp: PolicyDecisionPoint):
        self.pdp = pdp

    def evaluate(self, req, assessment, home_country):
        d_p, _ = self.pdp.policy_decision(req)
        hits = sum([
            req.context.country != home_country,
            not req.device.managed,
            req.threat.bad_ip,
        ])
        d = Decision.DENY if req.threat.bad_ip else (Decision.STEP_UP if hits else Decision.ALLOW)
        return Verdict(stricter(d_p, d), hits / 3, d_p)


class B2UnboundedModel:
    name = "B2 unbounded AI"
    sees_sessions = True

    def __init__(self, pdp: PolicyDecisionPoint):
        self.pdp = pdp

    def evaluate(self, req, assessment, home_country):
        d_p, _ = self.pdp.policy_decision(req)
        d_r, _ = self.pdp.risk_decision(assessment, req.resource.sensitivity)
        return Verdict(d_r, assessment.risk, d_p)   # the model decides alone


class PBCASetup:
    name = "PBCA"
    sees_sessions = True

    def __init__(self, pdp: PolicyDecisionPoint):
        self.pdp = pdp

    def evaluate(self, req, assessment, home_country):
        d_p, _ = self.pdp.policy_decision(req)
        d_r, _ = self.pdp.risk_decision(assessment, req.resource.sensitivity)
        return Verdict(stricter(d_p, d_r), assessment.risk, d_p)


def all_setups(pdp: PolicyDecisionPoint) -> list:
    return [B0MfaEverywhere(pdp), B1StaticRules(pdp), B2UnboundedModel(pdp), PBCASetup(pdp)]
