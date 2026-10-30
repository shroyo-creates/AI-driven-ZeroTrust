"""Policy decision point (PDP): mandatory rules, risk tiers and Eq. 5.

The PDP corresponds to the policy engine + policy administrator of NIST
SP 800-207. It computes two decisions:

* ``d_P`` from fixed, attribute-based rules written by the organization
  (``MANDATORY_RULES``). These never look at the risk score.
* ``d_R`` from the risk value ``r`` and the sensitivity thresholds of Table III,
  floored at Step-up when the confidence ``c`` is below ``c_min`` on a medium or
  high sensitivity resource.

and returns ``d = stricter(d_P, d_R)``. The same rules are expressed in Rego
for Open Policy Agent in ``policies/pbca.rego``.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

from .decisions import Decision, stricter
from .risk.engine import RiskAssessment
from .signals import AccessRequest, Sensitivity

PHISHING_RESISTANT = {"passkey", "security_key", "webauthn", "fido2"}

# Table III: starting thresholds (tau1, tau2, tau3) by resource sensitivity.
# More sensitive resources get lower thresholds. Tune in report-only mode.
DEFAULT_THRESHOLDS: dict[Sensitivity, tuple[float, float, float]] = {
    Sensitivity.LOW: (0.50, 0.80, 0.95),
    Sensitivity.MEDIUM: (0.35, 0.65, 0.90),
    Sensitivity.HIGH: (0.20, 0.50, 0.80),
}


@dataclass(frozen=True)
class RuleResult:
    rule: str
    decision: Decision
    reason: str


Rule = Callable[[AccessRequest], "RuleResult | None"]


# ------------------------------------------------------------ mandatory rules
def rule_unmanaged_customer_records(req: AccessRequest) -> RuleResult | None:
    """Unmanaged devices may never open unmasked customer records."""
    if req.resource.customer_records and not req.device.managed:
        return RuleResult("R1", Decision.DENY, "unmanaged device may not open unmasked customer records")
    return None


def rule_noncompliant_device(req: AccessRequest) -> RuleResult | None:
    """A managed but non-compliant device gets masked, read-only access to sensitive data."""
    if req.device.managed and not req.device.compliant and req.resource.sensitivity >= Sensitivity.HIGH:
        return RuleResult("R2", Decision.RESTRICT, "device out of compliance (patch age or EDR)")
    return None


def rule_privileged_phishing_resistant(req: AccessRequest) -> RuleResult | None:
    """Privileged roles must always use phishing-resistant MFA."""
    if req.identity.privileged and req.mfa_satisfied not in PHISHING_RESISTANT:
        return RuleResult("R3", Decision.STEP_UP, "privileged role requires phishing-resistant MFA")
    return None


def rule_threat_intel(req: AccessRequest) -> RuleResult | None:
    if req.threat.bad_ip:
        return RuleResult("R4", Decision.DENY, "source IP on threat-intelligence block list")
    if req.threat.leaked_credential and req.mfa_satisfied not in PHISHING_RESISTANT:
        return RuleResult("R5", Decision.STEP_UP, "credential appears in a leak; re-verify with strong factor")
    return None


def rule_export_requires_compliant_device(req: AccessRequest) -> RuleResult | None:
    if req.action == "export" and req.resource.customer_records and not req.device.compliant:
        return RuleResult("R6", Decision.DENY, "export of customer data requires a compliant managed device")
    return None


MANDATORY_RULES: tuple[Rule, ...] = (
    rule_unmanaged_customer_records,
    rule_noncompliant_device,
    rule_privileged_phishing_resistant,
    rule_threat_intel,
    rule_export_requires_compliant_device,
)


# ------------------------------------------------------------- decision record
@dataclass
class DecisionRecord:
    final: Decision
    d_policy: Decision
    d_risk: Decision
    policy_reasons: list[RuleResult]
    risk_notes: list[str]
    assessment: RiskAssessment
    user_id: str
    resource: str
    sensitivity: Sensitivity
    thresholds: tuple[float, float, float]
    session_id: str | None = None
    trigger: str = "access"
    latency_ms: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "user_id": self.user_id,
            "session_id": self.session_id,
            "resource": self.resource,
            "sensitivity": self.sensitivity.name,
            "trigger": self.trigger,
            "decision": self.final.name,
            "decision_label": self.final.label,
            "d_policy": self.d_policy.name,
            "d_risk": self.d_risk.name,
            "policy_reasons": [f"{r.rule}: {r.reason}" for r in self.policy_reasons],
            "risk_notes": self.risk_notes,
            "thresholds": list(self.thresholds),
            "latency_ms": round(self.latency_ms, 3),
            "risk": self.assessment.to_dict(),
        }


# ------------------------------------------------------------------------ PDP
class PolicyDecisionPoint:
    def __init__(
        self,
        rules: tuple[Rule, ...] = MANDATORY_RULES,
        thresholds: dict[Sensitivity, tuple[float, float, float]] | None = None,
        c_min: float = 0.5,
        combine: Callable[[Decision, Decision], Decision] = stricter,
    ):
        self.rules = rules
        self.thresholds = dict(thresholds or DEFAULT_THRESHOLDS)
        for s, (t1, t2, t3) in self.thresholds.items():
            if not 0 <= t1 < t2 < t3 <= 1:
                raise ValueError(f"thresholds for {s.name} must satisfy 0 <= t1 < t2 < t3 <= 1")
        self.c_min = c_min
        self.combine = combine

    def policy_decision(self, req: AccessRequest) -> tuple[Decision, list[RuleResult]]:
        hits = [r for r in (rule(req) for rule in self.rules) if r is not None]
        return stricter(Decision.ALLOW, *(h.decision for h in hits)), hits

    def risk_decision(self, assessment: RiskAssessment, sensitivity: Sensitivity) -> tuple[Decision, list[str]]:
        t1, t2, t3 = self.thresholds[sensitivity]
        r = assessment.risk
        if r >= t3:
            d = Decision.DENY
        elif r >= t2:
            d = Decision.RESTRICT
        elif r >= t1:
            d = Decision.STEP_UP
        else:
            d = Decision.ALLOW
        notes = [f"risk {r:.3f} -> {d.name} (tau={t1:.2f}/{t2:.2f}/{t3:.2f})"]
        if assessment.confidence < self.c_min and sensitivity >= Sensitivity.MEDIUM and d < Decision.STEP_UP:
            d = Decision.STEP_UP
            notes.append(f"confidence {assessment.confidence:.2f} < c_min {self.c_min}: floored at STEP_UP")
        return d, notes

    def decide(
        self,
        req: AccessRequest,
        assessment: RiskAssessment,
        trigger: str = "access",
    ) -> DecisionRecord:
        start = time.perf_counter()
        d_p, reasons = self.policy_decision(req)
        d_r, notes = self.risk_decision(assessment, req.resource.sensitivity)
        final = self.combine(d_p, d_r)
        return DecisionRecord(
            final=final,
            d_policy=d_p,
            d_risk=d_r,
            policy_reasons=reasons,
            risk_notes=notes + assessment.explanation,
            assessment=assessment,
            user_id=req.identity.user_id,
            resource=req.resource.name,
            sensitivity=req.resource.sensitivity,
            thresholds=self.thresholds[req.resource.sensitivity],
            session_id=req.session_id,
            trigger=trigger,
            latency_ms=(time.perf_counter() - start) * 1000,
        )
