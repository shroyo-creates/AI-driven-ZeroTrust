"""PBCA control plane: sessions, enforcement (PEP) and continuous re-evaluation.

Flow for every decision (Fig. 1 / Fig. 2 of the paper):

    request or session event
      -> collect signals -> risk engine (r, c, explanation)
      -> PDP: d = stricter(d_P, d_R)
      -> PEP enforces, decision logged with attributions
      -> session events re-enter as new evidence

Per-request decisions (``access``) govern a single request, e.g. "deny
sensitive access, step-up elsewhere". Session-level re-evaluations (behavior
windows, device-compliance changes, threat-intel matches, the periodic Δt
check) change the tier applied to the whole session. When that tier becomes
stricter, a CAEP event is sent; a session-level DENY revokes the session.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field, replace

from .audit import AuditLog
from .caep import CREDENTIAL_CHANGE, SESSION_REVOKED, CaepTransmitter, Delivery, event_type_for
from .decisions import Decision, stricter
from .policy import PHISHING_RESISTANT, DecisionRecord, PolicyDecisionPoint
from .privacy import minimize_context
from .risk.engine import RiskEngine
from .risk.login import LoginScore
from .signals import (
    AccessRequest,
    DevicePosture,
    Identity,
    LoginContext,
    Resource,
    Sensitivity,
    SessionWindow,
    ThreatIntel,
)

PORTAL = Resource("sso-portal", Sensitivity.LOW)


class SessionRevoked(Exception):
    pass


@dataclass
class Session:
    session_id: str
    identity: Identity
    device: DevicePosture
    context: LoginContext
    threat: ThreatIntel
    login_score: LoginScore
    active_resource: Resource
    applied: Decision
    mfa_satisfied: str | None = None
    last_window: SessionWindow | None = None
    created: float = field(default_factory=time.time)
    last_eval: float = field(default_factory=time.time)
    revoked: bool = False
    history: list[dict] = field(default_factory=list)

    def summary(self) -> dict:
        return {
            "session_id": self.session_id,
            "user_id": self.identity.user_id,
            "role": self.identity.role,
            "device_managed": self.device.managed,
            "device_compliant": self.device.compliant,
            "country": self.context.country,
            "active_resource": self.active_resource.name,
            "applied": self.applied.name,
            "mfa": self.mfa_satisfied,
            "r_login": round(self.login_score.risk, 4),
            "revoked": self.revoked,
        }


@dataclass
class Outcome:
    record: DecisionRecord
    enforced: Decision
    session: Session | None
    deliveries: list[Delivery] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = self.record.to_dict()
        d["enforced"] = self.enforced.name
        d["enforced_label"] = self.enforced.label
        d["caep_events"] = [x.event_type.rsplit("/", 1)[-1] for x in self.deliveries]
        return d


class PBCASystem:
    def __init__(
        self,
        engine: RiskEngine,
        pdp: PolicyDecisionPoint | None = None,
        transmitter: CaepTransmitter | None = None,
        audit: AuditLog | None = None,
        delta_t: float = 300.0,
    ):
        self.engine = engine
        self.pdp = pdp or PolicyDecisionPoint()
        self.caep = transmitter or CaepTransmitter()
        self.audit = audit or AuditLog()
        self.delta_t = delta_t
        self.sessions: dict[str, Session] = {}

    # ------------------------------------------------------------- helpers
    @staticmethod
    def _effective(decision: Decision, mfa: str | None) -> Decision:
        """A Step-up decision is satisfied once a phishing-resistant factor is used."""
        if decision == Decision.STEP_UP and mfa in PHISHING_RESISTANT:
            return Decision.ALLOW
        return decision

    def _request(self, s: Session, resource: Resource, action: str = "read") -> AccessRequest:
        return AccessRequest(
            identity=s.identity,
            device=s.device,
            context=s.context,
            resource=resource,
            threat=s.threat,
            action=action,
            mfa_satisfied=s.mfa_satisfied,
            session_id=s.session_id,
        )

    def _log(self, outcome: Outcome) -> None:
        self.audit.append("decision", outcome.to_dict())
        if outcome.session is not None:
            outcome.session.history.append(outcome.to_dict())

    def _get(self, session_id: str) -> Session:
        s = self.sessions.get(session_id)
        if s is None:
            raise KeyError(f"unknown session {session_id}")
        if s.revoked:
            raise SessionRevoked(session_id)
        return s

    # --------------------------------------------------------------- login
    def login(
        self,
        identity: Identity,
        device: DevicePosture,
        context: LoginContext,
        threat: ThreatIntel = ThreatIntel(),
        mfa: str | None = None,
    ) -> Outcome:
        ctx = minimize_context(context)
        login_score = self.engine.score_login(identity, ctx, device)
        session = Session(
            session_id=uuid.uuid4().hex[:12],
            identity=identity,
            device=device,
            context=ctx,
            threat=threat,
            login_score=login_score,
            active_resource=PORTAL,
            applied=Decision.ALLOW,
            mfa_satisfied=mfa,
        )
        assessment = self.engine.combine(login_score, self.engine.score_session(identity, None))
        record = self.pdp.decide(self._request(session, PORTAL), assessment, trigger="login")
        enforced = self._effective(record.final, mfa)
        session.applied = enforced
        if enforced == Decision.DENY:
            outcome = Outcome(record, enforced, None)
        else:
            self.sessions[session.session_id] = session
            outcome = Outcome(record, enforced, session)
        self._log(outcome)
        return outcome

    def complete_step_up(self, session_id: str, factor: str = "passkey") -> Outcome:
        s = self._get(session_id)
        s.mfa_satisfied = factor
        self.audit.append("step_up", {"session_id": session_id, "factor": factor})
        if s.applied == Decision.STEP_UP and factor in PHISHING_RESISTANT:
            s.applied = Decision.ALLOW
        return self._reevaluate(s, "step_up", allow_relax=False)

    # ----------------------------------------------------- per-request PDP
    def access(self, session_id: str, resource: Resource, action: str = "read") -> Outcome:
        s = self._get(session_id)
        req = self._request(s, resource, action)
        assessment = self.engine.combine(s.login_score, self.engine.score_session(s.identity, s.last_window))
        record = self.pdp.decide(req, assessment, trigger=f"access:{action}")
        enforced = stricter(self._effective(record.final, s.mfa_satisfied), s.applied)
        if enforced < Decision.DENY and resource.sensitivity >= s.active_resource.sensitivity:
            s.active_resource = resource
        outcome = Outcome(record, enforced, s)
        self._log(outcome)
        return outcome

    # ---------------------------------------------- continuous re-evaluation
    def _reevaluate(
        self,
        s: Session,
        trigger: str,
        trigger_time: float | None = None,
        allow_relax: bool = False,
    ) -> Outcome:
        trigger_time = trigger_time if trigger_time is not None else time.time()
        assessment = self.engine.combine(s.login_score, self.engine.score_session(s.identity, s.last_window))
        record = self.pdp.decide(self._request(s, s.active_resource), assessment, trigger=trigger)
        new = self._effective(record.final, s.mfa_satisfied)
        deliveries: list[Delivery] = []
        if new > s.applied:
            reason = "; ".join(record.risk_notes[:3] + [r.reason for r in record.policy_reasons])
            deliveries = self.caep.send(
                event_type_for(new), s.session_id, s.identity.user_id, new, reason, trigger_time
            )
            s.applied = new
            if new == Decision.DENY:
                s.revoked = True
        elif allow_relax:
            s.applied = new
        s.last_eval = time.time()
        outcome = Outcome(record, s.applied, s, deliveries)
        self._log(outcome)
        return outcome

    def observe_window(self, session_id: str, window: SessionWindow, trigger_time: float | None = None) -> Outcome:
        s = self._get(session_id)
        s.last_window = window
        return self._reevaluate(s, "behavior_window", trigger_time)

    def update_device(self, session_id: str, device: DevicePosture, trigger_time: float | None = None) -> Outcome:
        s = self._get(session_id)
        s.device = device
        return self._reevaluate(s, "device_compliance", trigger_time)

    def threat_match(
        self, session_id: str, bad_ip: bool = False, leaked_credential: bool = False, trigger_time: float | None = None
    ) -> Outcome:
        s = self._get(session_id)
        s.threat = replace(s.threat, bad_ip=s.threat.bad_ip or bad_ip,
                           leaked_credential=s.threat.leaked_credential or leaked_credential)
        return self._reevaluate(s, "threat_intel", trigger_time)

    def tick(self, now: float | None = None) -> list[Outcome]:
        """Periodic check: re-evaluate sessions with no evaluation in the last Δt."""
        now = now if now is not None else time.time()
        return [
            self._reevaluate(s, "periodic")
            for s in list(self.sessions.values())
            if not s.revoked and now - s.last_eval >= self.delta_t
        ]

    def confirm_compromise(self, user_id: str, analyst: str = "analyst") -> list[Delivery]:
        """Analyst confirmation: revoke every session and force a credential reset."""
        out: list[Delivery] = []
        for s in self.sessions.values():
            if s.identity.user_id != user_id or s.revoked:
                continue
            reason = f"compromise confirmed by {analyst}"
            out += self.caep.send(SESSION_REVOKED, s.session_id, user_id, Decision.DENY, reason)
            out += self.caep.send(
                CREDENTIAL_CHANGE, s.session_id, user_id, Decision.DENY, reason,
                extra={"credential_type": "password", "change_type": "revoke"},
            )
            s.applied, s.revoked = Decision.DENY, True
        self.audit.append("compromise_confirmed", {"user_id": user_id, "analyst": analyst, "events": len(out)})
        return out
