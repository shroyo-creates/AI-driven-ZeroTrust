"""PBCA demo service: REST API + dashboard.

Run:  uvicorn pbca.web.app:app --reload     then open http://127.0.0.1:8000

On startup a synthetic workforce is generated and both risk layers are
trained on it. The API then exposes the control plane: logins, per-request
access decisions, session events that trigger re-evaluation, step-up, analyst
confirmation, the CAEP events received by the demo bank app and the
hash-chained audit log.
"""

from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

from ..caep import DemoBankReceiver, verify_set
from ..policy import PolicyDecisionPoint
from ..risk.login import LoginScore
from ..signals import (
    AccessRequest,
    DevicePosture,
    Identity,
    LoginContext,
    Resource,
    Sensitivity,
    SessionWindow,
    ThreatIntel,
)
from ..simulation.data import Organization, build_trained_engine
from ..system import PBCASystem, SessionRevoked

STATIC = Path(__file__).parent / "static"

RESOURCES = {
    "intranet": Resource("intranet", Sensitivity.LOW),
    "hr-self-service": Resource("hr-self-service", Sensitivity.LOW),
    "internal-reporting": Resource("internal-reporting", Sensitivity.MEDIUM),
    "customer-records": Resource("customer-records", Sensitivity.HIGH, customer_records=True),
    "payments": Resource("payments", Sensitivity.HIGH, customer_records=True),
}


class State:
    def __init__(self, seed: int, n_users: int):
        self.org = Organization(n_users=n_users, seed=seed)
        self.engine = build_trained_engine(self.org)
        self.system = PBCASystem(self.engine)
        self.bank = DemoBankReceiver(self.system.caep.secret)
        self.system.caep.register("demo-bank", self.bank)
        self.by_id = {e.identity.user_id: e for e in self.org.employees}

    def employee(self, user_id: str):
        if user_id not in self.by_id:
            raise HTTPException(404, f"unknown user {user_id}")
        return self.by_id[user_id]


# ------------------------------------------------------------------- schemas
class LoginIn(BaseModel):
    user_id: str
    profile: Literal["office", "home", "attacker_foreign", "attacker_proxy", "token_replay"] = "office"
    mfa: str | None = "passkey"
    bad_ip: bool = False
    leaked_credential: bool = False


class AccessIn(BaseModel):
    resource: str = "customer-records"
    action: Literal["read", "export", "write"] = "read"


class ActivityIn(BaseModel):
    kind: Literal["normal", "bulk", "mimicry", "custom"] = "normal"
    window: dict[str, float] | None = None


class StepUpIn(BaseModel):
    factor: str = "passkey"


class DeviceIn(BaseModel):
    managed: bool = True
    os_patch_age_days: int = 0
    edr_running: bool = True


class ThreatIn(BaseModel):
    bad_ip: bool = False
    leaked_credential: bool = False


class PlaygroundIn(BaseModel):
    """Evaluate the PDP directly with a chosen risk value (e.g. a fooled model)."""

    risk: float = Field(0.0, ge=0, le=1)
    confidence: float = Field(1.0, ge=0, le=1)
    resource: str = "customer-records"
    action: Literal["read", "export", "write"] = "read"
    managed: bool = True
    compliant: bool = True
    privileged: bool = False
    mfa: str | None = "passkey"
    bad_ip: bool = False
    leaked_credential: bool = False


def create_app(seed: int = 7, n_users: int = 150) -> FastAPI:
    app = FastAPI(title="PBCA — Policy-Bounded Continuous Authorization", version="0.1.0")
    state = State(seed, n_users)
    app.state.pbca = state

    def resource(name: str) -> Resource:
        if name not in RESOURCES:
            raise HTTPException(404, f"unknown resource {name}")
        return RESOURCES[name]

    def guarded(fn, *args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except SessionRevoked:
            raise HTTPException(403, "session revoked")
        except KeyError as exc:
            raise HTTPException(404, str(exc))

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(STATIC / "index.html")

    @app.get("/api/employees")
    def employees(limit: int = 30):
        history = state.engine.login_model.history
        out = []
        for e in state.org.employees[:limit]:
            out.append({
                "user_id": e.identity.user_id,
                "role": e.identity.role,
                "privileged": e.identity.privileged,
                "mfa": e.identity.mfa_method,
                "prior_logins": history(e.identity.user_id),
            })
        return out

    @app.get("/api/resources")
    def resources():
        return [{"name": r.name, "sensitivity": r.sensitivity.name, "customer_records": r.customer_records}
                for r in RESOURCES.values()]

    @app.post("/api/login")
    def login(body: LoginIn):
        e = state.employee(body.user_id)
        now = datetime.now()
        managed = DevicePosture(managed=True, os_patch_age_days=4, edr_running=True)
        if body.profile in ("office", "token_replay"):
            ctx, dev = LoginContext(e.office_ip, e.office_asn, "IN", e.browser, e.os, "laptop", now), managed
        elif body.profile == "home":
            ctx, dev = LoginContext(e.home_ip, e.home_asn, "IN", e.browser, e.os, "laptop", now), managed
        elif body.profile == "attacker_proxy":
            ctx = LoginContext("103.77.12.9", "AS133982", "IN", e.browser, e.os, "laptop", now)
            dev = DevicePosture(managed=False, os_patch_age_days=60, edr_running=False)
        else:
            ctx = LoginContext("185.220.101.7", "AS200052", "RO", "Firefox", "Linux", "desktop", now)
            dev = DevicePosture(managed=False, os_patch_age_days=200, edr_running=False)
        threat = ThreatIntel(bad_ip=body.bad_ip, leaked_credential=body.leaked_credential)
        o = state.system.login(e.identity, dev, ctx, threat, mfa=body.mfa)
        if o.session:
            state.bank.sessions[o.session.session_id] = o.enforced.name
        return {**o.to_dict(), "session": o.session.summary() if o.session else None}

    @app.post("/api/sessions/{sid}/access")
    def access(sid: str, body: AccessIn):
        o = guarded(state.system.access, sid, resource(body.resource), body.action)
        return o.to_dict()

    @app.post("/api/sessions/{sid}/activity")
    def activity(sid: str, body: ActivityIn):
        s = guarded(state.system._get, sid)
        e = state.employee(s.identity.user_id)
        if body.kind == "normal":
            w = state.org.legit_window(e)
        elif body.kind == "custom":
            w = SessionWindow(**(body.window or {}))
        else:
            w = state.org.attack_window(e, body.kind)
        o = guarded(state.system.observe_window, sid, w)
        return {**o.to_dict(), "window": w.as_dict()}

    @app.post("/api/sessions/{sid}/step-up")
    def step_up(sid: str, body: StepUpIn):
        return guarded(state.system.complete_step_up, sid, body.factor).to_dict()

    @app.post("/api/sessions/{sid}/device")
    def device(sid: str, body: DeviceIn):
        return guarded(state.system.update_device, sid, DevicePosture(**body.model_dump())).to_dict()

    @app.post("/api/sessions/{sid}/threat")
    def threat(sid: str, body: ThreatIn):
        return guarded(state.system.threat_match, sid, body.bad_ip, body.leaked_credential).to_dict()

    @app.post("/api/users/{user_id}/compromise")
    def compromise(user_id: str):
        state.employee(user_id)
        deliveries = state.system.confirm_compromise(user_id, analyst="dashboard")
        return {"events": [d.event_type.rsplit("/", 1)[-1] for d in deliveries]}

    @app.post("/api/tick")
    def tick():
        return [o.to_dict() for o in state.system.tick(now=float("inf"))]

    @app.get("/api/sessions")
    def sessions():
        return [s.summary() for s in state.system.sessions.values()]

    @app.get("/api/sessions/{sid}")
    def session_detail(sid: str):
        s = state.system.sessions.get(sid)
        if not s:
            raise HTTPException(404, "unknown session")
        return {**s.summary(), "history": s.history}

    @app.get("/api/audit")
    def audit(n: int = 50, kind: str | None = None):
        ok, bad = state.system.audit.verify()
        return {"chain_ok": ok, "first_bad": bad, "count": len(state.system.audit.entries),
                "entries": state.system.audit.tail(n, kind)}

    @app.get("/api/caep")
    def caep():
        return {
            "bank_sessions": state.bank.sessions,
            "deliveries": [
                {**d.__dict__, "event_type": d.event_type.rsplit("/", 1)[-1],
                 "containment_ms": round(d.containment_seconds * 1000, 3)}
                for d in state.system.caep.deliveries[-50:]
            ],
            "last_set": state.bank.received[-1] if state.bank.received else None,
        }

    @app.post("/api/caep/receiver", status_code=202)
    async def caep_receiver(request: Request):
        """SSF push endpoint: accepts a signed SET (application/secevent+jwt)."""
        token = (await request.body()).decode().strip()
        try:
            payload = verify_set(token, state.system.caep.secret)
        except ValueError as exc:
            return JSONResponse({"err": "invalid_request", "description": str(exc)}, status_code=400)
        state.bank(token)
        return {"accepted": payload["jti"]}

    @app.post("/api/pdp/playground")
    def playground(body: PlaygroundIn):
        pdp: PolicyDecisionPoint = state.system.pdp
        res = resource(body.resource)
        device = DevicePosture(managed=body.managed, os_patch_age_days=0 if body.compliant else 90,
                               edr_running=body.compliant)
        req = AccessRequest(
            Identity("playground", "demo", "demo", privileged=body.privileged), device,
            LoginContext("ip:demo", "AS0", "IN", "b", "o", "laptop"), res,
            ThreatIntel(body.bad_ip, body.leaked_credential), body.action, body.mfa,
        )
        n_u = round(body.confidence * state.engine.n_min)
        a = state.engine.combine(LoginScore(body.risk, 0.0, {}, n_u), state.engine.score_session(req.identity, None))
        rec = pdp.decide(req, a, trigger="playground")
        return {
            "d_policy": rec.d_policy.name,
            "d_risk": rec.d_risk.name,
            "pbca": rec.final.name,
            "b2_unbounded": rec.d_risk.name,
            "b2_violates_policy": rec.d_risk < rec.d_policy,
            "policy_reasons": [f"{r.rule}: {r.reason}" for r in rec.policy_reasons],
            "risk_notes": rec.risk_notes,
        }

    @app.post("/api/scenario")
    def scenario():
        from ..simulation.scenario import run
        steps, _, _ = run(seed=seed, verbose=False)
        return [s.__dict__ for s in steps]

    return app


app = create_app(
    seed=int(os.environ.get("PBCA_SEED", "7")),
    n_users=int(os.environ.get("PBCA_USERS", "150")),
)
