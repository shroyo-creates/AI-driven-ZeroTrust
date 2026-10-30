"""Case walk-through (Table V of the paper), run end to end.

A relationship manager at a financial services firm normally opens customer
records from a managed office laptop. An attacker steals the password and
tries to log in from an unknown device elsewhere, then (in the harder case)
uses a stolen session token from the employee's own laptop and starts bulk
viewing and exporting records.

Run:  python -m pbca.simulation.scenario
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, replace

from ..caep import DemoBankReceiver
from ..risk.login import LoginScore
from ..signals import AccessRequest, DevicePosture, LoginContext, Resource, Sensitivity
from ..system import PBCASystem
from .data import Organization, build_trained_engine

CUSTOMER_RECORDS = Resource("customer-records", Sensitivity.HIGH, customer_records=True)
INTRANET = Resource("intranet", Sensitivity.LOW)
REPORTING = Resource("internal-reporting", Sensitivity.MEDIUM)


@dataclass
class Step:
    event: str
    signals: str
    decision: str
    caep: str = ""


def _signals(o) -> str:
    r = o.record.assessment
    parts = [f"rL={r.r_login:.2f}", f"rS={r.r_session:.2f}", f"c={r.confidence:.2f}"]
    if o.record.policy_reasons:
        parts.append("policy: " + ", ".join(p.rule for p in o.record.policy_reasons))
    top = r.session.top_features(1)
    if top and r.r_session > 0:
        parts.append(f"top feature: {top[0][0]}")
    return "; ".join(parts)


def run(seed: int = 7, verbose: bool = True) -> tuple[list[Step], PBCASystem, DemoBankReceiver]:
    org = Organization(n_users=150, seed=seed)
    engine = build_trained_engine(org)
    system = PBCASystem(engine)
    bank = DemoBankReceiver(system.caep.secret)
    system.caep.register("demo-bank", bank)

    # pick a frequent relationship manager as the victim
    victim = next(
        e for e in org.employees
        if e.identity.role == "relationship_manager" and e.logins_per_month > 15
        and engine.login_model.history(e.identity.user_id) >= 8
    )
    office = LoginContext(victim.office_ip, victim.office_asn, "IN", victim.browser, victim.os, "laptop",
                          org.start.replace(month=4, day=6, hour=10))
    laptop = DevicePosture(managed=True, os_patch_age_days=5, edr_running=True)
    steps: list[Step] = []

    # 1. legitimate employee, managed laptop, office network
    o = system.login(victim.identity, laptop, office, mfa="passkey")
    a = system.access(o.session.session_id, CUSTOMER_RECORDS)
    bank.sessions[o.session.session_id] = a.enforced.name
    system.observe_window(o.session.session_id, org.legit_window(victim))
    steps.append(Step("Employee, managed laptop, office network", _signals(a), a.enforced.label))

    # 2. stolen password, unmanaged device, new ASN in another city
    attacker_ctx = LoginContext("185.220.101.7", "AS200052", "IN", "Firefox", "Linux", "desktop",
                                org.start.replace(month=4, day=6, hour=23))
    attacker_dev = DevicePosture(managed=False, os_patch_age_days=200, edr_running=False)
    o2 = system.login(victim.identity, attacker_dev, attacker_ctx, mfa="totp")
    if o2.session is None:
        steps.append(Step("Stolen password, unmanaged device, new ASN", _signals(o2), "Deny at login"))
    else:
        sensitive = system.access(o2.session.session_id, CUSTOMER_RECORDS)
        elsewhere = system.access(o2.session.session_id, INTRANET)
        steps.append(Step(
            "Stolen password, unmanaged device, new ASN", _signals(sensitive),
            f"{sensitive.enforced.label} on customer records; {elsewhere.enforced.label} on intranet",
        ))

    # 2b. same attacker, but suppose the model was fooled or poisoned (r = 0).
    #      Policy bounding: d = stricter(d_P, d_R) still cannot be looser than d_P.
    fooled = engine.combine(
        LoginScore(risk=0.0, log_ratio=-50.0, contributions={}, user_history=99),
        engine.score_session(victim.identity, None),
    )
    req = AccessRequest(victim.identity, attacker_dev, attacker_ctx, CUSTOMER_RECORDS, mfa_satisfied="totp")
    rec = system.pdp.decide(req, fooled, trigger="fooled-model-check")
    steps.append(Step(
        "Same attacker, model fooled (risk forced to 0)",
        f"r=0.00; d_R={rec.d_risk.name}; d_P={rec.d_policy.name} ({', '.join(p.rule for p in rec.policy_reasons)})",
        f"{rec.final.label} on customer records: policy bound holds",
    ))

    # 3. stolen session token replayed from the managed laptop: Layer 1 sees nothing
    o3 = system.login(victim.identity, laptop, replace(office, timestamp=office.timestamp.replace(hour=14)),
                      mfa="passkey")
    sid = o3.session.session_id
    a3 = system.access(sid, CUSTOMER_RECORDS)
    bank.sessions[sid] = a3.enforced.name
    steps.append(Step("Stolen session token on managed device", _signals(a3), f"{a3.enforced.label}, monitored"))

    # 4. bulk record viewing and export
    w = system.observe_window(sid, org.attack_window(victim, "bulk"))
    steps.append(Step(
        "Bulk record viewing and export", _signals(w),
        f"{w.enforced.label}; alert analyst",
        ", ".join(d.event_type.rsplit("/", 1)[-1] for d in w.deliveries),
    ))
    if w.enforced.name != "DENY":
        exp = system.access(sid, CUSTOMER_RECORDS, action="export")
        steps[-1].decision += f" (export attempt -> {exp.enforced.label})"

    # 5. analyst confirms the compromise
    deliveries = system.confirm_compromise(victim.identity.user_id, analyst="soc-analyst-1")
    steps.append(Step(
        "Compromise confirmed", "analyst confirmation", "Revoke via CAEP; reset credentials",
        ", ".join(sorted({d.event_type.rsplit('/', 1)[-1] for d in deliveries})),
    ))

    if verbose:
        _print(steps, system, bank)
    return steps, system, bank


def _print(steps: list[Step], system: PBCASystem, bank: DemoBankReceiver) -> None:
    print("\nPBCA case walk-through (Table V)\n" + "=" * 32)
    for i, s in enumerate(steps, 1):
        print(f"\n{i}. {s.event}\n   signals : {s.signals}\n   decision: {s.decision}")
        if s.caep:
            print(f"   CAEP    : {s.caep}")
    ok, bad = system.audit.verify()
    print(f"\nAudit log: {len(system.audit.entries)} entries, hash chain {'intact' if ok else f'BROKEN at {bad}'}")
    print("Demo bank session view:", json.dumps(bank.sessions, indent=None))
    contain = [d.containment_seconds * 1000 for d in system.caep.deliveries]
    if contain:
        print(f"Time to containment (in-process): max {max(contain):.2f} ms over {len(contain)} CAEP deliveries")


if __name__ == "__main__":
    run(seed=int(sys.argv[1]) if len(sys.argv) > 1 else 7)
