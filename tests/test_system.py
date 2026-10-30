import pytest

from pbca.audit import AuditLog
from pbca.caep import (
    CREDENTIAL_CHANGE,
    SESSION_REVOKED,
    TOKEN_CLAIMS_CHANGE,
    CaepTransmitter,
    DemoBankReceiver,
    sign_set,
    verify_set,
)
from pbca.decisions import Decision
from pbca.signals import DevicePosture, LoginContext, Resource, Sensitivity
from pbca.simulation.scenario import run
from pbca.system import PBCASystem, SessionRevoked

RECORDS = Resource("customer-records", Sensitivity.HIGH, customer_records=True)


@pytest.fixture
def system(engine):
    s = PBCASystem(engine)
    s.bank = DemoBankReceiver(s.caep.secret)
    s.caep.register("demo-bank", s.bank)
    return s


def office(e, org):
    return LoginContext(e.office_ip, e.office_asn, "IN", e.browser, e.os, "laptop", org.start.replace(hour=10))


MANAGED = DevicePosture(managed=True, os_patch_age_days=3)


# --------------------------------------------------------------------- CAEP
def test_set_roundtrip_and_tamper_detection():
    tx = CaepTransmitter()
    payload = tx.build(SESSION_REVOKED, "s1", "u1", "bank", "test")
    token = sign_set(payload, tx.secret)
    assert verify_set(token, tx.secret)["events"][SESSION_REVOKED]["reason_admin"]["en"] == "test"
    h, p, sig = token.split(".")
    with pytest.raises(ValueError):
        verify_set(f"{h}.{p}x.{sig}", tx.secret)
    with pytest.raises(ValueError):
        verify_set(token, b"wrong-key")


def test_set_shape_follows_ssf():
    payload = CaepTransmitter().build(TOKEN_CLAIMS_CHANGE, "s1", "u1", "bank", "r")
    assert {"iss", "jti", "iat", "aud", "sub_id", "events"} <= set(payload)
    assert payload["sub_id"]["format"] == "complex"
    assert payload["sub_id"]["session"]["id"] == "s1"


# --------------------------------------------------------------------- audit
def test_audit_chain_detects_tampering(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    for i in range(5):
        log.append("decision", {"i": i})
    assert log.verify() == (True, None)
    assert len((tmp_path / "audit.jsonl").read_text().splitlines()) == 5
    log.entries[2]["data"]["i"] = 99
    assert log.verify() == (False, 2)


# ------------------------------------------------------------------- system
def test_legit_session_allowed_and_stays_allowed(system, org, frequent_employee):
    e = frequent_employee
    o = system.login(e.identity, MANAGED, office(e, org), mfa="passkey")
    assert o.enforced == Decision.ALLOW
    sid = o.session.session_id
    assert system.access(sid, RECORDS).enforced == Decision.ALLOW
    for _ in range(3):
        assert system.observe_window(sid, org.legit_window(e)).enforced <= Decision.STEP_UP
    assert system.caep.deliveries == []
    assert "203" not in o.session.context.ip and o.session.context.ip.startswith("ip:")


def test_bulk_misuse_triggers_caep_and_blocks_export(system, org, frequent_employee):
    e = frequent_employee
    sid = system.login(e.identity, MANAGED, office(e, org), mfa="passkey").session.session_id
    system.access(sid, RECORDS)
    o = system.observe_window(sid, org.attack_window(e, "bulk"))
    assert o.enforced >= Decision.RESTRICT
    assert o.deliveries and o.deliveries[0].event_type in (SESSION_REVOKED, TOKEN_CLAIMS_CHANGE)
    assert system.bank.sessions[sid] in ("RESTRICT", "REVOKED")
    if o.enforced == Decision.DENY:
        with pytest.raises(SessionRevoked):
            system.access(sid, RECORDS, action="export")
    else:
        assert system.access(sid, RECORDS, action="export").enforced >= Decision.RESTRICT


def test_device_compliance_change_restricts_live_session(system, org, frequent_employee):
    e = frequent_employee
    sid = system.login(e.identity, MANAGED, office(e, org), mfa="passkey").session.session_id
    system.access(sid, RECORDS)
    o = system.update_device(sid, DevicePosture(managed=True, os_patch_age_days=120, edr_running=False))
    assert o.enforced == Decision.RESTRICT
    assert o.deliveries[0].event_type == TOKEN_CLAIMS_CHANGE


def test_threat_intel_match_revokes(system, org, frequent_employee):
    e = frequent_employee
    sid = system.login(e.identity, MANAGED, office(e, org), mfa="passkey").session.session_id
    o = system.threat_match(sid, bad_ip=True)
    assert o.enforced == Decision.DENY and system.sessions[sid].revoked
    assert system.bank.sessions[sid] == "REVOKED"


def test_step_up_satisfies_step_up_decision(system, org, frequent_employee):
    from dataclasses import replace
    e = frequent_employee
    admin = replace(e.identity, privileged=True)
    o = system.login(admin, MANAGED, office(e, org), mfa="totp")
    assert o.enforced == Decision.STEP_UP           # R3: privileged role needs passkey
    sid = o.session.session_id
    assert system.complete_step_up(sid, "passkey").enforced == Decision.ALLOW


def test_confirm_compromise_revokes_every_session(system, org, frequent_employee):
    e = frequent_employee
    ids = [system.login(e.identity, MANAGED, office(e, org), mfa="passkey").session.session_id for _ in range(2)]
    deliveries = system.confirm_compromise(e.identity.user_id)
    assert {d.event_type for d in deliveries} == {SESSION_REVOKED, CREDENTIAL_CHANGE}
    assert all(system.sessions[i].revoked for i in ids)


def test_periodic_tick_reevaluates_idle_sessions(system, org, frequent_employee):
    e = frequent_employee
    system.login(e.identity, MANAGED, office(e, org), mfa="passkey")
    assert system.tick(now=0) == []
    assert len(system.tick(now=float("inf"))) == 1


def test_every_decision_is_audited(system, org, frequent_employee):
    e = frequent_employee
    sid = system.login(e.identity, MANAGED, office(e, org), mfa="passkey").session.session_id
    system.access(sid, RECORDS)
    kinds = [x["kind"] for x in system.audit.entries]
    assert kinds.count("decision") == 2
    assert system.audit.verify()[0]


# ----------------------------------------------------------- case scenario
def test_case_walkthrough_matches_expected_outcomes():
    steps, system, bank = run(seed=7, verbose=False)
    by_event = {s.event: s for s in steps}
    assert by_event["Employee, managed laptop, office network"].decision == "Allow"
    assert "Deny" in by_event["Stolen password, unmanaged device, new ASN"].decision
    fooled = by_event["Same attacker, model fooled (risk forced to 0)"]
    assert "d_R=ALLOW" in fooled.signals and "d_P=DENY" in fooled.signals and fooled.decision.startswith("Deny")
    assert by_event["Stolen session token on managed device"].decision.startswith("Allow")
    bulk = by_event["Bulk record viewing and export"]
    assert bulk.decision.startswith(("Restrict", "Deny")) and bulk.caep
    assert "credential-change" in by_event["Compromise confirmed"].caep
    assert system.audit.verify()[0]
    assert all(v == "REVOKED" for v in bank.sessions.values())
