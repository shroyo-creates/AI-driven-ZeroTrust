import pytest

from pbca.decisions import Decision
from pbca.policy import DEFAULT_THRESHOLDS, PolicyDecisionPoint
from pbca.risk.engine import RiskAssessment
from pbca.risk.login import LoginScore
from pbca.risk.session import SessionScore
from pbca.signals import AccessRequest, DevicePosture, Identity, LoginContext, Resource, Sensitivity, ThreatIntel

CTX = LoginContext("ip:x", "AS1", "IN", "Edge", "Windows", "laptop")
RECORDS = Resource("customer-records", Sensitivity.HIGH, customer_records=True)
INTRANET = Resource("intranet", Sensitivity.LOW)
MANAGED = DevicePosture(managed=True)


def req(resource=RECORDS, device=MANAGED, privileged=False, mfa="passkey", threat=ThreatIntel(), action="read"):
    return AccessRequest(Identity("u", "teller", "teller", privileged=privileged), device, CTX, resource,
                         threat, action, mfa)


def risk(r, n_u=20):
    return RiskAssessment(r, min(1.0, n_u / 8), LoginScore(r, 0.0, {}, n_u), SessionScore(0.0, 0.0))


@pytest.mark.parametrize(
    "request_, expected, rule",
    [
        (req(), Decision.ALLOW, None),
        (req(device=DevicePosture(managed=False)), Decision.DENY, "R1"),
        (req(device=DevicePosture(managed=True, os_patch_age_days=90)), Decision.RESTRICT, "R2"),
        (req(privileged=True, mfa="totp"), Decision.STEP_UP, "R3"),
        (req(privileged=True, mfa="passkey"), Decision.ALLOW, None),
        (req(threat=ThreatIntel(bad_ip=True)), Decision.DENY, "R4"),
        (req(threat=ThreatIntel(leaked_credential=True), mfa="totp"), Decision.STEP_UP, "R5"),
        (req(device=DevicePosture(managed=True, edr_running=False), action="export"), Decision.DENY, "R6"),
        (req(resource=INTRANET, device=DevicePosture(managed=False)), Decision.ALLOW, None),
    ],
)
def test_mandatory_rules(request_, expected, rule):
    d, hits = PolicyDecisionPoint().policy_decision(request_)
    assert d == expected
    assert (rule in [h.rule for h in hits]) if rule else not hits


@pytest.mark.parametrize("sens", list(Sensitivity))
def test_risk_bands_follow_table_iii(sens):
    pdp = PolicyDecisionPoint()
    t1, t2, t3 = DEFAULT_THRESHOLDS[sens]
    assert pdp.risk_decision(risk(max(0, t1 - 0.01)), sens)[0] == Decision.ALLOW
    assert pdp.risk_decision(risk(t1), sens)[0] == Decision.STEP_UP
    assert pdp.risk_decision(risk(t2), sens)[0] == Decision.RESTRICT
    assert pdp.risk_decision(risk(t3), sens)[0] == Decision.DENY


def test_sensitive_resources_react_to_smaller_risk():
    pdp = PolicyDecisionPoint()
    assert pdp.risk_decision(risk(0.3), Sensitivity.LOW)[0] == Decision.ALLOW
    assert pdp.risk_decision(risk(0.3), Sensitivity.HIGH)[0] == Decision.STEP_UP


def test_low_confidence_floors_at_step_up_on_sensitive_resources():
    pdp = PolicyDecisionPoint(c_min=0.5)
    assert pdp.risk_decision(risk(0.0, n_u=1), Sensitivity.HIGH)[0] == Decision.STEP_UP
    assert pdp.risk_decision(risk(0.0, n_u=1), Sensitivity.MEDIUM)[0] == Decision.STEP_UP
    assert pdp.risk_decision(risk(0.0, n_u=1), Sensitivity.LOW)[0] == Decision.ALLOW
    assert pdp.risk_decision(risk(0.0, n_u=8), Sensitivity.HIGH)[0] == Decision.ALLOW
    # the floor never lowers an already stricter tier
    assert pdp.risk_decision(risk(0.9, n_u=1), Sensitivity.HIGH)[0] == Decision.DENY


def test_final_is_stricter_of_policy_and_risk():
    pdp = PolicyDecisionPoint()
    rec = pdp.decide(req(device=DevicePosture(managed=True, os_patch_age_days=90)), risk(0.25))
    assert (rec.d_policy, rec.d_risk, rec.final) == (Decision.RESTRICT, Decision.STEP_UP, Decision.RESTRICT)
    rec = pdp.decide(req(), risk(0.85))
    assert (rec.d_policy, rec.d_risk, rec.final) == (Decision.ALLOW, Decision.DENY, Decision.DENY)


def test_invalid_thresholds_rejected():
    with pytest.raises(ValueError):
        PolicyDecisionPoint(thresholds={**DEFAULT_THRESHOLDS, Sensitivity.HIGH: (0.5, 0.4, 0.9)})


def test_record_serializes():
    d = PolicyDecisionPoint().decide(req(), risk(0.1)).to_dict()
    assert d["decision"] == "ALLOW" and d["sensitivity"] == "HIGH" and "risk" in d
