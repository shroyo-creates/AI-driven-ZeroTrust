"""Policy bounding (Eq. 5): the final decision is never looser than d_P.

This is the RQ2 property test from the evaluation plan: random requests and
deliberately bad risk scores, including scores forced to zero, are fed to the
PDP. PBCA must never produce a decision looser than d_P; the unbounded B2
setup is expected to fail.
"""

from hypothesis import given, settings
from hypothesis import strategies as st

from pbca.decisions import Decision, is_policy_bounded, stricter
from pbca.evaluation.baselines import B2UnboundedModel, PBCASetup
from pbca.policy import PolicyDecisionPoint
from pbca.risk.engine import RiskAssessment
from pbca.risk.login import LoginScore
from pbca.risk.session import SessionScore
from pbca.signals import AccessRequest, DevicePosture, Identity, LoginContext, Resource, Sensitivity, ThreatIntel

decisions = st.sampled_from(list(Decision))

requests = st.builds(
    AccessRequest,
    identity=st.builds(Identity, user_id=st.just("u"), role=st.just("r"), peer_group=st.just("g"),
                       privileged=st.booleans()),
    device=st.builds(DevicePosture, managed=st.booleans(), os_patch_age_days=st.integers(0, 400),
                     edr_running=st.booleans()),
    context=st.just(LoginContext("ip:x", "AS1", "IN", "b", "o", "laptop")),
    resource=st.builds(Resource, name=st.just("res"), sensitivity=st.sampled_from(list(Sensitivity)),
                       customer_records=st.booleans()),
    threat=st.builds(ThreatIntel, bad_ip=st.booleans(), leaked_credential=st.booleans()),
    action=st.sampled_from(["read", "export", "write"]),
    mfa_satisfied=st.sampled_from([None, "sms", "totp", "passkey", "security_key"]),
)

# adversarial risk: forced to zero half the time, otherwise anything in [0, 1]
risks = st.one_of(st.just(0.0), st.floats(0.0, 1.0))


def assessment(r: float, n_u: int) -> RiskAssessment:
    return RiskAssessment(r, min(1.0, n_u / 8), LoginScore(r, 0.0, {}, n_u), SessionScore(0.0, 0.0))


@given(decisions, decisions)
def test_stricter_is_never_looser_than_either_input(d_p, d_r):
    d = stricter(d_p, d_r)
    assert d >= d_p and d >= d_r
    assert d in (d_p, d_r)


@settings(max_examples=2000)
@given(requests, risks, st.integers(0, 50))
def test_pbca_never_looser_than_policy(req, r, n_u):
    pdp = PolicyDecisionPoint()
    rec = pdp.decide(req, assessment(r, n_u))
    assert is_policy_bounded(rec.final, rec.d_policy)
    v = PBCASetup(pdp).evaluate(req, assessment(r, n_u), "IN")
    assert v.decision >= v.d_policy


def test_unbounded_model_can_relax_policy():
    """B2 lets a fooled model (r = 0) open customer records from an unmanaged device."""
    pdp = PolicyDecisionPoint()
    req = AccessRequest(
        Identity("u", "teller", "teller"), DevicePosture(managed=False),
        LoginContext("ip:x", "AS1", "IN", "b", "o", "laptop"),
        Resource("customer-records", Sensitivity.HIGH, customer_records=True), mfa_satisfied="passkey",
    )
    fooled = assessment(0.0, 50)
    b2 = B2UnboundedModel(pdp).evaluate(req, fooled, "IN")
    pbca = PBCASetup(pdp).evaluate(req, fooled, "IN")
    assert b2.d_policy == Decision.DENY
    assert b2.decision == Decision.ALLOW          # violation
    assert pbca.decision == Decision.DENY         # bounded
