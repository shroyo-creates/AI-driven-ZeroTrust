from datetime import datetime

import pytest

from pbca.privacy import hash_ip, minimize_context
from pbca.risk.engine import confidence, noisy_or
from pbca.risk.login import LoginRiskModel
from pbca.signals import DevicePosture, LoginContext, SessionWindow

MANAGED = DevicePosture(managed=True)
T = datetime(2026, 3, 2, 10)


def ctx(ip="10.0.0.5", asn="AS64500", cc="IN", browser="Edge", os="Windows", dev="laptop", when=T):
    return LoginContext(ip, asn, cc, browser, os, dev, when)


@pytest.fixture
def model():
    m = LoginRiskModel()
    for _ in range(30):
        m.observe("alice", ctx(), MANAGED)
    for u in range(40):
        for i in range(10):
            m.observe(f"u{u}", ctx(ip=f"10.1.{u}.{i % 3}", asn=f"AS{u % 4}"), MANAGED)
    return m


# ------------------------------------------------------------------- Layer 1
def test_familiar_login_is_low_risk(model):
    assert model.score("alice", ctx(), MANAGED).risk < 0.05


def test_attacker_login_is_high_risk(model):
    s = model.score("alice", ctx("185.1.1.1", "AS999", "RO", "Firefox", "Linux", "desktop",
                                 T.replace(hour=3)), DevicePosture(managed=False))
    assert s.risk > 0.95
    assert all(s.contributions[k] > 0 for k in ("ip", "user_agent", "managed_device"))


def test_hierarchical_smoothing_new_ip_same_asn_is_less_risky(model):
    same_asn = model.score("alice", ctx(ip="10.0.0.99"), MANAGED).risk
    new_asn = model.score("alice", ctx(ip="49.1.1.1", asn="AS777"), MANAGED).risk
    new_country = model.score("alice", ctx(ip="49.1.1.1", asn="AS777", cc="BR"), MANAGED).risk
    assert same_asn < new_asn <= new_country


def test_user_prior_is_bounded_for_new_users(model):
    import math
    s = model.score("nobody", ctx(), MANAGED)
    assert 0 < s.contributions["user_prior"] <= math.log(2) + 1e-9
    assert s.user_history == 0
    assert s.risk < 0.5     # low history alone does not make a login risky; Eq. 4 handles it


def test_more_history_makes_unfamiliar_values_riskier():
    m = LoginRiskModel()
    for u in range(10):
        m.observe(f"x{u}", ctx(ip=f"10.9.9.{u}"), MANAGED)
    m.observe("bob", ctx(), MANAGED)
    weird = ctx("185.1.1.1", "AS999", "RO", "Firefox", "Linux", "desktop")
    few = m.score("bob", weird, DevicePosture(managed=False)).risk
    for _ in range(20):
        m.observe("bob", ctx(), MANAGED)
    many = m.score("bob", weird, DevicePosture(managed=False)).risk
    assert many > few


def test_known_attack_distribution_raises_matching_logins(model):
    attacker = ctx("185.1.1.1", "AS999", "RO", "Firefox", "Linux", "desktop")
    before = model.score("u1", attacker, DevicePosture(managed=False)).log_ratio
    for _ in range(20):
        model.observe_attack(attacker, DevicePosture(managed=False))
    assert model.score("u1", attacker, DevicePosture(managed=False)).log_ratio > before


def test_feature_subset_and_validation():
    m = LoginRiskModel(features=("ip",))
    m.observe("a", ctx(), MANAGED)
    assert set(m.score("a", ctx(), MANAGED).contributions) == {"user_prior", "ip"}
    with pytest.raises(ValueError):
        LoginRiskModel(features=("shoe_size",))


# ------------------------------------------------------------------- Layer 2
def test_session_layer_flags_bulk_export(org, engine, frequent_employee):
    e = frequent_employee
    normal = [engine.score_session(e.identity, org.legit_window(e)).risk for _ in range(30)]
    bulk = engine.score_session(e.identity, org.attack_window(e, "bulk"))
    assert sum(normal) / len(normal) < 0.1
    assert bulk.risk > 0.8
    assert bulk.top_features(1)[0][1] > 0


def test_no_window_means_zero_session_risk(engine, frequent_employee):
    s = engine.score_session(frequent_employee.identity, None)
    assert s.risk == 0.0 and s.attributions == {}


def test_unknown_peer_group_falls_back_to_global_model(engine, frequent_employee):
    from dataclasses import replace
    stranger = replace(frequent_employee.identity, peer_group="new-team")
    s = engine.score_session(stranger, SessionWindow(records_opened=10, distinct_record_types=2))
    assert s.model_group == "__all__"


# --------------------------------------------------------- aggregation, Eq 3-4
def test_noisy_or():
    assert noisy_or(0, 0) == 0
    assert noisy_or(0.5, 0.5) == pytest.approx(0.75)
    assert noisy_or(0.9, 0) == pytest.approx(0.9)
    assert noisy_or(0, 0.9) == pytest.approx(0.9)


def test_confidence():
    assert confidence(0) == 0
    assert confidence(4) == 0.5
    assert confidence(8) == 1
    assert confidence(100) == 1


# -------------------------------------------------------------------- privacy
def test_ip_is_hashed_and_stable():
    c = minimize_context(ctx(ip="203.0.113.7"))
    assert c.ip.startswith("ip:") and "203.0.113.7" not in c.ip
    assert c.ip == hash_ip("203.0.113.7")
    assert minimize_context(c) == c
    assert hash_ip("203.0.113.7", b"other-salt") != c.ip
