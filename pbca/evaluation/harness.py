"""Evaluation harness for RQ1-RQ4 (Table IV).

Runs every setup (B0, B1, B2, PBCA) on the same events with a temporal split:
models are trained on the first three months of activity and tested on the
fourth. By default the events come from the synthetic organization in
:mod:`pbca.simulation.data`, so these numbers are a pipeline check, not
experimental results for the paper. Point the loaders in
:mod:`pbca.evaluation.datasets` at the public RBA and CERT data for that.

Run:  python -m pbca.evaluation.harness [--users 200] [--attacks 300] [--out reports]
"""

from __future__ import annotations

import argparse
import json
import math
import random
import time
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

import numpy as np

from ..caep import DemoBankReceiver
from ..decisions import Decision
from ..policy import PolicyDecisionPoint
from ..privacy import minimize_context
from ..risk.engine import RiskEngine
from ..risk.login import LoginRiskModel, LoginScore
from ..risk.session import SessionAnomalyModel
from ..signals import AccessRequest, DevicePosture, Identity, LoginContext, Resource, Sensitivity, ThreatIntel
from ..simulation.data import Employee, Organization
from ..system import PBCASystem
from .baselines import all_setups
from .metrics import percentile, rate, roc_auc, tpr_at_fpr

CUSTOMER_RECORDS = Resource("customer-records", Sensitivity.HIGH, customer_records=True)
REPORTING = Resource("internal-reporting", Sensitivity.MEDIUM)
WINDOW_SECONDS = 300
TOKEN_LIFETIME = 3600


def resource_for(e: Employee) -> Resource:
    return REPORTING if e.identity.role == "it_admin" else CUSTOMER_RECORDS


@dataclass
class Event:
    employee: Employee
    request: AccessRequest
    attack: bool
    kind: str
    phase: str                     # login | session
    login: LoginScore
    window: object | None = None


# --------------------------------------------------------------------- setup
def train(org: Organization, login_features=None, train_months: int = 3) -> RiskEngine:
    login_model = LoginRiskModel(features=login_features)
    for rec in org.legit_logins(months=train_months):
        login_model.observe(rec.employee.identity.user_id, minimize_context(rec.context), rec.device)
    session_model = SessionAnomalyModel().fit(org.windows_by_group(org.windows(per_user=40)))
    return RiskEngine(login_model, session_model)


def build_events(org: Organization, engine: RiskEngine, n_attacks: int) -> list[Event]:
    events: list[Event] = []
    month = 3
    for rec in org.legit_logins(months=1, offset_months=month) + org.attack_logins(n_attacks, offset_months=month):
        e = rec.employee
        ctx = minimize_context(rec.context)
        mfa = e.identity.mfa_method if (not rec.attack or rec.kind == "token") else "totp"
        req = AccessRequest(e.identity, rec.device, ctx, resource_for(e), mfa_satisfied=mfa)
        events.append(Event(e, req, rec.attack, rec.kind, "login", engine.score_login(e.identity, ctx, rec.device)))

    # Session phase: the login looked normal (managed laptop, office network,
    # e.g. a replayed session token); only behavior can reveal misuse.
    for wr in org.windows(per_user=5, offset_months=month) + org.attack_windows(n_attacks, offset_months=month):
        e = wr.employee
        ctx = minimize_context(LoginContext(e.office_ip, e.office_asn, "IN", e.browser, e.os, "laptop", wr.time))
        dev = DevicePosture(managed=True, os_patch_age_days=3, edr_running=True)
        req = AccessRequest(e.identity, dev, ctx, resource_for(e), mfa_satisfied=e.identity.mfa_method)
        events.append(Event(e, req, wr.attack, wr.kind, "session",
                            engine.score_login(e.identity, ctx, dev), wr.window))
    return events


def assess_all(events: list[Event], engine: RiskEngine) -> tuple[list, list[float]]:
    """Score every event once; returns assessments and per-decision latency (ms)."""
    pdp = PolicyDecisionPoint()
    assessments, latencies = [], []
    for ev in events:
        t0 = time.perf_counter()
        a = engine.combine(ev.login, engine.score_session(ev.employee.identity, ev.window))
        pdp.decide(ev.request, a)
        latencies.append((time.perf_counter() - t0) * 1000)
        assessments.append(a)
    return assessments, latencies


def run_setups(events: list[Event], assessments: list, pdp: PolicyDecisionPoint) -> dict:
    results = {}
    for s in all_setups(pdp):
        verdicts = []
        for ev, a in zip(events, assessments):
            v = s.evaluate(ev.request, a, "IN")
            if ev.phase == "session" and not s.sees_sessions:
                # no in-session evaluation: only the static mandatory policy applies
                v.decision, v.score = v.d_policy, 0.0
            verdicts.append(v)
        results[s.name] = verdicts
    return results


# -------------------------------------------------------------------- RQ1/2
def summarize(events, results, phase: str) -> dict:
    idx = [i for i, e in enumerate(events) if e.phase == phase]
    y = np.array([events[i].attack for i in idx], dtype=int)
    out = {}
    for name, verdicts in results.items():
        v = [verdicts[i] for i in idx]
        scores = [x.score for x in v]
        flagged = np.array([x.decision >= Decision.STEP_UP for x in v])
        by_kind = defaultdict(list)
        for i, x in zip(idx, v):
            if events[i].attack:
                by_kind[events[i].kind].append(x.decision >= Decision.STEP_UP)
        out[name] = {
            "roc_auc": roc_auc(y, scores),
            "tpr@fpr1%": tpr_at_fpr(y, scores, 0.01),
            "tpr@fpr5%": tpr_at_fpr(y, scores, 0.05),
            "tpr@fpr10%": tpr_at_fpr(y, scores, 0.10),
            "detected": rate(flagged[y == 1]),
            "detected_by_kind": {k: rate(f) for k, f in sorted(by_kind.items())},
            "stepups_per_100_genuine": 100 * rate(flagged[y == 0]),
            "restricted_genuine_%": 100 * rate([x.decision >= Decision.RESTRICT for x, t in zip(v, y) if t == 0]),
            "policy_violations": int(sum(x.decision < x.d_policy for x in v)),
        }
    return out


def fuzz_policy_bound(pdp: PolicyDecisionPoint, engine: RiskEngine, n: int = 5000, seed: int = 1) -> dict:
    """Random requests with deliberately bad risk scores (incl. forced zero)."""
    rnd = random.Random(seed)
    setups = {s.name: s for s in all_setups(pdp)}
    violations = {"B2 unbounded AI": 0, "PBCA": 0}
    for _ in range(n):
        req = AccessRequest(
            Identity("fuzz", "x", "x", privileged=rnd.random() < 0.3),
            DevicePosture(managed=rnd.random() < 0.5, os_patch_age_days=rnd.choice([0, 10, 90]),
                          edr_running=rnd.random() < 0.7),
            LoginContext("ip:x", "AS1", "IN", "b", "o", "laptop"),
            Resource("r", rnd.choice(list(Sensitivity)), customer_records=rnd.random() < 0.5),
            ThreatIntel(bad_ip=rnd.random() < 0.1, leaked_credential=rnd.random() < 0.1),
            action=rnd.choice(["read", "export"]),
            mfa_satisfied=rnd.choice([None, "totp", "passkey"]),
        )
        r = 0.0 if rnd.random() < 0.5 else rnd.random()
        a = engine.combine(LoginScore(r, 0.0, {}, rnd.randint(0, 20)), engine.score_session(req.identity, None))
        for name in violations:
            v = setups[name].evaluate(req, a, "IN")
            violations[name] += v.decision < v.d_policy
    return {"requests": n, "violations": violations}


# ---------------------------------------------------------------------- RQ3
def containment(org: Organization, engine: RiskEngine, n_sessions: int = 40, max_windows: int = 12) -> dict:
    system = PBCASystem(engine)
    bank = DemoBankReceiver(system.caep.secret)
    system.caep.register("demo-bank", bank)
    rng = np.random.default_rng(3)
    out = {}
    for kind in ("bulk", "mimicry"):
        pbca_exposed, expiry_exposed, contained, windows_to_contain, enforce_ms = [], [], 0, [], []
        for _ in range(n_sessions):
            e = org.employees[int(rng.integers(0, len(org.employees)))]
            if e.identity.role == "it_admin":
                continue
            ctx = LoginContext(e.office_ip, e.office_asn, "IN", e.browser, e.os, "laptop", org.start)
            dev = DevicePosture(managed=True, os_patch_age_days=3, edr_running=True)
            o = system.login(e.identity, dev, ctx, mfa=e.identity.mfa_method)
            if o.session is None:
                continue
            sid = o.session.session_id
            system.access(sid, CUSTOMER_RECORDS)
            windows = [org.attack_window(e, kind) for _ in range(max_windows)]
            # the access token expires at a random point; that bounds both setups
            n_exp = min(max_windows, math.ceil(rng.uniform(0, TOKEN_LIFETIME) / WINDOW_SECONDS))
            expiry_exposed.append(sum(w.records_opened for w in windows[:n_exp]))
            exposed = 0.0
            for k, w in enumerate(windows[:n_exp], 1):
                exposed += w.records_opened
                out_w = system.observe_window(sid, w, trigger_time=time.time())
                if out_w.enforced >= Decision.RESTRICT:
                    contained += 1
                    windows_to_contain.append(k)
                    enforce_ms += [d.containment_seconds * 1000 for d in out_w.deliveries]
                    break
            pbca_exposed.append(exposed)
        out[kind] = {
            "sessions": len(pbca_exposed),
            "contained_before_expiry_%": 100 * contained / max(1, len(pbca_exposed)),
            "median_windows_to_containment": float(np.median(windows_to_contain)) if windows_to_contain else None,
            "trigger_to_enforcement_ms_p95": percentile(enforce_ms, 95) if enforce_ms else None,
            "records_exposed_pbca_mean": float(np.mean(pbca_exposed)) if pbca_exposed else None,
            "records_exposed_token_expiry_mean": float(np.mean(expiry_exposed)) if expiry_exposed else None,
            "seconds_to_containment_token_expiry_mean": TOKEN_LIFETIME / 2,
        }
    return out


# ---------------------------------------------------------------------- RQ4
def frr_by_group(events, verdicts) -> dict:
    groups = defaultdict(list)
    for e, v in zip(events, verdicts):
        if e.attack or e.phase != "login":
            continue
        flagged = v.decision >= Decision.STEP_UP
        freq = "infrequent" if e.employee.logins_per_month < 5 else "frequent"
        groups[f"frequency:{freq}"].append(flagged)
        groups[f"role:{e.employee.identity.role}"].append(flagged)
    return {k: {"n": len(f), "stepup_%": 100 * rate(f)} for k, f in sorted(groups.items())}


def ablations(seed: int, n_users: int, n_attacks: int, pdp: PolicyDecisionPoint) -> dict:
    variants = {
        "all signals": None,
        "no user agent": ("ip", "managed_device", "hour_bucket"),
        "no managed flag": ("ip", "user_agent", "hour_bucket"),
        "IP only": ("ip",),
    }
    out = {}
    for name, feats in variants.items():
        org = Organization(n_users=n_users, seed=seed)
        engine = train(org, login_features=feats)
        events = [e for e in build_events(org, engine, n_attacks) if e.phase == "login"]
        results = run_setups(events, assess_all(events, engine)[0], pdp)
        s = summarize(events, results, "login")["PBCA"]
        out[name] = {k: s[k] for k in ("roc_auc", "tpr@fpr5%", "detected", "stepups_per_100_genuine")}
    return out


def threshold_sweep(events, assessments, scales=(0.5, 0.75, 1.0, 1.25, 1.5)) -> dict:
    from ..policy import DEFAULT_THRESHOLDS
    out = {}
    for k in scales:
        th = {s: tuple(min(0.999 - 0.001 * (2 - i), t * k) for i, t in enumerate(v))
              for s, v in DEFAULT_THRESHOLDS.items()}
        pdp = PolicyDecisionPoint(thresholds=th)
        results = run_setups(events, assessments, pdp)
        login, sess = summarize(events, results, "login")["PBCA"], summarize(events, results, "session")["PBCA"]
        out[f"x{k}"] = {
            "login_detected": login["detected"],
            "session_detected": sess["detected"],
            "stepups_per_100_genuine": login["stepups_per_100_genuine"],
            "session_flags_per_100_genuine_windows": sess["stepups_per_100_genuine"],
        }
    return out


# ---------------------------------------------------------------------- main
def evaluate(seed: int = 42, n_users: int = 200, n_attacks: int = 300, full: bool = True) -> dict:
    org = Organization(n_users=n_users, seed=seed)
    engine = train(org)
    pdp = PolicyDecisionPoint()
    events = build_events(org, engine, n_attacks)
    assessments, latencies = assess_all(events, engine)
    results = run_setups(events, assessments, pdp)
    report = {
        "config": {"seed": seed, "users": n_users, "attacks_per_phase": n_attacks,
                   "events": len(events), "data": "synthetic", "split": "train months 0-3, test month 4"},
        "RQ1_login": summarize(events, results, "login"),
        "RQ1_session": summarize(events, results, "session"),
        "RQ2_fuzz": fuzz_policy_bound(pdp, engine),
        "RQ3_containment": containment(org, engine),
        "RQ4_latency_ms": {"p50": percentile(latencies, 50), "p95": percentile(latencies, 95)},
        "RQ4_frr_by_group": frr_by_group(events, results["PBCA"]),
    }
    if full:
        report["RQ4_threshold_sweep"] = threshold_sweep(events, assessments)
        report["RQ4_signal_ablation"] = ablations(seed, n_users, n_attacks, pdp)
    return report


def _fmt(x) -> str:
    if x is None or (isinstance(x, float) and math.isnan(x)):
        return "–"
    if isinstance(x, float):
        return f"{x:.3f}" if abs(x) < 10 else f"{x:.1f}"
    return str(x)


def to_markdown(report: dict) -> str:
    lines = ["# PBCA evaluation report", "",
             "> Synthetic data: a pipeline check of the evaluation plan, not experimental results.", "",
             "Config: " + ", ".join(f"{k}={v}" for k, v in report["config"].items()), ""]
    for key, title in (("RQ1_login", "RQ1 / RQ2 — login phase"), ("RQ1_session", "RQ1 / RQ2 — session phase")):
        lines += [f"## {title}", "",
                  "| Setup | ROC-AUC | TPR@1%FPR | TPR@5%FPR | Detected | Step-ups /100 genuine | Restricted genuine % | Looser than d_P |",
                  "|---|---|---|---|---|---|---|---|"]
        for name, m in report[key].items():
            lines.append(f"| {name} | {_fmt(m['roc_auc'])} | {_fmt(m['tpr@fpr1%'])} | {_fmt(m['tpr@fpr5%'])} | "
                         f"{_fmt(m['detected'])} | {_fmt(m['stepups_per_100_genuine'])} | "
                         f"{_fmt(m['restricted_genuine_%'])} | {m['policy_violations']} |")
        lines += ["", "Detection by attack kind:", ""]
        for name, m in report[key].items():
            lines.append(f"- **{name}**: " + ", ".join(f"{k} {_fmt(v)}" for k, v in m["detected_by_kind"].items()))
        lines.append("")
    f = report["RQ2_fuzz"]
    lines += ["## RQ2 — property test (random requests, forced-zero risk)", "",
              f"{f['requests']} requests: " + ", ".join(f"{k}: {v} decisions looser than d_P" for k, v in f["violations"].items()), ""]
    lines += ["## RQ3 — containment (CAEP vs. waiting for token expiry)", "",
              "| Misuse | Sessions | Contained before expiry % | Median windows | Trigger→enforcement p95 (ms) | Records exposed (PBCA) | Records exposed (token expiry) |",
              "|---|---|---|---|---|---|---|"]
    for kind, m in report["RQ3_containment"].items():
        lines.append(f"| {kind} | {m['sessions']} | {_fmt(m['contained_before_expiry_%'])} | {_fmt(m['median_windows_to_containment'])} | "
                     f"{_fmt(m['trigger_to_enforcement_ms_p95'])} | {_fmt(m['records_exposed_pbca_mean'])} | "
                     f"{_fmt(m['records_exposed_token_expiry_mean'])} |")
    lat = report["RQ4_latency_ms"]
    lines += ["", "## RQ4 — trade-offs", "", f"Decision latency: p50 {_fmt(lat['p50'])} ms, p95 {_fmt(lat['p95'])} ms", "",
              "Step-up rate for genuine logins by group:", ""]
    for g, m in report["RQ4_frr_by_group"].items():
        lines.append(f"- {g}: {_fmt(m['stepup_%'])}% (n={m['n']})")
    if "RQ4_threshold_sweep" in report:
        lines += ["", "Threshold sweep (all τ scaled):", "",
                  "| Scale | Login detected | Session detected | Step-ups /100 genuine logins | Flags /100 genuine windows |",
                  "|---|---|---|---|---|"]
        for k, m in report["RQ4_threshold_sweep"].items():
            lines.append(f"| {k} | {_fmt(m['login_detected'])} | {_fmt(m['session_detected'])} | "
                         f"{_fmt(m['stepups_per_100_genuine'])} | {_fmt(m['session_flags_per_100_genuine_windows'])} |")
        lines += ["", "Login-signal ablation (PBCA):", "", "| Signals | ROC-AUC | TPR@5%FPR | Detected | Step-ups /100 genuine |",
                  "|---|---|---|---|---|"]
        for k, m in report["RQ4_signal_ablation"].items():
            lines.append(f"| {k} | {_fmt(m['roc_auc'])} | {_fmt(m['tpr@fpr5%'])} | {_fmt(m['detected'])} | "
                         f"{_fmt(m['stepups_per_100_genuine'])} |")
    return "\n".join(lines) + "\n"


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--users", type=int, default=200)
    ap.add_argument("--attacks", type=int, default=300)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--quick", action="store_true", help="skip threshold sweep and ablations")
    ap.add_argument("--out", default="reports")
    args = ap.parse_args(argv)
    report = evaluate(args.seed, args.users, args.attacks, full=not args.quick)
    md = to_markdown(report)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "evaluation.json").write_text(json.dumps(report, indent=2, default=float))
    (out / "evaluation.md").write_text(md)
    print(md)
    print(f"written to {out}/evaluation.md and {out}/evaluation.json")


if __name__ == "__main__":
    main()
