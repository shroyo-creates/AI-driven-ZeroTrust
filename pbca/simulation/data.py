"""Synthetic financial-services workforce for demos and the evaluation harness.

The real evaluation (Section V-I) uses the public RBA login dataset of
Wiefling et al. and the CERT Insider Threat dataset; loaders for both are in
:mod:`pbca.evaluation.datasets`. This module generates data with the same
shape so the whole pipeline runs offline, with no personal data:

* employees in peer groups (tellers, analysts, relationship managers, IT
  admins), each with an office network, a home ISP and a managed laptop;
  a share of users log in rarely (the infrequent users Wiefling et al. found
  to be challenged more often);
* a time-stamped stream of legitimate logins and 5-minute behavior windows;
* attacks from the threat model of Section V-B:
    - ``naive``      foreign network, unmanaged device, random user agent
    - ``targeted``   proxy in the victim's country, copied user agent
    - ``token``      stolen session token: the login looks exactly like the victim
  and in-session misuse:
    - ``bulk``       bulk viewing and export of customer records
    - ``mimicry``    a patient attacker staying close to normal habits
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

import numpy as np

from ..signals import DevicePosture, Identity, LoginContext, SessionWindow

COUNTRY = "IN"
FOREIGN = ["RU", "NG", "BR", "US", "RO", "VN", "CN", "UA"]
BROWSERS = ["Chrome", "Edge", "Firefox", "Safari"]
OSES = ["Windows", "macOS", "Linux", "Android", "iOS"]

# Behavior profile per peer group: mean records opened, record types, exports,
# prints and unusual-app requests per 5-minute window.
PROFILES = {
    "teller": dict(records=10, types=2, exports=0.03, prints=0.2, apps=0.02),
    "analyst": dict(records=25, types=4, exports=0.3, prints=0.1, apps=0.05),
    "relationship_manager": dict(records=15, types=3, exports=0.1, prints=0.3, apps=0.03),
    "it_admin": dict(records=2, types=1, exports=0.05, prints=0.0, apps=0.4),
}
ROLE_MIX = [("teller", 0.4), ("analyst", 0.25), ("relationship_manager", 0.25), ("it_admin", 0.1)]


@dataclass(frozen=True)
class Employee:
    identity: Identity
    office_ip: str
    office_asn: str
    home_ip: str
    home_asn: str
    browser: str
    os: str
    logins_per_month: float


@dataclass(frozen=True)
class LoginRecord:
    employee: Employee
    context: LoginContext
    device: DevicePosture
    attack: bool = False
    kind: str = "legit"


@dataclass(frozen=True)
class WindowRecord:
    employee: Employee
    window: SessionWindow
    time: datetime
    attack: bool = False
    kind: str = "legit"


@dataclass
class Organization:
    n_users: int = 200
    seed: int = 42
    start: datetime = datetime(2026, 1, 1)
    infrequent_share: float = 0.2
    employees: list[Employee] = field(default_factory=list)

    def __post_init__(self):
        self.rng = np.random.default_rng(self.seed)
        roles = [r for r, _ in ROLE_MIX]
        probs = [p for _, p in ROLE_MIX]
        for i in range(self.n_users):
            role = str(self.rng.choice(roles, p=probs))
            branch = i % 8
            infrequent = self.rng.random() < self.infrequent_share
            self.employees.append(
                Employee(
                    identity=Identity(
                        user_id=f"emp{i:04d}",
                        role=role,
                        peer_group=role,
                        account_age_days=int(self.rng.integers(30, 3000)),
                        mfa_method="passkey" if self.rng.random() < 0.7 else "totp",
                        privileged=role == "it_admin",
                    ),
                    office_ip=f"10.{branch}.{i // 250}.{i % 250 + 2}",
                    office_asn="AS64500",
                    home_ip=f"49.{int(self.rng.integers(1, 250))}.{int(self.rng.integers(0, 250))}.{i % 250}",
                    home_asn=str(self.rng.choice(["AS24560", "AS55836", "AS45609", "AS9829"])),
                    browser="Edge" if self.rng.random() < 0.6 else "Chrome",
                    os="Windows",
                    logins_per_month=float(self.rng.uniform(1, 3) if infrequent else self.rng.uniform(15, 40)),
                )
            )

    # ---------------------------------------------------------- legit logins
    def _legit_context(self, e: Employee, when: datetime) -> tuple[LoginContext, DevicePosture]:
        at_home = self.rng.random() < 0.25
        ip, asn = (e.home_ip, e.home_asn) if at_home else (e.office_ip, e.office_asn)
        ctx = LoginContext(ip, asn, COUNTRY, e.browser, e.os, "laptop", when)
        patch = int(self.rng.integers(0, 45)) if self.rng.random() < 0.05 else int(self.rng.integers(0, 20))
        return ctx, DevicePosture(managed=True, os_patch_age_days=patch, edr_running=True)

    def _work_time(self, day_offset: float) -> datetime:
        day = self.start + timedelta(days=int(day_offset))
        hour = float(np.clip(self.rng.normal(11, 2.5), 6, 22))
        return day + timedelta(hours=hour)

    def legit_logins(self, months: int = 3, offset_months: int = 0) -> list[LoginRecord]:
        out = []
        for e in self.employees:
            n = self.rng.poisson(e.logins_per_month * months)
            days = self.rng.uniform(offset_months * 30, (offset_months + months) * 30, size=n)
            for d in np.sort(days):
                ctx, dev = self._legit_context(e, self._work_time(d))
                out.append(LoginRecord(e, ctx, dev))
        return sorted(out, key=lambda r: r.context.timestamp)

    # ------------------------------------------------------- attack logins
    def attack_login(self, victim: Employee, kind: str, when: datetime) -> LoginRecord:
        r = self.rng
        if kind == "naive":
            cc = str(r.choice(FOREIGN))
            ctx = LoginContext(
                f"185.{int(r.integers(0, 255))}.{int(r.integers(0, 255))}.{int(r.integers(1, 255))}",
                f"AS{int(r.integers(10000, 60000))}", cc,
                str(r.choice(BROWSERS)), str(r.choice(OSES)), str(r.choice(["desktop", "mobile"])),
                when.replace(hour=int(r.integers(0, 24))),
            )
            dev = DevicePosture(managed=False, os_patch_age_days=int(r.integers(30, 400)), edr_running=False)
        elif kind == "targeted":
            # residential proxy in the victim's country, victim's browser copied
            ctx = LoginContext(
                f"103.{int(r.integers(0, 255))}.{int(r.integers(0, 255))}.{int(r.integers(1, 255))}",
                str(r.choice(["AS24560", "AS55836", "AS133982"])), COUNTRY,
                victim.browser, victim.os, "laptop", when,
            )
            dev = DevicePosture(managed=False, os_patch_age_days=int(r.integers(0, 90)), edr_running=False)
        elif kind == "token":
            ctx, dev = self._legit_context(victim, when)
        else:
            raise ValueError(kind)
        return LoginRecord(victim, ctx, dev, attack=True, kind=kind)

    def attack_logins(self, n: int, kinds=("naive", "targeted", "token"), offset_months: int = 3) -> list[LoginRecord]:
        out = []
        for i in range(n):
            victim = self.employees[int(self.rng.integers(0, len(self.employees)))]
            when = self._work_time(self.rng.uniform(offset_months * 30, offset_months * 30 + 30))
            out.append(self.attack_login(victim, kinds[i % len(kinds)], when))
        return out

    # ---------------------------------------------------- behavior windows
    def legit_window(self, e: Employee) -> SessionWindow:
        p, r = PROFILES[e.identity.role], self.rng
        return SessionWindow(
            records_opened=float(r.poisson(p["records"])),
            distinct_record_types=float(max(1, r.poisson(p["types"]))),
            exports=float(r.poisson(p["exports"])),
            prints=float(r.poisson(p["prints"])),
            unusual_app_requests=float(r.poisson(p["apps"])),
            request_rate_ratio=float(r.lognormal(0, 0.25)),
        )

    def attack_window(self, e: Employee, kind: str) -> SessionWindow:
        p, r = PROFILES[e.identity.role], self.rng
        if kind == "bulk":
            return SessionWindow(
                records_opened=float(r.integers(80, 250)),
                distinct_record_types=float(r.integers(p["types"] + 2, p["types"] + 8)),
                exports=float(r.integers(3, 20)),
                prints=float(r.poisson(1)),
                unusual_app_requests=float(r.poisson(1.5)),
                request_rate_ratio=float(r.uniform(3, 8)),
            )
        if kind == "mimicry":
            return SessionWindow(
                records_opened=float(r.poisson(p["records"] * 1.4)),
                distinct_record_types=float(max(1, r.poisson(p["types"]))),
                exports=float(r.poisson(0.5)),
                prints=float(r.poisson(p["prints"])),
                unusual_app_requests=float(r.poisson(p["apps"])),
                request_rate_ratio=float(r.lognormal(0.2, 0.25)),
            )
        raise ValueError(kind)

    def windows(self, per_user: int = 40, offset_months: int = 0) -> list[WindowRecord]:
        out = []
        for e in self.employees:
            for _ in range(per_user):
                out.append(WindowRecord(e, self.legit_window(e), self._work_time(self.rng.uniform(offset_months * 30, offset_months * 30 + 30))))
        return out

    def attack_windows(self, n: int, kinds=("bulk", "mimicry"), offset_months: int = 3) -> list[WindowRecord]:
        out = []
        for i in range(n):
            e = self.employees[int(self.rng.integers(0, len(self.employees)))]
            kind = kinds[i % len(kinds)]
            when = self._work_time(self.rng.uniform(offset_months * 30, offset_months * 30 + 30))
            out.append(WindowRecord(e, self.attack_window(e, kind), when, attack=True, kind=kind))
        return out

    def windows_by_group(self, records: list[WindowRecord]) -> dict[str, list[SessionWindow]]:
        groups: dict[str, list[SessionWindow]] = {}
        for r in records:
            groups.setdefault(r.employee.identity.peer_group, []).append(r.window)
        return groups


def build_trained_engine(org: Organization, train_months: int = 3, windows_per_user: int = 40):
    """Train both layers on the first ``train_months`` of legitimate activity."""
    from ..risk.engine import RiskEngine
    from ..risk.login import LoginRiskModel
    from ..risk.session import SessionAnomalyModel
    from ..privacy import minimize_context

    login_model = LoginRiskModel()
    for rec in org.legit_logins(months=train_months):
        login_model.observe(rec.employee.identity.user_id, minimize_context(rec.context), rec.device)
    session_model = SessionAnomalyModel().fit(org.windows_by_group(org.windows(per_user=windows_per_user)))
    return RiskEngine(login_model, session_model)
