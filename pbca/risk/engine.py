"""Risk engine: aggregation (Eq. 3) and confidence (Eq. 4).

The risk engine is the only machine-learning component in PBCA. It produces
evidence (a risk value, a confidence value and an explanation) and never
decides anything itself; the policy decision point does that.

    r = 1 - (1 - r_L)(1 - r_S)        noisy-OR: either layer can raise risk
    c = min(1, n_u / n_min)           n_min = 8 (Wiefling et al.)
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..signals import DevicePosture, Identity, LoginContext, SessionWindow
from .login import LoginRiskModel, LoginScore
from .session import SessionAnomalyModel, SessionScore

N_MIN = 8


def noisy_or(r_login: float, r_session: float) -> float:
    return 1.0 - (1.0 - r_login) * (1.0 - r_session)


def confidence(n_u: int, n_min: int = N_MIN) -> float:
    return min(1.0, n_u / n_min) if n_min > 0 else 1.0


@dataclass
class RiskAssessment:
    risk: float
    confidence: float
    login: LoginScore
    session: SessionScore
    explanation: list[str] = field(default_factory=list)

    @property
    def r_login(self) -> float:
        return self.login.risk

    @property
    def r_session(self) -> float:
        return self.session.risk

    def to_dict(self) -> dict:
        return {
            "risk": round(self.risk, 4),
            "confidence": round(self.confidence, 3),
            "r_login": round(self.r_login, 4),
            "r_session": round(self.r_session, 4),
            "session_raw": round(self.session.raw, 4),
            "login_contributions": {k: round(v, 3) for k, v in self.login.contributions.items()},
            "session_attributions": {k: round(v, 4) for k, v in self.session.attributions.items()},
            "explanation": self.explanation,
        }


class RiskEngine:
    def __init__(
        self,
        login_model: LoginRiskModel | None = None,
        session_model: SessionAnomalyModel | None = None,
        n_min: int = N_MIN,
    ):
        self.login_model = login_model or LoginRiskModel()
        self.session_model = session_model or SessionAnomalyModel()
        self.n_min = n_min

    def score_login(self, identity: Identity, ctx: LoginContext, device: DevicePosture) -> LoginScore:
        return self.login_model.score(identity.user_id, ctx, device)

    def score_session(self, identity: Identity, window: SessionWindow | None) -> SessionScore:
        return self.session_model.score(identity.peer_group, window)

    def combine(self, login: LoginScore, session: SessionScore) -> RiskAssessment:
        r = noisy_or(login.risk, session.risk)
        c = confidence(login.user_history, self.n_min)
        return RiskAssessment(r, c, login, session, self._explain(login, session, c))

    def assess(
        self,
        identity: Identity,
        ctx: LoginContext,
        device: DevicePosture,
        window: SessionWindow | None = None,
    ) -> RiskAssessment:
        return self.combine(self.score_login(identity, ctx, device), self.score_session(identity, window))

    @staticmethod
    def _explain(login: LoginScore, session: SessionScore, c: float) -> list[str]:
        notes = []
        risky = sorted(
            ((k, v) for k, v in login.contributions.items() if v > 0.5),
            key=lambda kv: kv[1],
            reverse=True,
        )
        for name, v in risky[:3]:
            notes.append(f"login: unfamiliar {name.replace('_', ' ')} (log-ratio +{v:.1f})")
        for name, v in session.top_features():
            notes.append(f"session: {name.replace('_', ' ')} unusual for peer group (+{v:.3f})")
        if c < 1.0:
            notes.append(f"low history: {login.user_history} prior logins (confidence {c:.2f})")
        return notes
