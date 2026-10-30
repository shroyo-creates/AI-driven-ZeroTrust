"""Layer 1: login risk with a likelihood-ratio model (Eq. 1).

Following Freeman et al. (NDSS 2016) and Wiefling et al. (ACM TOPS 2022):

    R_L = [P(u|A) / P(u|L)] * prod_k P(x_k|A) / P(x_k|u,L)
    r_L = R_L / (1 + R_L)

* Features are hierarchical. IP falls back to ASN and then country; the user
  agent falls back to OS + device type and then device type. A value that has
  never been seen for a user is smoothed toward the broader level.
* The attacker model P(x|A) is the global population distribution (an
  attacker looks like a random member of the population), optionally mixed
  with the distribution of known attack logins.
* P(u|A) is uniform targeting; P(u|L) is the user's share of legitimate logins.
* All counts live in hash tables (``collections.Counter``) so a score is a few
  dictionary lookups, which keeps interactive logins fast.

Scores are computed in log space and every feature's log-ratio is returned so
the decision can be explained.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Callable

from ..signals import DevicePosture, LoginContext

Path = tuple[str, ...]


def _ip_levels(ctx: LoginContext, device: DevicePosture) -> list[Path]:
    # coarsest first: country -> ASN -> IP
    return [(ctx.country,), (ctx.country, ctx.asn), (ctx.country, ctx.asn, ctx.ip)]


def _ua_levels(ctx: LoginContext, device: DevicePosture) -> list[Path]:
    # coarsest first: device type -> OS -> browser
    return [(ctx.device_type,), (ctx.device_type, ctx.os), (ctx.device_type, ctx.os, ctx.browser)]


def _managed_levels(ctx: LoginContext, device: DevicePosture) -> list[Path]:
    return [("managed" if device.managed else "unmanaged",)]


def _hour_levels(ctx: LoginContext, device: DevicePosture) -> list[Path]:
    # 6-hour buckets: coarse enough not to profile someone's day
    return [(f"h{ctx.hour // 6}",)]


FEATURES: dict[str, Callable[[LoginContext, DevicePosture], list[Path]]] = {
    "ip": _ip_levels,
    "user_agent": _ua_levels,
    "managed_device": _managed_levels,
    "hour_bucket": _hour_levels,
}


@dataclass
class _Counts:
    """Counts of every hierarchy path, per feature."""

    paths: dict[str, Counter] = field(default_factory=lambda: defaultdict(Counter))
    children: dict[str, dict[Path, set]] = field(
        default_factory=lambda: defaultdict(lambda: defaultdict(set))
    )
    total: int = 0

    def add(self, feature: str, levels: list[Path]) -> None:
        parent: Path = ()
        for path in levels:
            self.paths[feature][path] += 1
            self.children[feature][parent].add(path)
            parent = path

    def count(self, feature: str, path: Path) -> int:
        if path == ():
            return self.total
        return self.paths[feature][path]

    def n_children(self, feature: str, parent: Path) -> int:
        return len(self.children[feature][parent])


@dataclass
class LoginScore:
    risk: float                      # r_L in [0, 1)
    log_ratio: float                 # log R_L
    contributions: dict[str, float]  # per-term log-ratios (positive = riskier)
    user_history: int                # n_u, legitimate logins seen for the user


class LoginRiskModel:
    """Freeman-style likelihood-ratio login scorer with hierarchical smoothing.

    Parameters
    ----------
    alpha:
        Strength of the pull toward the global distribution when smoothing a
        user's estimate. Larger values need more history before a familiar
        value lowers risk.
    attack_weight:
        Mixing weight of the known-attack distribution in P(x|A).
    prior_odds:
        Prior odds of attack vs. legitimate, multiplied into R_L. Attacks are
        rare, so the default is below 1; it shifts every score equally and is
        tuned together with the thresholds in report-only mode.
    features:
        Subset of ``FEATURES`` to use (all by default); used for ablations.
    """

    def __init__(
        self,
        alpha: float = 1.0,
        attack_weight: float = 0.3,
        prior_odds: float = 0.1,
        features: tuple[str, ...] | None = None,
    ):
        unknown = set(features or ()) - set(FEATURES)
        if unknown:
            raise ValueError(f"unknown login features: {sorted(unknown)}")
        self.features = {k: FEATURES[k] for k in (features or FEATURES)}
        self.alpha = alpha
        self.attack_weight = attack_weight
        self.prior_odds = prior_odds
        self._global = _Counts()
        self._attack = _Counts()
        self._users: dict[str, _Counts] = defaultdict(_Counts)

    # ---------------------------------------------------------------- training
    def observe(self, user_id: str, ctx: LoginContext, device: DevicePosture) -> None:
        """Record a legitimate (successful, unchallenged) login."""
        self._global.total += 1
        user = self._users[user_id]
        user.total += 1
        for name, levels in self.features.items():
            lv = levels(ctx, device)
            self._global.add(name, lv)
            user.add(name, lv)

    def observe_attack(self, ctx: LoginContext, device: DevicePosture) -> None:
        """Record a login known to come from an attacker (e.g. an attack-IP label)."""
        self._attack.total += 1
        for name, levels in self.features.items():
            self._attack.add(name, levels(ctx, device))

    def history(self, user_id: str) -> int:
        return self._users[user_id].total if user_id in self._users else 0

    @property
    def n_users(self) -> int:
        return len(self._users)

    # ----------------------------------------------------------------- scoring
    def _p_cond(self, counts: _Counts, feature: str, path: Path, parent: Path) -> float:
        """Laplace-smoothed P(path | parent), keeping one slot for unseen values."""
        k = counts.n_children(feature, parent) + 1
        return (counts.count(feature, path) + 1) / (counts.count(feature, parent) + k)

    def _p_attack(self, feature: str, path: Path, parent: Path) -> float:
        p = self._p_cond(self._global, feature, path, parent)
        if self._attack.total and self.attack_weight:
            pa = self._p_cond(self._attack, feature, path, parent)
            p = (1 - self.attack_weight) * p + self.attack_weight * pa
        return p

    def _p_user(self, user: _Counts | None, feature: str, path: Path, parent: Path) -> float:
        pg = self._p_cond(self._global, feature, path, parent)
        if user is None:
            return pg
        c_path, c_parent = user.count(feature, path), user.count(feature, parent)
        return (c_path + self.alpha * pg) / (c_parent + self.alpha)

    def score(self, user_id: str, ctx: LoginContext, device: DevicePosture) -> LoginScore:
        user = self._users.get(user_id)
        n_u = user.total if user else 0
        n_users = max(1, self.n_users)
        total = self._global.total

        # P(u|A) / P(u|L): uniform targeting vs. the user's share of logins.
        # The share is shrunk toward the average user, so an average user scores
        # neutral and a user with no history at most doubles R_L here. Low
        # history is handled mainly by the confidence value (Eq. 4).
        avg = total / n_users if total else 1.0
        p_u_attack = 1.0 / n_users
        p_u_legit = (n_u + avg) / (total + avg * n_users)
        contributions = {"user_prior": math.log(p_u_attack / p_u_legit)}

        for name, levels in self.features.items():
            log_ratio, parent = 0.0, ()
            for path in levels(ctx, device):
                log_ratio += math.log(self._p_attack(name, path, parent))
                log_ratio -= math.log(self._p_user(user, name, path, parent))
                parent = path
            contributions[name] = log_ratio

        log_r = math.log(self.prior_odds) + sum(contributions.values())
        risk = 1.0 / (1.0 + math.exp(-log_r)) if log_r > -700 else 0.0
        return LoginScore(risk=risk, log_ratio=log_r, contributions=contributions, user_history=n_u)
