"""Layer 2: session anomaly detection with isolation forests (Eq. 2).

Activity is grouped into short sliding windows (see
:class:`pbca.signals.SessionWindow`). One isolation forest is trained per peer
group (users with the same role). The raw anomaly score is

    s(z) = 2 ** (-E[h(z)] / c(n))

which is what scikit-learn's ``score_samples`` returns, negated. Normal windows
sit around 0.4-0.5 and unusual ones approach 1, so a raw score cannot go
straight into the noisy-OR combination without inflating everyone's risk. We
therefore calibrate it against the peer group's own training windows:

    r_S = clip((s - s_ref) / (s_hi - s_ref), 0, 1)

where ``s_ref`` is a high quantile of the training scores (by default the
97.5th percentile) and ``s_hi`` is the score at which a window counts as fully
anomalous. Both are recorded with every decision. This calibration is an
implementation choice on top of the paper and is one of the knobs RQ4 varies.

Every scored window carries feature attributions. If the ``shap`` package is
installed, TreeSHAP values are used; otherwise each feature is replaced by the
peer-group median and the drop in anomaly score is reported (an occlusion
attribution with the same sign convention).
"""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np
from sklearn.ensemble import IsolationForest

from ..signals import SessionWindow

try:  # optional dependency
    import shap  # type: ignore

    _HAS_SHAP = True
except Exception:  # pragma: no cover - depends on environment
    _HAS_SHAP = False

GLOBAL_GROUP = "__all__"


@dataclass
class SessionScore:
    risk: float                                   # calibrated r_S in [0, 1]
    raw: float                                    # isolation-forest score s(z)
    attributions: dict[str, float] = field(default_factory=dict)
    model_group: str | None = None

    def top_features(self, k: int = 3) -> list[tuple[str, float]]:
        items = [(f, v) for f, v in self.attributions.items() if v > 0]
        return sorted(items, key=lambda kv: kv[1], reverse=True)[:k]


@dataclass
class _GroupModel:
    forest: IsolationForest
    median: np.ndarray
    s_ref: float
    s_hi: float
    explainer: object | None = None


class SessionAnomalyModel:
    def __init__(
        self,
        n_estimators: int = 200,
        ref_quantile: float = 0.975,
        s_hi: float = 0.75,
        min_windows: int = 50,
        random_state: int = 7,
        use_shap: bool = True,
    ):
        self.n_estimators = n_estimators
        self.ref_quantile = ref_quantile
        self.s_hi = s_hi
        self.min_windows = min_windows
        self.random_state = random_state
        self.use_shap = use_shap and _HAS_SHAP
        self._models: dict[str, _GroupModel] = {}

    # ---------------------------------------------------------------- training
    def fit(self, windows_by_group: dict[str, list[SessionWindow]]) -> "SessionAnomalyModel":
        """Train one forest per peer group plus a global fallback."""
        everything: list[SessionWindow] = []
        for group, windows in windows_by_group.items():
            everything.extend(windows)
            if len(windows) >= self.min_windows:
                self._models[group] = self._fit_group(windows)
        if len(everything) >= self.min_windows:
            self._models[GLOBAL_GROUP] = self._fit_group(everything)
        return self

    def _fit_group(self, windows: list[SessionWindow]) -> _GroupModel:
        X = np.array([w.vector() for w in windows], dtype=float)
        forest = IsolationForest(
            n_estimators=self.n_estimators, random_state=self.random_state
        ).fit(X)
        scores = -forest.score_samples(X)
        s_ref = float(np.quantile(scores, self.ref_quantile))
        s_hi = max(self.s_hi, s_ref + 0.05)
        explainer = shap.TreeExplainer(forest) if self.use_shap else None
        return _GroupModel(forest, np.median(X, axis=0), s_ref, s_hi, explainer)

    @property
    def groups(self) -> list[str]:
        return list(self._models)

    # ----------------------------------------------------------------- scoring
    def _model_for(self, group: str) -> tuple[str, _GroupModel] | None:
        if group in self._models:
            return group, self._models[group]
        if GLOBAL_GROUP in self._models:
            return GLOBAL_GROUP, self._models[GLOBAL_GROUP]
        return None

    def _calibrate(self, m: _GroupModel, raw: float) -> float:
        return float(np.clip((raw - m.s_ref) / (m.s_hi - m.s_ref), 0.0, 1.0))

    def score(self, group: str, window: SessionWindow | None, explain_all: bool = False) -> SessionScore:
        """Score one window. No window yet (start of session) means r_S = 0."""
        found = self._model_for(group)
        if window is None or found is None:
            return SessionScore(risk=0.0, raw=0.0, model_group=None)
        name, m = found
        x = np.array([window.vector()], dtype=float)
        if m.explainer is None:
            # score the window and every occlusion probe in a single forest pass
            probes = np.repeat(x, len(SessionWindow.FEATURES) + 1, axis=0)
            for i in range(len(SessionWindow.FEATURES)):
                probes[i + 1, i] = m.median[i]
            scores = -m.forest.score_samples(probes)
            raw = float(scores[0])
            occlusion = {n: raw - float(s) for n, s in zip(SessionWindow.FEATURES, scores[1:])}
        else:
            raw = float(-m.forest.score_samples(x)[0])
            occlusion = None
        risk = self._calibrate(m, raw)
        # explanations are stored for windows that raise risk (Section V-E)
        attributions: dict[str, float] = {}
        if risk > 0 or explain_all:
            attributions = occlusion if occlusion is not None else self._shap(m, x)
        return SessionScore(risk=risk, raw=raw, attributions=attributions, model_group=name)

    @staticmethod
    def _shap(m: _GroupModel, x: np.ndarray) -> dict[str, float]:
        # SHAP explains the forest's decision function (higher = more normal),
        # so flip the sign to make positive values push risk up.
        values = np.asarray(m.explainer.shap_values(x))[0]
        return {n: float(-v) for n, v in zip(SessionWindow.FEATURES, values)}
