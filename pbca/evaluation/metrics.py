"""Metrics from Table IV."""

from __future__ import annotations

import numpy as np
from sklearn.metrics import roc_auc_score, roc_curve


def tpr_at_fpr(y_true, scores, target_fpr: float) -> float:
    """True-positive rate at the largest operating point with FPR <= target."""
    y_true, scores = np.asarray(y_true), np.asarray(scores, dtype=float)
    if y_true.min() == y_true.max():
        return float("nan")
    fpr, tpr, _ = roc_curve(y_true, scores)
    ok = fpr <= target_fpr
    return float(tpr[ok].max()) if ok.any() else 0.0


def roc_auc(y_true, scores) -> float:
    y_true = np.asarray(y_true)
    if y_true.min() == y_true.max():
        return float("nan")
    return float(roc_auc_score(y_true, scores))


def rate(flags) -> float:
    flags = np.asarray(flags, dtype=float)
    return float(flags.mean()) if flags.size else float("nan")


def percentile(values, q: float) -> float:
    values = np.asarray(values, dtype=float)
    return float(np.percentile(values, q)) if values.size else float("nan")
