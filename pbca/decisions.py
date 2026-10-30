"""Ordered access decisions and the policy-bounded combination rule (Eq. 5).

Decisions are totally ordered by strictness:

    ALLOW < STEP_UP < RESTRICT < DENY

The final decision is ``stricter(d_P, d_R) = max(d_P, d_R)``. Because the
maximum of two elements of a total order is never below either of them, the
final decision is never looser than the mandatory policy decision ``d_P``,
whatever the risk engine outputs. This is the *policy-bounding* property.
"""

from __future__ import annotations

from enum import IntEnum


class Decision(IntEnum):
    """Access decision tiers, ordered from least to most strict."""

    ALLOW = 0      # role-appropriate access
    STEP_UP = 1    # require a stronger (phishing-resistant) factor first
    RESTRICT = 2   # read-only, sensitive fields masked, no export
    DENY = 3       # refuse the request / revoke an open session

    @property
    def label(self) -> str:
        return {
            Decision.ALLOW: "Allow",
            Decision.STEP_UP: "Step-up MFA",
            Decision.RESTRICT: "Restrict",
            Decision.DENY: "Deny / revoke",
        }[self]


def stricter(*decisions: Decision) -> Decision:
    """Return the strictest of the given decisions (Eq. 5)."""
    if not decisions:
        raise ValueError("stricter() needs at least one decision")
    return Decision(max(decisions))


def is_policy_bounded(final: Decision, policy_decision: Decision) -> bool:
    """True when ``final`` is at least as strict as the policy decision."""
    return final >= policy_decision
