"""Data minimization (Table II, Section VII).

* IP addresses are replaced by a salted hash before scoring or logging.
* Location is kept only at country level.
* Behavior is kept as counts and rates, never content.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import replace

from .signals import LoginContext

_DEFAULT_SALT = os.environ.get("PBCA_IP_SALT", "pbca-demo-salt").encode()


def hash_ip(ip: str, salt: bytes = _DEFAULT_SALT) -> str:
    """Keyed hash of an IP address; stable for one salt, unlinkable without it."""
    return "ip:" + hmac.new(salt, ip.encode(), hashlib.sha256).hexdigest()[:16]


def minimize_context(ctx: LoginContext, salt: bytes = _DEFAULT_SALT) -> LoginContext:
    """Return a copy of ``ctx`` with the raw IP replaced by its salted hash."""
    if ctx.ip.startswith("ip:"):
        return ctx
    return replace(ctx, ip=hash_ip(ctx.ip, salt))
