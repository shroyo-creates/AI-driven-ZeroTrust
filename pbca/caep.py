"""OpenID Shared Signals Framework / CAEP 1.0 events.

When a re-evaluation produces a decision stricter than the one currently
applied to a session, the PDP (acting as SSF transmitter) sends a Security
Event Token (SET, RFC 8417) to every registered receiver:

* DENY                -> ``session-revoked``
* compromise confirmed -> ``credential-change`` (plus session-revoked)
* RESTRICT / STEP_UP  -> ``token-claims-change`` carrying the new access tier

SETs are signed as compact JWS with HS256 using a shared secret, which keeps
the demo dependency-free. A production deployment would use asymmetric keys
published through the transmitter's JWKS.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Callable

from .decisions import Decision

CAEP = "https://schemas.openid.net/secevent/caep/event-type/"
SESSION_REVOKED = CAEP + "session-revoked"
CREDENTIAL_CHANGE = CAEP + "credential-change"
TOKEN_CLAIMS_CHANGE = CAEP + "token-claims-change"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def sign_set(payload: dict, secret: bytes) -> str:
    header = {"alg": "HS256", "typ": "secevent+jwt"}
    signing_input = f"{_b64(json.dumps(header).encode())}.{_b64(json.dumps(payload).encode())}"
    sig = hmac.new(secret, signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{_b64(sig)}"


def verify_set(token: str, secret: bytes) -> dict:
    try:
        h, p, s = token.split(".")
    except ValueError as exc:
        raise ValueError("malformed SET") from exc
    expected = hmac.new(secret, f"{h}.{p}".encode(), hashlib.sha256).digest()
    if not hmac.compare_digest(expected, _unb64(s)):
        raise ValueError("bad SET signature")
    return json.loads(_unb64(p))


def event_type_for(decision: Decision) -> str:
    return SESSION_REVOKED if decision >= Decision.DENY else TOKEN_CLAIMS_CHANGE


@dataclass
class Delivery:
    jti: str
    event_type: str
    session_id: str
    decision: str
    trigger_time: float
    delivered_time: float
    receiver: str

    @property
    def containment_seconds(self) -> float:
        return self.delivered_time - self.trigger_time


Receiver = Callable[[str], None]


@dataclass
class CaepTransmitter:
    issuer: str = "https://pbca.local/"
    secret: bytes = b"pbca-demo-shared-secret"
    receivers: dict[str, Receiver] = field(default_factory=dict)
    deliveries: list[Delivery] = field(default_factory=list)

    def register(self, audience: str, receiver: Receiver) -> None:
        self.receivers[audience] = receiver

    def build(
        self,
        event_type: str,
        session_id: str,
        user_id: str,
        audience: str,
        reason: str,
        extra: dict | None = None,
    ) -> dict:
        now = int(time.time())
        body = {"event_timestamp": now, "initiating_entity": "policy", "reason_admin": {"en": reason}}
        body.update(extra or {})
        return {
            "iss": self.issuer,
            "jti": uuid.uuid4().hex,
            "iat": now,
            "aud": audience,
            "sub_id": {
                "format": "complex",
                "session": {"format": "opaque", "id": session_id},
                "user": {"format": "opaque", "id": user_id},
            },
            "events": {event_type: body},
        }

    def send(
        self,
        event_type: str,
        session_id: str,
        user_id: str,
        decision: Decision,
        reason: str,
        trigger_time: float | None = None,
        extra: dict | None = None,
    ) -> list[Delivery]:
        """Sign and push the event to every receiver; record time to containment."""
        trigger_time = trigger_time if trigger_time is not None else time.time()
        out = []
        for aud, receiver in self.receivers.items():
            payload = self.build(event_type, session_id, user_id, aud, reason, {"pbca_tier": decision.name, **(extra or {})})
            receiver(sign_set(payload, self.secret))
            d = Delivery(payload["jti"], event_type, session_id, decision.name, trigger_time, time.time(), aud)
            self.deliveries.append(d)
            out.append(d)
        return out


class DemoBankReceiver:
    """A CAEP receiver standing in for the demo banking application.

    It keeps its own view of each session and applies the tier it is told to.
    """

    def __init__(self, secret: bytes = b"pbca-demo-shared-secret"):
        self.secret = secret
        self.sessions: dict[str, str] = {}
        self.received: list[dict] = []

    def __call__(self, token: str) -> None:
        payload = verify_set(token, self.secret)
        self.received.append(payload)
        session_id = payload["sub_id"]["session"]["id"]
        for event_type, body in payload["events"].items():
            if event_type in (SESSION_REVOKED, CREDENTIAL_CHANGE):
                self.sessions[session_id] = "REVOKED"
            else:
                self.sessions[session_id] = body.get("pbca_tier", "RESTRICT")
