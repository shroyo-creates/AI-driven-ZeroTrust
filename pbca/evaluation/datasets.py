"""Loaders for the public datasets named in the evaluation plan (Section V-I).

Neither dataset is redistributed with this repository; download them and
point these functions at the files.

* RBA login dataset (Wiefling et al., 2022): ``rba-dataset.csv``, 33M+
  synthesized logins with attack-IP and account-takeover labels.
  https://github.com/das-group/rba-dataset
* CERT Insider Threat Test Dataset (r4.2 or later), Carnegie Mellon SEI:
  per-user ``logon.csv``, ``device.csv``, ``file.csv``, ``http.csv`` and the
  ``answers/insiders.csv`` key.
  https://kilthub.cmu.edu/articles/dataset/Insider_Threat_Test_Dataset/12841247

Both loaders stream rows so they can handle the full files.
"""

from __future__ import annotations

import csv
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterator

from ..signals import DevicePosture, LoginContext, SessionWindow


def _truthy(v: str) -> bool:
    return str(v).strip().lower() in {"true", "1", "yes"}


# ---------------------------------------------------------------- RBA logins
@dataclass(frozen=True)
class RBALogin:
    user_id: str
    context: LoginContext
    device: DevicePosture
    successful: bool
    attack_ip: bool
    account_takeover: bool


def _parse_ts(v: str) -> datetime:
    v = v.strip()
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(v, fmt)
        except ValueError:
            pass
    return datetime.fromisoformat(v)


def load_rba(path: str | Path, limit: int | None = None) -> Iterator[RBALogin]:
    """Yield logins from the RBA dataset CSV.

    The dataset has no device-management flag, so every device is reported as
    managed; the ``managed_device`` feature then carries no information and
    ablations should drop it.
    """
    with open(path, newline="", encoding="utf-8") as fh:
        for i, row in enumerate(csv.DictReader(fh)):
            if limit is not None and i >= limit:
                break
            ctx = LoginContext(
                ip=row["IP Address"],
                asn=str(row["ASN"]),
                country=row["Country"],
                browser=row.get("Browser Name and Version", ""),
                os=row.get("OS Name and Version", ""),
                device_type=row.get("Device Type", ""),
                timestamp=_parse_ts(row["Login Timestamp"]),
            )
            yield RBALogin(
                user_id=str(row["User ID"]),
                context=ctx,
                device=DevicePosture(managed=True),
                successful=_truthy(row.get("Login Successful", "True")),
                attack_ip=_truthy(row.get("Is Attack IP", "False")),
                account_takeover=_truthy(row.get("Is Account Takeover", "False")),
            )


# ------------------------------------------------------------- CERT windows
@dataclass(frozen=True)
class CertWindow:
    user_id: str
    start: datetime
    window: SessionWindow
    malicious: bool


def _cert_ts(v: str) -> datetime:
    return datetime.strptime(v.strip(), "%m/%d/%Y %H:%M:%S")


def load_cert_insiders(answers_csv: str | Path) -> dict[str, list[tuple[datetime, datetime]]]:
    """Map user -> list of (start, end) malicious periods from the answer key."""
    out: dict[str, list[tuple[datetime, datetime]]] = defaultdict(list)
    with open(answers_csv, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            out[row["user"]].append((_cert_ts(row["start"]), _cert_ts(row["end"])))
    return out


def load_cert_windows(
    root: str | Path,
    answers_csv: str | Path | None = None,
    window: timedelta = timedelta(minutes=5),
) -> list[CertWindow]:
    """Aggregate CERT activity logs into PBCA behavior windows.

    Mapping to :class:`SessionWindow` features:

    * ``records_opened``          file.csv events (file accesses)
    * ``distinct_record_types``   distinct file extensions in the window
    * ``exports``                 device.csv ``Connect`` events (removable media)
    * ``prints``                  0 (not in CERT)
    * ``unusual_app_requests``    http.csv requests to domains the user has
                                  not visited before
    * ``request_rate_ratio``      events in window / user's median per window
    """
    root = Path(root)
    bins: dict[tuple[str, datetime], dict] = defaultdict(
        lambda: {"files": 0, "exts": set(), "exports": 0, "new_domains": 0, "events": 0}
    )
    seen_domains: dict[str, set] = defaultdict(set)

    def key(user: str, ts: datetime) -> tuple[str, datetime]:
        start = ts - timedelta(minutes=ts.minute % (window.seconds // 60), seconds=ts.second)
        return user, start

    def rows(name: str):
        p = root / name
        if p.exists():
            with p.open(newline="", encoding="utf-8", errors="replace") as fh:
                yield from csv.DictReader(fh)

    for r in rows("file.csv"):
        b = bins[key(r["user"], _cert_ts(r["date"]))]
        b["files"] += 1
        b["events"] += 1
        b["exts"].add(Path(r.get("filename", "")).suffix.lower())
    for r in rows("device.csv"):
        b = bins[key(r["user"], _cert_ts(r["date"]))]
        b["events"] += 1
        if r.get("activity", "").strip().lower() == "connect":
            b["exports"] += 1
    http = sorted(rows("http.csv"), key=lambda r: _cert_ts(r["date"]))
    for r in http:
        user = r["user"]
        domain = r.get("url", "").split("/")[2] if "//" in r.get("url", "") else r.get("url", "")
        b = bins[key(user, _cert_ts(r["date"]))]
        b["events"] += 1
        if domain not in seen_domains[user]:
            seen_domains[user].add(domain)
            b["new_domains"] += 1

    per_user_events: dict[str, list[int]] = defaultdict(list)
    for (user, _), b in bins.items():
        per_user_events[user].append(b["events"])
    medians = {u: max(1.0, sorted(v)[len(v) // 2]) for u, v in per_user_events.items()}

    insiders = load_cert_insiders(answers_csv) if answers_csv else {}
    out = []
    for (user, start), b in sorted(bins.items(), key=lambda kv: kv[0][1]):
        malicious = any(s <= start <= e for s, e in insiders.get(user, []))
        out.append(CertWindow(user, start, SessionWindow(
            records_opened=b["files"],
            distinct_record_types=len(b["exts"]),
            exports=b["exports"],
            prints=0,
            unusual_app_requests=b["new_domains"],
            request_rate_ratio=b["events"] / medians[user],
        ), malicious))
    return out
