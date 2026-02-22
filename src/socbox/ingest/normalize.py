from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Optional

from dateutil import parser as dtparser


def _get(d: Dict[str, Any], path: str) -> Optional[Any]:
    """
    Safe dotted-path getter.
    Example: _get(event, "winlog.event_data.TargetUserName")
    """
    cur: Any = d
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _as_iso(ts: Any) -> Optional[str]:
    if ts is None:
        return None
    if isinstance(ts, str):
        ts = ts.strip()
        if not ts:
            return None
        try:
            # handles many timestamp formats
            dt = dtparser.parse(ts)
            return dt.isoformat()
        except Exception:
            return None
    if isinstance(ts, (int, float)):
        try:
            return datetime.utcfromtimestamp(ts).isoformat() + "Z"
        except Exception:
            return None
    return None


@dataclass(frozen=True)
class NormalizedEvent:
    timestamp: str
    dataset: str
    category: str
    action: Optional[str]
    outcome: Optional[str]
    host_name: Optional[str]
    user_name: Optional[str]
    source_ip: Optional[str]
    destination_ip: Optional[str]
    process_name: Optional[str]
    process_cmd: Optional[str]
    message: Optional[str]
    raw: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "@timestamp": self.timestamp,
            "event.dataset": self.dataset,
            "event.category": self.category,
            "event.action": self.action,
            "event.outcome": self.outcome,
            "host.name": self.host_name,
            "user.name": self.user_name,
            "source.ip": self.source_ip,
            "destination.ip": self.destination_ip,
            "process.name": self.process_name,
            "process.command_line": self.process_cmd,
            "message": self.message,
            "raw": self.raw,  # keep for traceability
        }


def normalize_mordor_event(event: Dict[str, Any], dataset_name: str = "mordor") -> Optional[NormalizedEvent]:
    """
    Mordor datasets vary (Sysmon, Security logs, etc.). We normalize conservatively:
    - find a timestamp from common keys
    - infer broad category from event/source fields
    - extract some common user/host/process/ip fields when present
    """
    ts = (
        _as_iso(_get(event, "@timestamp"))
        or _as_iso(_get(event, "Timestamp"))
        or _as_iso(_get(event, "timestamp"))
        or _as_iso(_get(event, "winlog.time_created"))
        or _as_iso(_get(event, "TimeCreated"))
        or _as_iso(_get(event, "UtcTime"))
        or _as_iso(_get(event, "EventTime"))
        or _as_iso(_get(event, "EventReceivedTime"))
    )
    if not ts:
        return None

    # crude category inference
    provider = str(_get(event, "winlog.provider_name") or _get(event, "Channel") or _get(event, "source") or "").lower()
    event_id = _get(event, "winlog.event_id") or _get(event, "EventID")

    category = "other"
    if "security" in provider or str(event_id) in {"4624", "4625", "4768", "4769"}:
        category = "auth"
    elif "sysmon" in provider or str(event_id) in {"1", "4688"}:
        category = "process"
    elif "dns" in provider:
        category = "dns"
    elif "proxy" in provider or "http" in provider or "web" in provider:
        category = "web"
    elif "network" in provider:
        category = "network"

    # common fields (best-effort)
    host = (
        _get(event, "host.name")
        or _get(event, "Computer")
        or _get(event, "winlog.computer_name")
        or _get(event, "Hostname")  # <-- Sysmon-style in Security-Datasets exports
    )

    user = (
        _get(event, "user.name")
        or _get(event, "winlog.event_data.TargetUserName")
        or _get(event, "winlog.event_data.SubjectUserName")
        or _get(event, "TargetUserName")
        or _get(event, "SubjectUserName")
        or _get(event, "AccountName")  # <-- Sysmon-style exports
    )

    # combine Domain + AccountName if present
    domain = _get(event, "Domain")
    if user and domain and "\\" not in str(user):
        user = f"{domain}\\{user}"

    src_ip = (
        _get(event, "source.ip")
        or _get(event, "winlog.event_data.IpAddress")
        or _get(event, "IpAddress")
    )

    dst_ip = (
        _get(event, "destination.ip")
        or _get(event, "winlog.event_data.DestinationIp")
        or _get(event, "DestinationIp")
    )

    proc_name = (
        _get(event, "process.name")
        or _get(event, "winlog.event_data.Image")
        or _get(event, "Image")
        or _get(event, "ProcessName")
        or _get(event, "SourceImage")  # <-- Sysmon ProcessAccess often has SourceImage/TargetImage
        or _get(event, "TargetImage")
    )

    proc_cmd = (
        _get(event, "process.command_line")
        or _get(event, "winlog.event_data.CommandLine")
        or _get(event, "CommandLine")
    )

    action = str(event_id) if event_id is not None else None
    outcome = None  # we can infer later for specific event IDs
    message = _get(event, "message") or _get(event, "winlog.message")

    return NormalizedEvent(
        timestamp=ts,
        dataset=dataset_name,
        category=category,
        action=action,
        outcome=outcome,
        host_name=str(host) if host is not None else None,
        user_name=str(user) if user is not None else None,
        source_ip=str(src_ip) if src_ip is not None else None,
        destination_ip=str(dst_ip) if dst_ip is not None else None,
        process_name=str(proc_name) if proc_name is not None else None,
        process_cmd=str(proc_cmd) if proc_cmd is not None else None,
        message=str(message) if message is not None else None,
        raw=event,
    )