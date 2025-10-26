"""The security-event schema — the common record every log source normalizes to.

A realistic SOC ingests heterogeneous logs (auth, process, network) and
normalizes them to a common event model before detection. This is that model.
"""

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel


class EventType(StrEnum):
    AUTH = "auth"  # login attempt (success/failure)
    PROCESS = "process"  # process creation
    NETWORK = "network"  # network connection


class Event(BaseModel):
    ts: datetime
    event_type: EventType
    host: str
    user: str
    source_ip: str = ""
    # auth
    action: str = ""  # "login_success" | "login_failure" | "logout"
    # process
    process: str = ""
    command_line: str = ""
    parent_process: str = ""
    # network
    dest_ip: str = ""
    dest_port: int = 0
    bytes_out: int = 0
    # ground-truth label (present only in generated data; detectors must NOT read it)
    scenario: str = ""  # "" for benign; scenario name for attack events
    technique_id: str = ""  # the ATT&CK technique this malicious event belongs to
