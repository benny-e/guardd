from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Union


EVENT_SCHEMA_VERSION = 1


@dataclass(slots=True, frozen=True)
class ExecEvent:
    ts_ms: int
    type: Literal["exec"]
    pid: int
    ppid: int
    uid: int
    comm: str
    file: str


@dataclass(slots=True, frozen=True)
class NetEvent:
    ts_ms: int
    type: Literal["net"]
    pid: int
    uid: int
    comm: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int


@dataclass(slots=True, frozen=True)
class StatsEvent:
    ts_ms: int
    type: Literal["stats"]
    exec_emit_ok: int
    exec_ringbuf_drop: int
    net_emit_ok: int
    net_ringbuf_drop: int


GuardEvent = Union[ExecEvent, NetEvent, StatsEvent]
