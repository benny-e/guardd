from __future__ import annotations

from dataclasses import dataclass, field

from guard.ebpf.schema import ExecEvent, GuardEvent, NetEvent, StatsEvent
from guard.pipeline.clock import floor_window_start


DEFAULT_WINDOW_MS = 60_000


@dataclass(slots=True)
class WindowState:
    window_start_ms: int

    exec_count: int = 0
    net_count: int = 0

    unique_uids: set[int] = field(default_factory=set)
    unique_comms: set[str] = field(default_factory=set)
    unique_files: set[str] = field(default_factory=set)
    unique_parent_child: set[tuple[int, str]] = field(default_factory=set)
    unique_dst_ips: set[str] = field(default_factory=set)
    unique_dst_ports: set[int] = field(default_factory=set)

    stats_exec_emit_ok: int = 0
    stats_exec_ringbuf_drop: int = 0
    stats_net_emit_ok: int = 0
    stats_net_ringbuf_drop: int = 0

    def add(self, event: GuardEvent) -> None:
        if isinstance(event, ExecEvent):
            self.exec_count += 1
            self.unique_uids.add(event.uid)
            self.unique_comms.add(event.comm)
            self.unique_files.add(event.file)
            self.unique_parent_child.add((event.ppid, event.comm))
            return

        if isinstance(event, NetEvent):
            self.net_count += 1
            self.unique_uids.add(event.uid)
            self.unique_comms.add(event.comm)
            self.unique_dst_ips.add(event.dst_ip)
            self.unique_dst_ports.add(event.dst_port)
            return

        if isinstance(event, StatsEvent):
            self.stats_exec_emit_ok = event.exec_emit_ok
            self.stats_exec_ringbuf_drop = event.exec_ringbuf_drop
            self.stats_net_emit_ok = event.net_emit_ok
            self.stats_net_ringbuf_drop = event.net_ringbuf_drop
            return


class HostAggregator:
    def __init__(self, window_ms: int = DEFAULT_WINDOW_MS) -> None:
        self.window_ms = window_ms
        self.current: WindowState | None = None

    def push(self, event: GuardEvent) -> list[WindowState]:
        event_window = floor_window_start(event.ts_ms, self.window_ms)
        emitted: list[WindowState] = []

        if self.current is None:
            self.current = WindowState(window_start_ms=event_window)

        while self.current.window_start_ms < event_window:
            emitted.append(self.current)
            self.current = WindowState(
                window_start_ms=self.current.window_start_ms + self.window_ms
            )

        self.current.add(event)
        return emitted

    def flush(self) -> list[WindowState]:
        if self.current is None:
            return []

        out = [self.current]
        self.current = None
        return out
