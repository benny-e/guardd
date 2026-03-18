from __future__ import annotations

import json
import logging
import subprocess
from collections.abc import Generator, Iterable
from dataclasses import asdict
from pathlib import Path

from guard.ebpf.schema import ExecEvent, GuardEvent, NetEvent, StatsEvent

LOG = logging.getLogger(__name__)


class GuardReaderError(Exception):
    pass


def parse_event_obj(obj: dict) -> GuardEvent:
    kind = obj.get("type")

    if kind == "exec":
        return ExecEvent(
            ts_ms=int(obj["ts_ms"]),
            type="exec",
            pid=int(obj["pid"]),
            ppid=int(obj["ppid"]),
            uid=int(obj["uid"]),
            comm=str(obj["comm"]),
            file=str(obj["file"]),
        )

    if kind == "net":
        return NetEvent(
            ts_ms=int(obj["ts_ms"]),
            type="net",
            pid=int(obj["pid"]),
            uid=int(obj["uid"]),
            comm=str(obj["comm"]),
            src_ip=str(obj["src_ip"]),
            src_port=int(obj["src_port"]),
            dst_ip=str(obj["dst_ip"]),
            dst_port=int(obj["dst_port"]),
        )

    if kind == "stats":
        return StatsEvent(
            ts_ms=int(obj["ts_ms"]),
            type="stats",
            exec_emit_ok=int(obj["exec_emit_ok"]),
            exec_ringbuf_drop=int(obj["exec_ringbuf_drop"]),
            net_emit_ok=int(obj["net_emit_ok"]),
            net_ringbuf_drop=int(obj["net_ringbuf_drop"]),
        )

    raise GuardReaderError(f"unknown event type: {kind!r}")


def parse_event_line(line: str) -> GuardEvent:
    try:
        obj = json.loads(line)
    except json.JSONDecodeError as exc:
        raise GuardReaderError(f"invalid JSON line: {exc}") from exc

    if not isinstance(obj, dict):
        raise GuardReaderError("event line must decode to a JSON object")

    return parse_event_obj(obj)


def event_to_dict(event: GuardEvent) -> dict:
    return asdict(event)


class GuarddProcessReader:
    def __init__(
        self,
        guardd_path: str | Path,
        extra_args: Iterable[str] | None = None,
    ) -> None:
        self.guardd_path = str(guardd_path)
        self.extra_args = list(extra_args or [])
        self.proc: subprocess.Popen[str] | None = None

    def command(self) -> list[str]:
        return [self.guardd_path, "--json", *self.extra_args]

    def start(self) -> None:
        if self.proc is not None:
            raise GuardReaderError("guardd process already started")

        cmd = self.command()
        LOG.info("starting guardd: %s", " ".join(cmd))

        self.proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )

        if self.proc.stdout is None or self.proc.stderr is None:
            raise GuardReaderError("failed to capture guardd stdout/stderr")

    def iter_events(self) -> Generator[GuardEvent, None, None]:
        if self.proc is None:
            self.start()

        assert self.proc is not None
        assert self.proc.stdout is not None

        try:
            for raw_line in self.proc.stdout:
                line = raw_line.strip()
                if not line:
                    continue

                try:
                    yield parse_event_line(line)
                except GuardReaderError as exc:
                    LOG.warning("dropping malformed guardd line: %r (%s)", line, exc)
        finally:
            self.stop()

    def stop(self) -> None:
        if self.proc is None:
            return

        proc = self.proc
        self.proc = None

        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)

        if proc.returncode not in (0, None):
            stderr_text = ""
            if proc.stderr is not None:
                try:
                    stderr_text = proc.stderr.read().strip()
                except Exception:
                    stderr_text = ""
            if stderr_text:
                LOG.warning("guardd exited rc=%s stderr=%s", proc.returncode, stderr_text)
            else:
                LOG.warning("guardd exited rc=%s", proc.returncode)
