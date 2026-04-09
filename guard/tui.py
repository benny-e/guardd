from __future__ import annotations

import curses
import os
import subprocess
import time
from datetime import datetime
from pathlib import Path
from textwrap import wrap

from guard.storage.anomaly_store import AnomalyStore


AUTO_REFRESH_SECONDS = 2.0


def _fmt_ts(ts_ms: int) -> str:
    return datetime.fromtimestamp(ts_ms / 1000).strftime("%Y-%m-%d %H:%M:%S")


def _short_ts(ts_ms: int) -> str:
    return datetime.fromtimestamp(ts_ms / 1000).strftime("%m-%d %H:%M")


def _truncate(text: str, width: int) -> str:
    if width <= 0:
        return ""
    if len(text) <= width:
        return text
    if width <= 3:
        return text[:width]
    return text[: width - 3] + "..."


def _severity_label(severity: str) -> str:
    return severity.upper()


def _severity_attr(severity: str) -> int:
    sev = severity.lower()
    if sev == "high":
        return curses.color_pair(1)
    if sev == "medium":
        return curses.color_pair(2)
    if sev == "low":
        return curses.color_pair(3)
    return curses.color_pair(4)


def _first_reason(row: dict) -> str:
    reasons = row.get("reasons", [])
    if reasons:
        return str(reasons[0])
    return "No explanation available"


def _summary_lines(summary: dict) -> list[str]:
    preferred_keys = [
        "exec_count",
        "net_count",
        "unique_comm_count",
        "unique_file_count",
        "unique_parent_child_count",
        "unique_dst_ip_count",
        "unique_dst_port_count",
        "new_comm_count",
        "new_file_count",
        "new_parent_child_counts",
        "new_parent_child_ratio",
        "exec_to_net_ratio",
        "ringbuf_drop_total",
    ]

    lines: list[str] = []
    for key in preferred_keys:
        if key not in summary:
            continue

        value = summary[key]
        if isinstance(value, float):
            if key.endswith("_ratio") or key in {"exec_to_net_ratio"}:
                rendered = f"{value:.3f}"
            else:
                rendered = f"{value:.2f}"
        else:
            rendered = str(value)

        lines.append(f"- {key}: {rendered}")

    return lines


def _metadata_lines(metadata: dict) -> list[str]:
    lines: list[str] = []

    for key in ("new_comms", "new_files", "unique_dst_ips", "unique_dst_ports"):
        values = metadata.get(key, [])
        if not values:
            continue

        preview = ", ".join(str(v) for v in values[:4])
        if len(values) > 4:
            preview += ", ..."
        lines.append(f"- {key}: {preview}")

    parent_child = metadata.get("new_parent_child", [])
    if parent_child:
        preview_items = []
        for item in parent_child[:3]:
            if isinstance(item, dict):
                preview_items.append(f"({item.get('ppid')} -> {item.get('comm')})")
            else:
                preview_items.append(str(item))
        preview = ", ".join(preview_items)
        if len(parent_child) > 3:
            preview += ", ..."
        lines.append(f"- new_parent_child: {preview}")

    return lines


def _relative_age(ts_ms: int | None) -> str:
    if ts_ms is None:
        return "none"

    delta_s = max(0, int(time.time() - (ts_ms / 1000)))
    if delta_s < 60:
        return f"{delta_s}s ago"
    if delta_s < 3600:
        return f"{delta_s // 60}m ago"
    if delta_s < 86400:
        return f"{delta_s // 3600}h ago"
    return f"{delta_s // 86400}d ago"


def _format_mib(value_bytes: int | None) -> str:
    if value_bytes is None:
        return "n/a"
    return f"{value_bytes / (1024 * 1024):.1f} MiB"


class GuarddStats:
    def __init__(self, service_name: str = "guardd.service") -> None:
        self.service_name = service_name
        self._last_pid: int | None = None
        self._last_proc_time: float | None = None
        self._last_wall_time: float | None = None
        self._clk_tck = os.sysconf(os.sysconf_names["SC_CLK_TCK"])

    def sample(self) -> dict[str, object]:
        pid = self._get_main_pid()
        if pid is None:
            self._reset_cpu_tracking()
            return {
                "pid": None,
                "state": "inactive",
                "cpu_percent": None,
                "rss_bytes": None,
            }

        state = self._read_proc_state(pid)
        rss_bytes = self._read_rss_bytes(pid)
        cpu_percent = self._sample_cpu_percent(pid)

        return {
            "pid": pid,
            "state": state,
            "cpu_percent": cpu_percent,
            "rss_bytes": rss_bytes,
        }

    def _reset_cpu_tracking(self) -> None:
        self._last_pid = None
        self._last_proc_time = None
        self._last_wall_time = None

    def _get_main_pid(self) -> int | None:
        try:
            result = subprocess.run(
                ["systemctl", "show", "-p", "MainPID", "--value", self.service_name],
                capture_output=True,
                text=True,
                check=False,
            )
        except Exception:
            return None

        if result.returncode != 0:
            return None

        text = result.stdout.strip()
        if not text or text == "0":
            return None

        try:
            pid = int(text)
        except ValueError:
            return None

        return pid if pid > 0 else None

    def _read_proc_state(self, pid: int) -> str:
        try:
            with Path(f"/proc/{pid}/status").open("r", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("State:"):
                        parts = line.split()
                        if len(parts) >= 2:
                            return parts[1]
                        break
        except Exception:
            return "unknown"
        return "unknown"

    def _read_rss_bytes(self, pid: int) -> int | None:
        try:
            with Path(f"/proc/{pid}/status").open("r", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("VmRSS:"):
                        parts = line.split()
                        if len(parts) >= 2:
                            return int(parts[1]) * 1024
        except Exception:
            return None
        return None

    def _read_total_proc_time_seconds(self, pid: int) -> float | None:
        try:
            with Path(f"/proc/{pid}/stat").open("r", encoding="utf-8") as f:
                data = f.read().strip()
        except Exception:
            return None

        end_comm = data.rfind(")")
        if end_comm == -1:
            return None

        rest = data[end_comm + 2 :].split()
        if len(rest) < 15:
            return None

        try:
            utime_ticks = int(rest[11])
            stime_ticks = int(rest[12])
        except (ValueError, IndexError):
            return None

        return float(utime_ticks + stime_ticks) / float(self._clk_tck)

    def _sample_cpu_percent(self, pid: int) -> float | None:
        now_wall = time.time()
        proc_time = self._read_total_proc_time_seconds(pid)
        if proc_time is None:
            self._reset_cpu_tracking()
            return None

        if self._last_pid != pid:
            self._last_pid = pid
            self._last_proc_time = proc_time
            self._last_wall_time = now_wall
            return None

        if self._last_proc_time is None or self._last_wall_time is None:
            self._last_proc_time = proc_time
            self._last_wall_time = now_wall
            return None

        delta_proc = proc_time - self._last_proc_time
        delta_wall = now_wall - self._last_wall_time

        self._last_proc_time = proc_time
        self._last_wall_time = now_wall

        if delta_wall <= 0:
            return None

        cpu_percent = (delta_proc / delta_wall) * 100.0
        if cpu_percent < 0:
            return 0.0
        return cpu_percent


class AlertTUI:
    def __init__(self, db_path: str | Path, limit: int = 200) -> None:
        self.store = AnomalyStore(db_path)
        self.store.init_db()

        self.limit = limit
        self.search = ""
        self.rows: list[dict] = []
        self.selected = 0
        self.last_refresh_ts = 0.0
        self.guardd_stats = GuarddStats()
        self.system_stats: dict[str, object] = {
            "pid": None,
            "state": "inactive",
            "cpu_percent": None,
            "rss_bytes": None,
        }

    def refresh(self) -> None:
        previous_id = None
        if self.rows and 0 <= self.selected < len(self.rows):
            previous_id = self.rows[self.selected]["id"]

        raw = self.store.list_anomalies(search=self.search or None, limit=self.limit)
        self.rows = [self.store.row_to_dict(r) for r in raw]
        self.system_stats = self.guardd_stats.sample()
        self.last_refresh_ts = time.time()

        if not self.rows:
            self.selected = 0
            return

        if previous_id is not None:
            for idx, row in enumerate(self.rows):
                if row["id"] == previous_id:
                    self.selected = idx
                    break
            else:
                self.selected = min(self.selected, len(self.rows) - 1)
        else:
            self.selected = min(self.selected, len(self.rows) - 1)

    def refresh_if_needed(self) -> None:
        if (time.time() - self.last_refresh_ts) >= AUTO_REFRESH_SECONDS:
            self.refresh()

    def reset_home(self) -> None:
        self.search = ""
        self.selected = 0
        self.refresh()

    def _counts(self) -> tuple[int, int, int]:
        high = sum(1 for row in self.rows if str(row.get("severity", "")).lower() == "high")
        medium = sum(1 for row in self.rows if str(row.get("severity", "")).lower() == "medium")
        low = sum(1 for row in self.rows if str(row.get("severity", "")).lower() == "low")
        return high, medium, low

    def run(self) -> None:
        curses.wrapper(self._main)

    def _main(self, stdscr) -> None:
        curses.curs_set(0)
        stdscr.keypad(True)
        curses.use_default_colors()
        stdscr.timeout(250)

        if curses.has_colors():
            curses.start_color()
            curses.init_pair(1, curses.COLOR_RED, -1)
            curses.init_pair(2, curses.COLOR_YELLOW, -1)
            curses.init_pair(3, curses.COLOR_CYAN, -1)
            curses.init_pair(4, curses.COLOR_WHITE, -1)

        self.refresh()

        while True:
            self.refresh_if_needed()

            stdscr.erase()
            h, w = stdscr.getmaxyx()

            left_w = max(38, min(56, int(w * 0.40)))
            right_x = left_w + 2
            right_w = max(20, w - right_x - 1)

            header = "GUARDD TUI  |  q quit  / search  r reset  auto-refresh on"
            stdscr.addnstr(0, 0, _truncate(header, w - 1), w - 1, curses.A_BOLD)

            if self.search:
                status = f"Search: {self.search}"
            else:
                status = f"Recent anomalies ({len(self.rows)})"

            stdscr.addnstr(1, 0, _truncate(status, w - 1), w - 1)
            stdscr.hline(2, 0, ord("-"), w)

            stdscr.addnstr(3, 0, _truncate("Recent Anomalies", left_w - 1), left_w - 1, curses.A_BOLD)
            stdscr.addnstr(3, right_x, _truncate("Anomaly Details", right_w), right_w, curses.A_BOLD)

            list_start_y = 4
            stats_h = 8
            list_h = max(1, h - list_start_y - stats_h - 1)
            detail_start_y = 4

            visible_rows = self.rows[:list_h]

            for idx, row in enumerate(visible_rows):
                y = list_start_y + idx
                selected = idx == self.selected
                color = _severity_attr(row["severity"])
                attr = (curses.A_REVERSE | color) if selected else color

                prefix = ">" if selected else " "
                sev = _severity_label(str(row["severity"]))
                ts = _short_ts(int(row["ts_ms"]))
                score = f"{float(row['score']):.3f}"
                reason = _first_reason(row)

                line = f"{prefix} {ts}  {sev:<6} {score:>7}  {reason}"
                stdscr.addnstr(y, 0, _truncate(line, left_w - 1), left_w - 1, attr)

            stats_y = list_start_y + list_h + 1
            if stats_y < h - 1:
                stdscr.hline(stats_y - 1, 0, ord("-"), left_w)

                high, medium, low = self._counts()
                latest_ts = self.rows[0]["ts_ms"] if self.rows else None
                selected_text = "none"
                if self.rows and 0 <= self.selected < len(self.rows):
                    selected_text = str(self.rows[self.selected]["id"])

                pid = self.system_stats.get("pid")
                state = str(self.system_stats.get("state", "unknown"))
                cpu_percent = self.system_stats.get("cpu_percent")
                rss_bytes = self.system_stats.get("rss_bytes")

                cpu_text = "n/a" if cpu_percent is None else f"{float(cpu_percent):.1f}%"
                pid_text = "n/a" if pid is None else str(pid)

                stats_lines = [
                    "Guard System Usage:",
                    f"  CPU: {cpu_text}",
                    f"  RAM: {_format_mib(rss_bytes if isinstance(rss_bytes, int) else None)}",
                    f"Loaded: {len(self.rows)} / {self.limit}",
                    f"Latest anomaly: {_relative_age(latest_ts)}",
                    f"H:{high}  M:{medium}  L:{low}  Sel:{selected_text}",
                ]

                for i, line in enumerate(stats_lines):
                    y = stats_y + i
                    if y >= h - 1:
                        break
                    stdscr.addnstr(y, 0, _truncate(line, left_w - 1), left_w - 1)

            if self.rows and 0 <= self.selected < len(self.rows):
                row = self.rows[self.selected]
                detail_lines: list[str | tuple[str, str]] = [
                    f"Anomaly ID: {row['id']}",
                    f"Time: {_fmt_ts(row['ts_ms'])}",
                    f"Window: {_fmt_ts(row['window_start_ms'])}",
                    ("Severity: ", str(row["severity"])),
                    f"Score: {row['score']:.6f}",
                    f"Threshold: {row['threshold_score']:.6f}",
                    "",
                    "Reasons:",
                ]

                for reason in row.get("reasons", []):
                    wrapped = wrap(f"- {reason}", width=max(10, right_w - 1))
                    if not wrapped:
                        detail_lines.append("-")
                    else:
                        detail_lines.extend(wrapped)

                summary = row.get("summary", {})
                summary_lines = _summary_lines(summary)
                if summary_lines:
                    detail_lines.append("")
                    detail_lines.append("Summary:")
                    detail_lines.extend(summary_lines)

                metadata = row.get("metadata", {})
                metadata_lines = _metadata_lines(metadata)
                if metadata_lines:
                    detail_lines.append("")
                    detail_lines.append("Metadata:")
                    detail_lines.extend(metadata_lines)

                y = detail_start_y
                for line in detail_lines:
                    if y >= h - 1:
                        break

                    if isinstance(line, tuple):
                        label, value = line
                        stdscr.addnstr(y, right_x, _truncate(label, right_w), right_w)
                        remaining_w = max(0, right_w - len(label))
                        if remaining_w > 0:
                            stdscr.addnstr(
                                y,
                                right_x + len(label),
                                _truncate(value, remaining_w),
                                remaining_w,
                                _severity_attr(value),
                            )
                        y += 1
                        continue

                    wrapped_lines = wrap(line, width=max(10, right_w))
                    if not wrapped_lines:
                        wrapped_lines = [""]

                    for wrapped_line in wrapped_lines:
                        if y >= h - 1:
                            break
                        stdscr.addnstr(y, right_x, _truncate(wrapped_line, right_w), right_w)
                        y += 1
            else:
                msg = "No anomalies found."
                if self.search:
                    msg = f"No anomalies found for search: {self.search}"
                stdscr.addnstr(detail_start_y, right_x, _truncate(msg, right_w), right_w)

            stdscr.refresh()
            ch = stdscr.getch()

            if ch == -1:
                continue
            if ch in (ord("q"), 27):
                break
            elif ch in (curses.KEY_DOWN, ord("j")):
                if self.selected < max(0, len(self.rows) - 1):
                    self.selected += 1
            elif ch in (curses.KEY_UP, ord("k")):
                if self.selected > 0:
                    self.selected -= 1
            elif ch == ord("r"):
                self.reset_home()
            elif ch == ord("/"):
                new_search = self._prompt(stdscr, "Search")
                self.search = new_search
                self.selected = 0
                self.refresh()

    def _prompt(self, stdscr, label: str) -> str:
        curses.curs_set(1)
        h, w = stdscr.getmaxyx()
        value = self.search

        while True:
            stdscr.move(h - 1, 0)
            stdscr.clrtoeol()
            stdscr.addnstr(h - 1, 0, _truncate(f"{label}: {value}", w - 1), w - 1)
            stdscr.refresh()

            ch = stdscr.getch()

            if ch in (10, 13):
                curses.curs_set(0)
                return value.strip()
            if ch in (27,):
                curses.curs_set(0)
                return self.search
            if ch in (curses.KEY_BACKSPACE, 127, 8):
                value = value[:-1]
                continue
            if 32 <= ch <= 126:
                value += chr(ch)


def run_tui(db_path: str | Path, *, limit: int = 200) -> int:
    app = AlertTUI(db_path=db_path, limit=limit)
    app.run()
    return 0

