from __future__ import annotations

import curses
from datetime import datetime
from pathlib import Path
from textwrap import wrap

from guard.storage.anomaly_store import AnomalyStore


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


class AlertTUI:
    def __init__(self, db_path: str | Path, limit: int = 200) -> None:
        self.store = AnomalyStore(db_path)
        self.store.init_db()

        self.limit = limit
        self.search = ""
        self.rows: list[dict] = []
        self.selected = 0

    def refresh(self) -> None:
        raw = self.store.list_anomalies(search=self.search or None, limit=self.limit)
        self.rows = [self.store.row_to_dict(r) for r in raw]

        if not self.rows:
            self.selected = 0
        else:
            self.selected = max(0, min(self.selected, len(self.rows) - 1))

    def reset_home(self) -> None:
        self.search = ""
        self.selected = 0
        self.refresh()

    def run(self) -> None:
        curses.wrapper(self._main)

    def _main(self, stdscr) -> None:
        curses.curs_set(0)
        stdscr.keypad(True)
        curses.use_default_colors()

        if curses.has_colors():
            curses.start_color()
            curses.init_pair(1, curses.COLOR_RED, -1)
            curses.init_pair(2, curses.COLOR_YELLOW, -1)
            curses.init_pair(3, curses.COLOR_CYAN, -1)
            curses.init_pair(4, curses.COLOR_WHITE, -1)

        self.refresh()

        while True:
            stdscr.erase()
            h, w = stdscr.getmaxyx()

            left_w = max(36, min(52, int(w * 0.38)))
            right_x = left_w + 2
            right_w = max(20, w - right_x - 1)

            header = "GUARD Alerts  |  q quit  / search  r home+refresh"
            stdscr.addnstr(0, 0, _truncate(header, w - 1), w - 1, curses.A_BOLD)

            if self.search:
                status = f"Search: {self.search}"
            else:
                total = len(self.rows)
                status = f"Newest alerts ({total})"

            stdscr.addnstr(1, 0, _truncate(status, w - 1), w - 1)
            stdscr.hline(2, 0, ord("-"), w)

            stdscr.addnstr(3, 0, _truncate("Recent Alerts", left_w - 1), left_w - 1, curses.A_BOLD)
            stdscr.addnstr(3, right_x, _truncate("Alert Details", right_w), right_w, curses.A_BOLD)

            list_start_y = 4
            detail_start_y = 4
            content_h = h - list_start_y - 1

            for idx, row in enumerate(self.rows[:content_h]):
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

            if self.rows:
                row = self.rows[self.selected]
                detail_lines: list[str | tuple[str, str]] = [
                    f"Alert ID: {row['id']}",
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
                msg = "No alerts found."
                if self.search:
                    msg = f"No alerts found for search: {self.search}"
                stdscr.addnstr(detail_start_y, right_x, _truncate(msg, right_w), right_w)

            stdscr.refresh()
            ch = stdscr.getch()

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
