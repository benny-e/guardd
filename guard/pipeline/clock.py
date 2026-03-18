from __future__ import annotations


def floor_window_start(ts_ms: int, window_ms: int) -> int:
    return ts_ms - (ts_ms % window_ms)
