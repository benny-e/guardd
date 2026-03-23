from __future__ import annotations

from dataclasses import dataclass

from guard.pipeline.aggregator import WindowState
from guard.pipeline.baseline import BaselineState


FEATURE_VERSION = 2

FEATURE_NAMES = [
    "exec_count",
    "net_count",
    "unique_uid_count",
    "unique_comm_count",
    "unique_file_count",
    "unique_parent_child_count",
    "unique_dst_ip_count",
    "unique_dst_port_count",
    "exec_to_net_ratio",
    "ringbuf_drop_total",
    "new_comm_count",
    "new_file_count",
]


@dataclass(slots=True, frozen=True)
class FeatureVector:
    feature_version: int
    window_start_ms: int
    values: list[float]
    metadata: dict[str, object]


def vectorize_window(
    window: WindowState,
    *,
    baseline: BaselineState | None = None,
) -> FeatureVector:
    if window.net_count > 0:
        exec_to_net_ratio = float(window.exec_count) / float(window.net_count)
    else:
        exec_to_net_ratio = float(window.exec_count)

    ringbuf_drop_total = float(
        window.stats_exec_ringbuf_drop + window.stats_net_ringbuf_drop
    )

    if baseline is None:
        new_comms: list[str] = []
        new_files: list[str] = []
    else:
        new_comms = baseline.new_comms(window)
        new_files = baseline.new_files(window)

    values = [
        float(window.exec_count),
        float(window.net_count),
        float(len(window.unique_uids)),
        float(len(window.unique_comms)),
        float(len(window.unique_files)),
        float(len(window.unique_parent_child)),
        float(len(window.unique_dst_ips)),
        float(len(window.unique_dst_ports)),
        float(exec_to_net_ratio),
        ringbuf_drop_total,
        float(len(new_comms)),
        float(len(new_files)),
    ]

    metadata = {
        "unique_comms": sorted(window.unique_comms),
        "unique_files": sorted(window.unique_files),
        "unique_dst_ips": sorted(window.unique_dst_ips),
        "unique_dst_ports": sorted(window.unique_dst_ports),
        "new_comms": new_comms,
        "new_files": new_files,
    }

    return FeatureVector(
        feature_version=FEATURE_VERSION,
        window_start_ms=window.window_start_ms,
        values=values,
        metadata=metadata,
    )
