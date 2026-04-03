from __future__ import annotations

from typing import Any

def explain_anomaly(result) -> list[str]:
    reasons: list[str] = []

    metadata = result.metadata
    values = result.values

    exec_count = values[0]
    net_count = values[1]
    unique_comm_count = values[3]
    unique_file_count = values[4]
    unique_dst_ip_count = values[6]
    unique_dst_port_count = values[7]
    ringbuf_drop_total = values[9]

    new_comms = metadata.get("new_comms", [])
    new_files = metadata.get("new_files", [])

    if new_comms:
        reasons.append(
            f"new process names observed: {', '.join(str(x) for x in new_comms[:3])}"
        )

    if new_files:
        reasons.append(
            f"new executable paths observed: {', '.join(str(x) for x in new_files[:3])}"
        )

    if net_count >= 20:
        reasons.append(f"spike in outbound connections: {int(net_count)} events")

    if unique_dst_ip_count >= 10:
        reasons.append(
            f"high destination IP diversity: {int(unique_dst_ip_count)} unique IPs"
        )

    if unique_dst_port_count >= 10:
        reasons.append(
            f"high destination port diversity: {int(unique_dst_port_count)} unique ports"
        )

    if exec_count >= 40:
        reasons.append(f"spike in process executions: {int(exec_count)} exec events")

    if unique_file_count >= 15:
        reasons.append(
            f"high executable path diversity: {int(unique_file_count)} unique files"
        )

    if ringbuf_drop_total > 0:
        reasons.append(
            f"telemetry drops detected: {int(ringbuf_drop_total)} dropped ring buffer events"
        )

    if not reasons:
        reasons.append("window score was below anomaly threshold based on aggregate behavior")

    return reasons
