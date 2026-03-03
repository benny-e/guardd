# Linux Behavioral Guard – Next Steps

## Completed (Kernel Layer)

- Exec sensor (sched_process_exec)
  - pid, ppid, uid, comm, filename
- IPv4 TCP connect sensor (inet_sock_set_state)
  - pid, uid, comm, src/dst IP, dst port
- Unified C daemon (guardd)
  - Loads both sensors
  - Clean shutdown
  - Human-readable output
  - JSONL output mode (--json)

The kernel telemetry layer is complete for v1.

---

## Phase 2 – Python Ingestion Layer

1. Build Python daemon
   - Spawn: sudo ./ebpf/guardd --json
   - Read JSONL stream
   - Parse into structured Python event objects
   - Route by event type (exec / net)

Goal: Clean ingestion pipeline working end-to-end.

---

## Phase 3 – Window Aggregation (Core Behavior Engine)

Implement 60-second rolling windows.

For each window:
- exec_count
- net_count
- unique_binaries
- unique_parent_child_pairs
- unique_dst_ips
- unique_dst_ports
- per-user counts

Output:
- Fixed-length feature vector (versioned)

---

## Phase 4 – Feature Storage

- Store per-window vectors (SQLite or Parquet)
- Store metadata (window start/end timestamps)
- Maintain feature schema version

---

## Phase 5 – Model Training

- IsolationForest (scikit-learn)
- Train on last N hours/days
- Compute anomaly threshold (percentile-based)
- Save atomic model bundle:
  - model
  - threshold
  - feature schema version
  - baseline snapshot

---

## Phase 6 – Detection Mode

- Score each new window
- If anomalous:
  - Emit structured anomaly record
  - Include explainability:
    - new binary
    - new port
    - rare parent-child
    - spike in activity

Output:
- anomalies.jsonl

---

## Phase 7 – Systemd Packaging

- guard.service (detect daemon)
- guard-train.service
- guard-train.timer

---

## Long-Term Enhancements (Optional)

- IPv6 support
- File open/write telemetry
- Hash executable instead of storing full path (privacy mode)
- Unix socket output instead of stdout
- Hot model reload
- Baseline warmup mode

