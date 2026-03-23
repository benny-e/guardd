from __future__ import annotations

import argparse
import json
import logging
import time
from pathlib import Path

from guard.ebpf.reader import GuardReaderError, GuarddProcessReader, event_to_dict
from guard.model.infer import ModelInferer
from guard.pipeline.aggregator import HostAggregator
from guard.pipeline.features import vectorize_window
from guard.storage.feature_store import FeatureStore

LOG = logging.getLogger(__name__)

def _severity_from_score(score: float, threshold_score: float) -> str:
    delta = threshold_score - score

    if delta >= 0.20:
        return "high"
    if delta >= 0.10:
        return "medium"
    return "low"


def _anomaly_summary(result) -> dict:
    values = result.values

    return {
        "exec_count": values[0],
        "net_count": values[1],
        "unique_uid_count": values[2],
        "unique_comm_count": values[3],
        "unique_file_count": values[4],
        "unique_parent_child_count": values[5],
        "unique_dst_ip_count": values[6],
        "unique_dst_port_count": values[7],
        "exec_to_net_ratio": values[8],
        "ringbuf_drop_total": values[9],
    }


def _anomaly_record(result) -> dict:
    return {
        "type": "anomaly",
        "ts_ms": int(time.time() * 1000),
        "window_start_ms": result.window_start_ms,
        "feature_version": result.feature_version,
        "score": result.score,
        "threshold_score": result.threshold_score,
        "severity": _severity_from_score(result.score, result.threshold_score),
        "summary": _anomaly_summary(result),
        "metadata": result.metadata,
    }

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="guard")
    sub = parser.add_subparsers(dest="command", required=True)

    ingest = sub.add_parser("ingest", help="read live events from guardd")
    ingest.add_argument(
        "--guardd-path",
        default="./ebpf/guardd",
        help="path to compiled guardd binary",
    )
    ingest.add_argument(
        "--pretty",
        action="store_true",
        help="pretty-print parsed events",
    )
    ingest.add_argument(
        "--debug",
        action="store_true",
        help="enable debug logging",
    )
    ingest.add_argument(
        "--print-windows",
        action="store_true",
        help="print completed window summaries",
    )
    ingest.add_argument(
        "--print-features",
        action="store_true",
        help="print feature vectors for completed windows",
    )

    collect = sub.add_parser("collect", help="collect live features into SQLite")
    collect.add_argument(
        "--guardd-path",
        default="./ebpf/guardd",
        help="path to compiled guardd binary",
    )
    collect.add_argument(
        "--db-path",
        default="data/features.db",
        help="path to SQLite feature store",
    )
    collect.add_argument(
        "--debug",
        action="store_true",
        help="enable debug logging",
    )
    collect.add_argument(
        "--print-windows",
        action="store_true",
        help="print completed window summaries while collecting",
    )
    collect.add_argument(
        "--print-features",
        action="store_true",
        help="print feature vectors while collecting",
    )

    detect = sub.add_parser("detect", help="score live windows against trained model")
    detect.add_argument(
        "--guardd-path",
        default="./ebpf/guardd",
        help="path to compiled guardd binary",
    )
    detect.add_argument(
        "--db-path",
        default="data/features.db",
        help="path to SQLite feature store",
    )
    detect.add_argument(
        "--model-path",
        default="data/model.bundle",
        help="path to trained model bundle",
    )
    detect.add_argument(
        "--debug",
        action="store_true",
        help="enable debug logging",
    )
    detect.add_argument(
        "--print-windows",
        action="store_true",
        help="print completed window summaries while detecting",
    )
    detect.add_argument(
        "--print-features",
        action="store_true",
        help="print feature vectors while detecting",
    )
    detect.add_argument(
        "--print-all-scores",
        action="store_true",
        help="print every scored window, not just anomalies",
    )
    detect.add_argument(
        "--no-store",
        action="store_true",
        help="do not write scored feature vectors to SQLite",
    )

    return parser


def _window_summary(window) -> dict:
    return {
        "type": "window",
        "window_start_ms": window.window_start_ms,
        "exec_count": window.exec_count,
        "net_count": window.net_count,
        "unique_uids": len(window.unique_uids),
        "unique_comms": len(window.unique_comms),
        "unique_files": len(window.unique_files),
        "unique_parent_child": len(window.unique_parent_child),
        "unique_dst_ips": len(window.unique_dst_ips),
        "unique_dst_ports": len(window.unique_dst_ports),
        "exec_emit_ok": window.stats_exec_emit_ok,
        "exec_ringbuf_drop": window.stats_exec_ringbuf_drop,
        "net_emit_ok": window.stats_net_emit_ok,
        "net_ringbuf_drop": window.stats_net_ringbuf_drop,
    }


def _feature_summary(vector) -> dict:
    return {
        "type": "features",
        "feature_version": vector.feature_version,
        "window_start_ms": vector.window_start_ms,
        "values": vector.values,
        "metadata": vector.metadata,
    }


def _inference_summary(result) -> dict:
    return {
        "type": "anomaly" if result.is_anomaly else "score",
        "window_start_ms": result.window_start_ms,
        "feature_version": result.feature_version,
        "score": result.score,
        "threshold_score": result.threshold_score,
        "is_anomaly": result.is_anomaly,
        "values": result.values,
        "metadata": result.metadata,
    }


def cmd_ingest(args: argparse.Namespace) -> int:
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    reader = GuarddProcessReader(Path(args.guardd_path))
    agg = HostAggregator()

    try:
        for event in reader.iter_events():
            if args.pretty:
                print(json.dumps(event_to_dict(event), indent=2, sort_keys=True))
            else:
                print(json.dumps(event_to_dict(event), separators=(",", ":"), sort_keys=True))

            completed = agg.push(event)
            if args.print_windows:
                for window in completed:
                    print(json.dumps(_window_summary(window), sort_keys=True))
                    if args.print_features:
                        print(json.dumps(_feature_summary(vectorize_window(window)), sort_keys=True))
    except KeyboardInterrupt:
        LOG.info("stopping ingestion")
        reader.stop()

        if args.print_windows:
            for window in agg.flush():
                print(json.dumps(_window_summary(window), sort_keys=True))
                if args.print_features:
                    print(json.dumps(_feature_summary(vectorize_window(window)), sort_keys=True))

        return 0
    except GuardReaderError as exc:
        LOG.error("ingestion failed: %s", exc)
        reader.stop()
        return 1

    return 0


def cmd_collect(args: argparse.Namespace) -> int:
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    reader = GuarddProcessReader(Path(args.guardd_path))
    agg = HostAggregator()
    store = FeatureStore(Path(args.db_path))
    store.init_db()

    LOG.info("collecting features into %s", args.db_path)

    try:
        for event in reader.iter_events():
            completed = agg.push(event)

            for window in completed:
                vector = vectorize_window(window)
                store.insert_feature_vector(vector)

                if args.print_windows:
                    print(json.dumps(_window_summary(window), sort_keys=True))
                if args.print_features:
                    print(json.dumps(_feature_summary(vector), sort_keys=True))

    except KeyboardInterrupt:
        LOG.info("stopping collection")
        reader.stop()

    except GuardReaderError as exc:
        LOG.error("collection failed: %s", exc)
        reader.stop()
        return 1

    finally:
        for window in agg.flush():
            vector = vectorize_window(window)
            store.insert_feature_vector(vector)

            if args.print_windows:
                print(json.dumps(_window_summary(window), sort_keys=True))
            if args.print_features:
                print(json.dumps(_feature_summary(vector), sort_keys=True))

    return 0


def cmd_detect(args: argparse.Namespace) -> int:
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    reader = GuarddProcessReader(Path(args.guardd_path))
    agg = HostAggregator()
    inferer = ModelInferer(Path(args.model_path))

    store = None
    if not args.no_store:
        store = FeatureStore(Path(args.db_path))
        store.init_db()

    LOG.info("detecting with model %s", args.model_path)

    try:
        for event in reader.iter_events():
            completed = agg.push(event)

            for window in completed:
                vector = vectorize_window(window)

                if store is not None:
                    store.insert_feature_vector(vector)

                if args.print_windows:
                    print(json.dumps(_window_summary(window), sort_keys=True))
                if args.print_features:
                    print(json.dumps(_feature_summary(vector), sort_keys=True))

                result = inferer.score_feature_vector(vector)

                if result.is_anomaly:
                    print(json.dumps(_anomaly_record(result), sort_keys=True))
                elif args.print_all_scores:
                    print(json.dumps(_inference_summary(result), sort_keys=True))

    except KeyboardInterrupt:
        LOG.info("stopping detection")
        reader.stop()

    except GuardReaderError as exc:
        LOG.error("detection failed: %s", exc)
        reader.stop()
        return 1

    finally:
        for window in agg.flush():
            vector = vectorize_window(window)

            if store is not None:
                store.insert_feature_vector(vector)

            if args.print_windows:
                print(json.dumps(_window_summary(window), sort_keys=True))
            if args.print_features:
                print(json.dumps(_feature_summary(vector), sort_keys=True))

            result = inferer.score_feature_vector(vector)

            if result.is_anomaly:
                print(json.dumps(_anomaly_record(result), sort_keys=True))
            elif args.print_all_scores:
                print(json.dumps(_inference_summary(result), sort_keys=True)) 

    return 0


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "ingest":
        return cmd_ingest(args)

    if args.command == "collect":
        return cmd_collect(args)

    if args.command == "detect":
        return cmd_detect(args)

    parser.error("unknown command")
    return 2
