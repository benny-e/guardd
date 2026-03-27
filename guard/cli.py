from __future__ import annotations

import argparse
import json
import logging
import time
from collections.abc import Callable
from pathlib import Path

from guard.ebpf.reader import GuardReaderError, GuarddProcessReader, event_to_dict
from guard.model.infer import ModelInferer
from guard.model.train import bundle_summary_json, train_isolation_forest
from guard.pipeline.aggregator import HostAggregator
from guard.pipeline.baseline import BaselineState
from guard.pipeline.features import vectorize_window
from guard.storage.feature_store import FeatureStore

LOG = logging.getLogger(__name__)

BOOTSTRAP_RETRY_SECONDS = 10 * 60
RETRAIN_INTERVAL_SECONDS = 7 * 24 * 60 * 60


def _configure_logging(debug: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if debug else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def _make_store(db_path: str | Path) -> FeatureStore:
    store = FeatureStore(Path(db_path))
    store.init_db()
    return store


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


def _severity_from_score(score: float, threshold_score: float) -> str:
    delta = threshold_score - score
    if delta >= 0.08:
        return "high"
    if delta >= 0.03:
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


def _print_window_and_feature(window, vector, *, print_windows: bool, print_features: bool) -> None:
    if print_windows:
        print(json.dumps(_window_summary(window), sort_keys=True))
    if print_features:
        print(json.dumps(_feature_summary(vector), sort_keys=True))


def _is_not_enough_training_data(exc: ValueError) -> bool:
    return "not enough training rows" in str(exc)


def try_train_model(
    *,
    db_path: str | Path,
    model_out: str | Path,
    limit: int | None = None,
    contamination: float = 0.01,
    n_estimators: int = 200,
    random_state: int = 42,
    threshold_percentile: float = 10.0,
    prune_retention_days: int = 45,
    emit_json: bool = False,
) -> bool:
    """
    Returns True if training succeeded and wrote a model.
    Returns False if training was skipped because there are not enough rows.
    Raises on real failures.
    """
    try:
        result = train_isolation_forest(
            db_path,
            model_out_path=model_out,
            limit=limit,
            contamination=contamination,
            n_estimators=n_estimators,
            random_state=random_state,
            threshold_percentile=threshold_percentile,
        )
    except ValueError as exc:
        if _is_not_enough_training_data(exc):
            LOG.info("training skipped: %s", exc)
            return False
        raise

    cutoff_ms = int(time.time() * 1000) - (prune_retention_days * 24 * 60 * 60 * 1000)
    store = _make_store(db_path)
    deleted_rows = store.delete_rows_older_than(cutoff_ms)

    if emit_json:
        print(json.dumps(result, sort_keys=True))
        print(bundle_summary_json(model_out))

    LOG.info(
        "training succeeded: rows=%s threshold=%s model=%s deleted_old_rows=%s",
        result["rows"],
        result["threshold_score"],
        model_out,
        deleted_rows,
    )
    return True


class ReloadableInferer:
    def __init__(self, model_path: str | Path) -> None:
        self.model_path = Path(model_path)
        self.inferer: ModelInferer | None = None
        self.baseline = BaselineState()
        self.last_mtime_ns: int | None = None
        self.reload()

    def reload(self) -> None:
        inferer = ModelInferer(self.model_path)
        self.inferer = inferer
        self.baseline = BaselineState.from_dict(inferer.bundle["baseline_snapshot"])
        self.last_mtime_ns = self.model_path.stat().st_mtime_ns
        LOG.info("loaded model bundle: %s", self.model_path)

    def maybe_reload(self) -> bool:
        try:
            current_mtime_ns = self.model_path.stat().st_mtime_ns
        except FileNotFoundError:
            LOG.warning("model bundle disappeared during detect loop: %s", self.model_path)
            return False

        if self.last_mtime_ns is None or current_mtime_ns != self.last_mtime_ns:
            self.reload()
            return True

        return False

    def score_feature_vector(self, vector):
        assert self.inferer is not None
        return self.inferer.score_feature_vector(vector)


def run_collect_loop(
    *,
    guardd_path: str | Path,
    db_path: str | Path,
    print_windows: bool = False,
    print_features: bool = False,
    should_stop: Callable[[], bool] | None = None,
) -> int:
    reader = GuarddProcessReader(Path(guardd_path))
    agg = HostAggregator()
    store = _make_store(db_path)
    baseline = BaselineState()

    LOG.info("collecting features into %s", db_path)

    try:
        for event in reader.iter_events():
            completed = agg.push(event)

            for window in completed:
                vector = vectorize_window(window, baseline=baseline)
                store.insert_feature_vector(vector)
                baseline.observe_window(window)
                _print_window_and_feature(
                    window,
                    vector,
                    print_windows=print_windows,
                    print_features=print_features,
                )

                if should_stop is not None and should_stop():
                    LOG.info("stopping collect loop for scheduled daemon action")
                    reader.stop()
                    break

    except KeyboardInterrupt:
        LOG.info("stopping collection")
        reader.stop()

    except GuardReaderError as exc:
        LOG.error("collection failed: %s", exc)
        reader.stop()
        return 1

    finally:
        for window in agg.flush():
            vector = vectorize_window(window, baseline=baseline)
            store.insert_feature_vector(vector)
            baseline.observe_window(window)
            _print_window_and_feature(
                window,
                vector,
                print_windows=print_windows,
                print_features=print_features,
            )

    return 0


def run_detect_loop(
    *,
    guardd_path: str | Path,
    db_path: str | Path,
    model_path: str | Path,
    print_windows: bool = False,
    print_features: bool = False,
    print_all_scores: bool = False,
    no_store: bool = False,
    reload_check_every_windows: int = 5,
    should_stop: Callable[[], bool] | None = None,
) -> int:
    model_path = Path(model_path)

    try:
        reloader = ReloadableInferer(model_path)
    except FileNotFoundError:
        LOG.error("model.bundle not found — run 'guard collect' and 'guard train' first")
        return 1

    reader = GuarddProcessReader(Path(guardd_path))
    agg = HostAggregator()
    store = None if no_store else _make_store(db_path)

    LOG.info("detecting with model %s", model_path)
    completed_window_count = 0

    def process_window(window) -> bool:
        nonlocal completed_window_count

        vector = vectorize_window(window, baseline=reloader.baseline)

        if store is not None:
            store.insert_feature_vector(vector)

        _print_window_and_feature(
            window,
            vector,
            print_windows=print_windows,
            print_features=print_features,
        )

        result = reloader.score_feature_vector(vector)
        reloader.baseline.observe_window(window)

        if result.is_anomaly:
            print(json.dumps(_anomaly_record(result), sort_keys=True))
        elif print_all_scores:
            print(json.dumps(_inference_summary(result), sort_keys=True))

        completed_window_count += 1
        if reload_check_every_windows > 0 and completed_window_count % reload_check_every_windows == 0:
            reloader.maybe_reload()

        if should_stop is not None and should_stop():
            LOG.info("stopping detect loop for scheduled daemon action")
            return True

        return False

    try:
        for event in reader.iter_events():
            completed = agg.push(event)

            for window in completed:
                should_break = process_window(window)
                if should_break:
                    reader.stop()
                    break

    except KeyboardInterrupt:
        LOG.info("stopping detection")
        reader.stop()

    except GuardReaderError as exc:
        LOG.error("detection failed: %s", exc)
        reader.stop()
        return 1

    finally:
        for window in agg.flush():
            process_window(window)

    return 0


def run_daemon_auto_loop(args: argparse.Namespace) -> int:
    model_path = Path(args.model_path)
    next_bootstrap_attempt = time.time()
    next_retrain_at = time.time() + RETRAIN_INTERVAL_SECONDS

    LOG.info(
        "daemon auto mode started: bootstrap_retry=%ss retrain_interval=%ss",
        BOOTSTRAP_RETRY_SECONDS,
        RETRAIN_INTERVAL_SECONDS,
    )

    while True:
        now = time.time()

        if model_path.exists():
            def should_stop_detect() -> bool:
                return time.time() >= next_retrain_at

            rc = run_detect_loop(
                guardd_path=args.guardd_path,
                db_path=args.db_path,
                model_path=args.model_path,
                print_windows=args.print_windows,
                print_features=args.print_features,
                print_all_scores=args.print_all_scores,
                no_store=args.no_store,
                should_stop=should_stop_detect,
            )
            if rc != 0:
                return rc

            LOG.info("weekly retrain window reached; pausing detection for training")
            trained = try_train_model(
                db_path=args.db_path,
                model_out=args.model_path,
                limit=args.limit,
                contamination=args.contamination,
                n_estimators=args.n_estimators,
                random_state=args.random_state,
                threshold_percentile=args.threshold_percentile,
                emit_json=False,
            )

            if trained:
                LOG.info("weekly retrain completed successfully")
            else:
                LOG.info("weekly retrain skipped due to insufficient rows")

            next_retrain_at = time.time() + RETRAIN_INTERVAL_SECONDS
            continue

        def should_stop_collect() -> bool:
            return time.time() >= next_bootstrap_attempt

        rc = run_collect_loop(
            guardd_path=args.guardd_path,
            db_path=args.db_path,
            print_windows=args.print_windows,
            print_features=args.print_features,
            should_stop=should_stop_collect,
        )
        if rc != 0:
            return rc

        LOG.info("bootstrap training window reached; pausing collection for training")
        trained = try_train_model(
            db_path=args.db_path,
            model_out=args.model_path,
            limit=args.limit,
            contamination=args.contamination,
            n_estimators=args.n_estimators,
            random_state=args.random_state,
            threshold_percentile=args.threshold_percentile,
            emit_json=False,
        )

        if trained:
            LOG.info("bootstrap training succeeded; switching daemon to detect mode")
            next_retrain_at = time.time() + RETRAIN_INTERVAL_SECONDS
        else:
            next_bootstrap_attempt = time.time() + BOOTSTRAP_RETRY_SECONDS
            LOG.info(
                "bootstrap training skipped; will retry in %s seconds",
                BOOTSTRAP_RETRY_SECONDS,
            )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="guard")
    sub = parser.add_subparsers(dest="command", required=True)

    ingest = sub.add_parser("ingest", help="read live events from guardd")
    ingest.add_argument("--guardd-path", default="./ebpf/guardd", help="path to compiled guardd binary")
    ingest.add_argument("--pretty", action="store_true", help="pretty-print parsed events")
    ingest.add_argument("--debug", action="store_true", help="enable debug logging")
    ingest.add_argument("--print-windows", action="store_true", help="print completed window summaries")
    ingest.add_argument("--print-features", action="store_true", help="print feature vectors for completed windows")

    collect = sub.add_parser("collect", help="collect live features into SQLite")
    collect.add_argument("--guardd-path", default="./ebpf/guardd", help="path to compiled guardd binary")
    collect.add_argument("--db-path", default="data/features.db", help="path to SQLite feature store")
    collect.add_argument("--debug", action="store_true", help="enable debug logging")
    collect.add_argument("--print-windows", action="store_true", help="print completed window summaries while collecting")
    collect.add_argument("--print-features", action="store_true", help="print feature vectors while collecting")

    detect = sub.add_parser("detect", help="score live windows against trained model")
    detect.add_argument("--guardd-path", default="./ebpf/guardd", help="path to compiled guardd binary")
    detect.add_argument("--db-path", default="data/features.db", help="path to SQLite feature store")
    detect.add_argument("--model-path", default="data/model.bundle", help="path to trained model bundle")
    detect.add_argument("--debug", action="store_true", help="enable debug logging")
    detect.add_argument("--print-windows", action="store_true", help="print completed window summaries while detecting")
    detect.add_argument("--print-features", action="store_true", help="print feature vectors while detecting")
    detect.add_argument("--print-all-scores", action="store_true", help="print every scored window, not just anomalies")
    detect.add_argument("--no-store", action="store_true", help="do not write scored feature vectors to SQLite")

    daemon = sub.add_parser("daemon", help="long-running guard daemon")
    daemon.add_argument("--mode", choices=("auto", "collect", "detect"), default="auto", help="daemon mode selection")
    daemon.add_argument("--guardd-path", default="./ebpf/guardd", help="path to compiled guardd binary")
    daemon.add_argument("--db-path", default="data/features.db", help="path to SQLite feature store")
    daemon.add_argument("--model-path", default="data/model.bundle", help="path to trained model bundle")
    daemon.add_argument("--debug", action="store_true", help="enable debug logging")
    daemon.add_argument("--print-windows", action="store_true", help="print completed window summaries while running")
    daemon.add_argument("--print-features", action="store_true", help="print feature vectors while running")
    daemon.add_argument("--print-all-scores", action="store_true", help="print every scored window, not just anomalies")
    daemon.add_argument("--no-store", action="store_true", help="do not write scored feature vectors to SQLite in detect mode")
    daemon.add_argument("--limit", type=int, default=None, help="maximum number of rows to use for training")
    daemon.add_argument("--contamination", type=float, default=0.01, help="Isolation Forest contamination value")
    daemon.add_argument("--n-estimators", type=int, default=200, help="number of trees for Isolation Forest")
    daemon.add_argument("--random-state", type=int, default=42, help="random seed for training")
    daemon.add_argument("--threshold-percentile", type=float, default=10.0, help="low-score percentile used as anomaly threshold")

    train = sub.add_parser("train", help="train Isolation Forest model from stored features")
    train.add_argument("--db-path", default="data/features.db", help="path to SQLite feature store")
    train.add_argument("--model-out", default="data/model.bundle", help="path to output model bundle")
    train.add_argument("--limit", type=int, default=None, help="maximum number of rows to use for training")
    train.add_argument("--contamination", type=float, default=0.01, help="Isolation Forest contamination value")
    train.add_argument("--n-estimators", type=int, default=200, help="number of trees for Isolation Forest")
    train.add_argument("--random-state", type=int, default=42, help="random seed for training")
    train.add_argument("--threshold-percentile", type=float, default=10.0, help="low-score percentile used as anomaly threshold")
    train.add_argument("--debug", action="store_true", help="enable debug logging")

    return parser


def cmd_train(args: argparse.Namespace) -> int:
    _configure_logging(args.debug)

    try:
        trained = try_train_model(
            db_path=args.db_path,
            model_out=args.model_out,
            limit=args.limit,
            contamination=args.contamination,
            n_estimators=args.n_estimators,
            random_state=args.random_state,
            threshold_percentile=args.threshold_percentile,
            emit_json=True,
        )
    except ValueError as exc:
        LOG.error("training failed: %s", exc)
        return 1

    if not trained:
        return 0

    return 0


def cmd_ingest(args: argparse.Namespace) -> int:
    _configure_logging(args.debug)

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
    _configure_logging(args.debug)
    return run_collect_loop(
        guardd_path=args.guardd_path,
        db_path=args.db_path,
        print_windows=args.print_windows,
        print_features=args.print_features,
    )


def cmd_detect(args: argparse.Namespace) -> int:
    _configure_logging(args.debug)
    return run_detect_loop(
        guardd_path=args.guardd_path,
        db_path=args.db_path,
        model_path=args.model_path,
        print_windows=args.print_windows,
        print_features=args.print_features,
        print_all_scores=args.print_all_scores,
        no_store=args.no_store,
    )


def cmd_daemon(args: argparse.Namespace) -> int:
    _configure_logging(args.debug)

    if args.mode == "collect":
        return run_collect_loop(
            guardd_path=args.guardd_path,
            db_path=args.db_path,
            print_windows=args.print_windows,
            print_features=args.print_features,
        )

    if args.mode == "detect":
        return run_detect_loop(
            guardd_path=args.guardd_path,
            db_path=args.db_path,
            model_path=args.model_path,
            print_windows=args.print_windows,
            print_features=args.print_features,
            print_all_scores=args.print_all_scores,
            no_store=args.no_store,
        )

    return run_daemon_auto_loop(args)


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "ingest":
        return cmd_ingest(args)
    if args.command == "collect":
        return cmd_collect(args)
    if args.command == "detect":
        return cmd_detect(args)
    if args.command == "daemon":
        return cmd_daemon(args)
    if args.command == "train":
        return cmd_train(args)

    parser.error("unknown command")
    return 2
