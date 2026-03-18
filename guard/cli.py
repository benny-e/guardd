from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

from guard.ebpf.reader import GuardReaderError, GuarddProcessReader, event_to_dict

LOG = logging.getLogger(__name__)


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

    return parser

def cmd_ingest(args: argparse.Namespace) -> int:
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    reader = GuarddProcessReader(Path(args.guardd_path))

    try:
        for event in reader.iter_events():
            payload = event_to_dict(event)
            if args.pretty:
                print(json.dumps(payload, indent=2, sort_keys=True))
            else:
                print(json.dumps(payload, separators=(",", ":"), sort_keys=True))
    except KeyboardInterrupt:
        LOG.info("stopping ingestion")
        reader.stop()
        return 0
    except GuardReaderError as exc:
        LOG.error("ingestion failed: %s", exc)
        reader.stop()
        return 1

    return 0

def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "ingest":
        return cmd_ingest(args)

    parser.error("unknown command")
    return 2
