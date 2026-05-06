#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from common import DEFAULT_ESTIMATOR_PATH, setup_estimator, write_estimator_commit


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Clone/update malb/lattice-estimator and record commit.")
    parser.add_argument("--estimator-path", default=DEFAULT_ESTIMATOR_PATH)
    parser.add_argument("--estimator-ref", default=None)
    parser.add_argument("--output-dir", default=None)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    setup = setup_estimator(args.estimator_path, args.estimator_ref)
    if args.output_dir:
        write_estimator_commit(setup, args.output_dir)
    print(f"estimator_path={setup.path}")
    print(f"estimator_commit={setup.commit}")
    if setup.requested_ref:
        print(f"requested_ref={setup.requested_ref}")
        print(f"checkout_ok={str(setup.checkout_ok).lower()}")
    for message in setup.messages:
        print(f"note={message}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
