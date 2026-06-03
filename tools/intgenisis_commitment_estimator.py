#!/usr/bin/env python3
"""Estimate live IntGenISIS Ajtai/MLWE commitment security.

This script is intentionally narrow. It models exactly the live commitment

    c = C_M*M + A_s*s + e

with implementation dimensions from credential/intgenisis_profile.go.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import subprocess
import sys
from pathlib import Path


PROFILES = [
    {
        "name": "intgenisis_profile_b",
        "N": 512,
        "q": 1017857,
        "ell_M": 1,
        "k_s": 2,
        "n_c": 1,
        "B": 4,
    },
    {
        "name": "intgenisis_profile_c",
        "N": 1024,
        "q": 1017857,
        "ell_M": 1,
        "k_s": 1,
        "n_c": 1,
        "B": 1,
    },
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--estimator-path",
        default=os.environ.get("LATTICE_ESTIMATOR_PATH", ""),
        help="path containing the estimator Python package; defaults to LATTICE_ESTIMATOR_PATH",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="pretty-print JSON",
    )
    return parser.parse_args()


def estimator_commit(path: Path) -> str:
    try:
        return subprocess.check_output(
            ["git", "-C", str(path), "rev-parse", "HEAD"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        return ""


def log2_value(value, oo) -> float:
    if value == oo or str(value) in {"+Infinity", "Infinity", "inf"}:
        return math.inf
    return float(math.log(float(value), 2))


def summarize_estimate(result, oo) -> dict:
    entries = []
    for attack, cost in result.items():
        rop = log2_value(cost.get("rop"), oo)
        entries.append(
            {
                "attack": attack,
                "log2_rop": "inf" if math.isinf(rop) else round(rop, 3),
                "bkz_beta": int(cost["beta"]) if "beta" in cost and cost["beta"] is not None else None,
                "tag": str(cost.get("tag")) if cost.get("tag") is not None else "",
            }
        )
    finite = [entry for entry in entries if entry["log2_rop"] != "inf"]
    best = min(finite, key=lambda entry: entry["log2_rop"]) if finite else None
    return {
        "best": best or {"attack": "", "log2_rop": "inf", "bkz_beta": None, "tag": ""},
        "entries": entries,
    }


def statistical_hiding_slack(profile: dict) -> float:
    n = profile["N"]
    q = profile["q"]
    k_s = profile["k_s"]
    n_c = profile["n_c"]
    b = profile["B"]
    randomness = n * (k_s + n_c) * math.log2(2 * b + 1)
    required = n * n_c * math.log2(q) + 2 * 128
    return randomness - required


def statistical_binding_slack(profile: dict) -> float:
    n = profile["N"]
    q = profile["q"]
    ell_m = profile["ell_M"]
    k_s = profile["k_s"]
    n_c = profile["n_c"]
    b = profile["B"]
    codomain = n * n_c * math.log2(q)
    diff_space = n * (ell_m + k_s + n_c) * math.log2(4 * b + 1)
    return codomain - diff_space


def main() -> int:
    args = parse_args()
    if not args.estimator_path:
        print("missing --estimator-path or LATTICE_ESTIMATOR_PATH", file=sys.stderr)
        return 2
    estimator_path = Path(args.estimator_path).resolve()
    sys.path.insert(0, str(estimator_path))

    from sage.all import oo, sqrt  # noqa: PLC0415
    from estimator import LWE, ND, SIS  # noqa: PLC0415

    estimates = []
    for profile in PROFILES:
        n = profile["N"]
        q = profile["q"]
        ell_m = profile["ell_M"]
        k_s = profile["k_s"]
        n_c = profile["n_c"]
        b = profile["B"]
        distribution = ND.Uniform(-b, b)

        lwe = LWE.Parameters(n=n * k_s, q=q, Xs=distribution, Xe=distribution, m=n * n_c)
        bind_len = ell_m + k_s + n_c
        sis_l2 = SIS.Parameters(
            n=n * n_c,
            q=q,
            length_bound=float(2 * b * sqrt(n * bind_len)),
            m=n * bind_len,
            norm=2,
        )
        sis_inf = SIS.Parameters(
            n=n * n_c,
            q=q,
            length_bound=2 * b,
            m=n * bind_len,
            norm=oo,
        )

        hiding = summarize_estimate(LWE.estimate.rough(lwe, quiet=True), oo)
        binding_l2 = summarize_estimate(SIS.estimate.rough(sis_l2, quiet=True), oo)
        binding_inf = summarize_estimate(SIS.estimate.rough(sis_inf, quiet=True), oo)
        estimates.append(
            {
                "profile": profile,
                "mlwe_hiding": hiding,
                "msis_binding_l2": binding_l2,
                "msis_binding_inf": binding_inf,
                "statistical_hiding_satisfied": statistical_hiding_slack(profile) >= 0,
                "statistical_hiding_slack_bits": round(statistical_hiding_slack(profile), 3),
                "statistical_binding_slack_bits": round(statistical_binding_slack(profile), 3),
            }
        )

    output = {
        "estimator": {
            "path": str(estimator_path),
            "commit": estimator_commit(estimator_path),
            "mode": "rough",
        },
        "estimates": estimates,
    }
    print(json.dumps(output, indent=2 if args.pretty else None, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
