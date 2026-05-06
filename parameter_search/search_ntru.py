#!/usr/bin/env python3
from __future__ import annotations

import argparse
import math
import sys
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from common import append_jsonl, bool_text, full_split_condition, is_prime, log2_value, q_values_for_N, write_csv
from estimator_wrapper import entry_columns, load_estimator_modules, run_estimator


NTRU_FIELDS = [
    "N",
    "q",
    "log2_q",
    "q_prime",
    "fully_split",
    "alpha",
    "eta_Z2N",
    "s_trap",
    "mode",
    "estimator_commit",
    "ntru_attack",
    "ntru_log2_rop",
    "ntru_log2_red",
    "ntru_log2_mem",
    "ntru_bkz_beta",
    "accepted",
    "rejection_reason",
    "notes",
    "raw_jsonl",
]


def ntru_formulas(N: int, q: int, alpha: float, lambda_bits: int) -> dict[str, float]:
    eta = math.sqrt(math.log(4 * N * (1 + 2**lambda_bits)) / math.pi)
    s_trap = alpha * math.sqrt(q) * eta
    return {"eta_Z2N": eta, "s_trap": s_trap}


def _row(
    N: int,
    q: int,
    alpha: float,
    mode: str,
    estimator_commit: str,
    min_bits: float,
    formulas: dict[str, float],
    outcome: Any | None,
    raw_jsonl: str,
    prefix_reasons: list[str] | None = None,
) -> dict[str, Any]:
    reasons = list(prefix_reasons or [])
    q_prime = bool(is_prime(int(q)))
    split = full_split_condition(q, N)
    if not q_prime:
        reasons.append("q not prime")
    if not split:
        reasons.append("q not fully split")

    best = None if outcome is None else outcome.best
    if outcome is not None:
        if outcome.exception:
            reasons.append(f"NTRU estimator exception: {outcome.exception}")
        elif best is None or best.log2_rop is None:
            reasons.append("NTRU estimate unavailable")
        elif best.log2_rop < min_bits:
            reasons.append("NTRU below target")

    row = {
        "N": N,
        "q": q,
        "log2_q": log2_value(q),
        "q_prime": str(q_prime).lower(),
        "fully_split": str(split).lower(),
        "alpha": alpha,
        "eta_Z2N": formulas["eta_Z2N"],
        "s_trap": formulas["s_trap"],
        "mode": mode,
        "estimator_commit": estimator_commit,
        "accepted": bool_text(len(reasons) == 0),
        "rejection_reason": "; ".join(dict.fromkeys(reasons)),
        "notes": "NTRU estimate only; sampler/trapdoor admissibility remains an implementation/source assumption.",
        "raw_jsonl": raw_jsonl,
    }
    row.update(entry_columns("ntru", best))
    return row


def run_search(args: argparse.Namespace) -> list[dict[str, Any]]:
    _LWE, _SIS, NTRU, ND, _oo, _sqrt, _pi, _log = load_estimator_modules(args.estimator_path)
    output = Path(args.output)
    raw_jsonl = output.with_suffix(output.suffix + ".raw.jsonl")
    if raw_jsonl.exists():
        raw_jsonl.unlink()

    run_rough = args.run_rough or not args.run_full
    if args.run_full:
        run_rough = True

    rows: list[dict[str, Any]] = []
    cache: dict[tuple[Any, ...], Any] = {}
    for N in args.Ns:
        for q in q_values_for_N(args, N):
            for alpha in args.alpha:
                formulas = ntru_formulas(N, q, alpha, args.lambda_bits)
                prefix: list[str] = []
                if args.require_fully_split and not full_split_condition(q, N):
                    prefix.append("q not fully split")
                if not is_prime(int(q)):
                    prefix.append("q not prime")
                rough_row: dict[str, Any] | None = None
                for mode in (["rough"] if run_rough else []):
                    outcome = None
                    if not prefix:
                        key = (mode, N, q, alpha)
                        outcome = cache.get(key)
                        if outcome is None:
                            X = ND.DiscreteGaussian(float(formulas["s_trap"]))
                            params = NTRU.Parameters(n=N, q=q, Xs=X, Xe=X)
                            outcome = run_estimator("ntru_trapdoor_estimate", NTRU, params, mode)
                            cache[key] = outcome
                            append_jsonl(
                                raw_jsonl,
                                {
                                    "N": N,
                                    "q": q,
                                    "alpha": alpha,
                                    "mode": mode,
                                    "params": repr(params),
                                    "formulas": formulas,
                                    "estimate": outcome,
                                },
                            )
                    rough_row = _row(
                        N,
                        q,
                        alpha,
                        mode,
                        args.estimator_commit,
                        args.min_bits,
                        formulas,
                        outcome,
                        str(raw_jsonl),
                        prefix,
                    )
                    rows.append(rough_row)

                should_run_full = args.run_full and rough_row is not None and rough_row.get("accepted") == "yes"
                if should_run_full:
                    mode = "full"
                    key = (mode, N, q, alpha)
                    outcome = cache.get(key)
                    if outcome is None:
                        X = ND.DiscreteGaussian(float(formulas["s_trap"]))
                        params = NTRU.Parameters(n=N, q=q, Xs=X, Xe=X)
                        outcome = run_estimator("ntru_trapdoor_estimate", NTRU, params, mode)
                        cache[key] = outcome
                        append_jsonl(
                            raw_jsonl,
                            {
                                "N": N,
                                "q": q,
                                "alpha": alpha,
                                "mode": mode,
                                "params": repr(params),
                                "formulas": formulas,
                                "estimate": outcome,
                            },
                        )
                    rows.append(
                        _row(
                            N,
                            q,
                            alpha,
                            mode,
                            args.estimator_commit,
                            args.min_bits,
                            formulas,
                            outcome,
                            str(raw_jsonl),
                            prefix,
                        )
                    )

    write_csv(output, rows, NTRU_FIELDS)
    return rows


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Search ARC-SPRUCE NTRU/trapdoor estimator parameters.")
    parser.add_argument("--Ns", type=int, nargs="+", default=[256, 512])
    parser.add_argument("--alpha", type=float, nargs="+", default=[1.15, 1.17, 1.23, 1.48, 2.04])
    parser.add_argument("--lambda-bits", type=int, default=128)
    parser.add_argument("--bits-start", type=int, default=12)
    parser.add_argument("--bits-end", type=int, default=30)
    parser.add_argument("--qs-per-bit", type=int, default=2)
    parser.add_argument("--max-delta-steps", type=int, default=20000)
    parser.add_argument("--q", type=int, nargs="+", default=None)
    parser.add_argument("--min-bits", type=float, default=128.0)
    parser.add_argument("--run-rough", action="store_true")
    parser.add_argument("--run-full", action="store_true")
    parser.add_argument("--require-fully-split", action="store_true", default=True)
    parser.add_argument("--estimator-path", default="/tmp/lattice-estimator-dklw")
    parser.add_argument("--estimator-commit", default="unknown")
    parser.add_argument("--output", default="parameter_search/results/ntru.csv")
    return parser.parse_args(argv)


if __name__ == "__main__":
    run_search(parse_args())
