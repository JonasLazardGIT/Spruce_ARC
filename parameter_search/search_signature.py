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


SIGNATURE_FIELDS = [
    "N",
    "q",
    "log2_q",
    "q_prime",
    "fully_split",
    "ell_m",
    "ell_r",
    "alpha",
    "eta_Z2N",
    "s_trap",
    "beta_sig",
    "log2_beta_sig",
    "m_sig",
    "mode",
    "estimator_commit",
    "sig_attack",
    "sig_log2_rop",
    "sig_log2_red",
    "sig_log2_mem",
    "sig_bkz_beta",
    "beta_lt_q",
    "beta_lt_q2",
    "sig_bits",
    "sig_bytes",
    "sig_kib",
    "pk_bits",
    "pk_bytes",
    "pk_kib",
    "accepted",
    "rejection_reason",
    "raw_jsonl",
]


def dklw_signature_formulas(N: int, q: int, ell_m: int, ell_r: int, alpha: float, lambda_bits: int) -> dict[str, float]:
    eta = math.sqrt(math.log(4 * N * (1 + 2**lambda_bits)) / math.pi)
    s_trap = alpha * math.sqrt(q) * eta
    ring_polys = 3 + ell_m + ell_r
    beta_sig = s_trap * math.sqrt(N * ring_polys)
    log2_beta = math.log2(beta_sig)
    sig_bits = (2 + ell_r) * N * log2_beta
    sig_bytes = sig_bits / 8.0
    # DKLW adopts the NTRU-key optimisation: the public key is derived from
    # one R_q element, not from the full trapdoored matrix representation.
    pk_bits = N * math.log2(q)
    return {
        "eta_Z2N": eta,
        "s_trap": s_trap,
        "beta_sig": beta_sig,
        "log2_beta_sig": log2_beta,
        "m_sig": N * ring_polys,
        "sig_bits": sig_bits,
        "sig_bytes": sig_bytes,
        "sig_kib": sig_bytes / 1024.0,
        "pk_bits": pk_bits,
        "pk_bytes": pk_bits / 8.0,
        "pk_kib": pk_bits / 8.0 / 1024.0,
    }


def _row(
    N: int,
    q: int,
    ell_m: int,
    ell_r: int,
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
    beta_lt_q = formulas["beta_sig"] < q
    beta_lt_q2 = formulas["beta_sig"] < q / 2.0
    if not q_prime:
        reasons.append("q not prime")
    if not split:
        reasons.append("q not fully split")
    if not beta_lt_q:
        reasons.append("beta_sig >= q")

    best = None if outcome is None else outcome.best
    if outcome is not None:
        if outcome.exception:
            reasons.append(f"signature SIS estimator exception: {outcome.exception}")
        elif best is None or best.log2_rop is None:
            reasons.append("signature SIS estimate unavailable")
        elif best.log2_rop < min_bits:
            reasons.append("signature SIS below target")

    row = {
        "N": N,
        "q": q,
        "log2_q": log2_value(q),
        "q_prime": str(q_prime).lower(),
        "fully_split": str(split).lower(),
        "ell_m": ell_m,
        "ell_r": ell_r,
        "alpha": alpha,
        "eta_Z2N": formulas["eta_Z2N"],
        "s_trap": formulas["s_trap"],
        "beta_sig": formulas["beta_sig"],
        "log2_beta_sig": formulas["log2_beta_sig"],
        "m_sig": int(formulas["m_sig"]),
        "mode": mode,
        "estimator_commit": estimator_commit,
        "beta_lt_q": str(beta_lt_q).lower(),
        "beta_lt_q2": str(beta_lt_q2).lower(),
        "sig_bits": formulas["sig_bits"],
        "sig_bytes": formulas["sig_bytes"],
        "sig_kib": formulas["sig_kib"],
        "pk_bits": formulas["pk_bits"],
        "pk_bytes": formulas["pk_bytes"],
        "pk_kib": formulas["pk_kib"],
        "accepted": bool_text(len(reasons) == 0),
        "rejection_reason": "; ".join(dict.fromkeys(reasons)),
        "raw_jsonl": raw_jsonl,
    }
    row.update(entry_columns("sig", best))
    return row


def run_search(args: argparse.Namespace) -> list[dict[str, Any]]:
    _LWE, SIS, _NTRU, _ND, _oo, _sqrt, _pi, _log = load_estimator_modules(args.estimator_path)
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
            for ell_m in args.ell_m:
                for ell_r in args.ell_r:
                    for alpha in args.alpha:
                        formulas = dklw_signature_formulas(N, q, ell_m, ell_r, alpha, args.lambda_bits)
                        prefix: list[str] = []
                        if args.require_fully_split and not full_split_condition(q, N):
                            prefix.append("q not fully split")
                        if not is_prime(int(q)):
                            prefix.append("q not prime")
                        rough_row: dict[str, Any] | None = None
                        for mode in (["rough"] if run_rough else []):
                            outcome = None
                            if not prefix:
                                key = (mode, N, q, ell_m, ell_r, alpha)
                                outcome = cache.get(key)
                                if outcome is None:
                                    params = SIS.Parameters(
                                        n=N,
                                        m=int(formulas["m_sig"]),
                                        q=q,
                                        length_bound=float(formulas["beta_sig"]),
                                        norm=2,
                                    )
                                    outcome = run_estimator("dklw_bb_tran_signature_sis", SIS, params, mode)
                                    cache[key] = outcome
                                    append_jsonl(
                                        raw_jsonl,
                                        {
                                            "N": N,
                                            "q": q,
                                            "ell_m": ell_m,
                                            "ell_r": ell_r,
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
                                ell_m,
                                ell_r,
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
                            key = (mode, N, q, ell_m, ell_r, alpha)
                            outcome = cache.get(key)
                            if outcome is None:
                                params = SIS.Parameters(
                                    n=N,
                                    m=int(formulas["m_sig"]),
                                    q=q,
                                    length_bound=float(formulas["beta_sig"]),
                                    norm=2,
                                )
                                outcome = run_estimator("dklw_bb_tran_signature_sis", SIS, params, mode)
                                cache[key] = outcome
                                append_jsonl(
                                    raw_jsonl,
                                    {
                                        "N": N,
                                        "q": q,
                                        "ell_m": ell_m,
                                        "ell_r": ell_r,
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
                                    ell_m,
                                    ell_r,
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

    write_csv(output, rows, SIGNATURE_FIELDS)
    return rows


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Search DKLW/BB-tran rational-hash signature parameters.")
    parser.add_argument("--Ns", type=int, nargs="+", default=[256, 512])
    parser.add_argument("--ell-m", "--l-m", dest="ell_m", type=int, nargs="+", default=[1])
    parser.add_argument("--ell-r", "--l-r", dest="ell_r", type=int, nargs="+", default=[2])
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
    parser.add_argument("--output", default="parameter_search/results/signature.csv")
    return parser.parse_args(argv)


if __name__ == "__main__":
    run_search(parse_args())
