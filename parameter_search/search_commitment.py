#!/usr/bin/env python3
from __future__ import annotations

import argparse
import math
import os
import sys
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from common import (
    append_jsonl,
    bool_text,
    full_split_condition,
    is_prime,
    log2_value,
    q_values_for_N,
    range_grade,
    write_csv,
)
from distributions import parse_bound_profiles
from estimator_wrapper import entry_columns, estimator_distribution, load_estimator_modules, run_estimator


COMMITMENT_FIELDS = [
    "N",
    "q",
    "log2_q",
    "q_prime",
    "fully_split",
    "B_profile",
    "B",
    "distribution",
    "support",
    "sigma_B",
    "ell_M",
    "k_s",
    "n_c",
    "n_LWE",
    "m_LWE",
    "n_SIS",
    "m_SIS",
    "L_bind",
    "beta_bind_inf",
    "beta_bind_l2",
    "mode",
    "estimator_commit",
    "hiding_attack",
    "hiding_log2_rop",
    "hiding_log2_red",
    "hiding_log2_mem",
    "hiding_bkz_beta",
    "binding_attack",
    "binding_norm",
    "binding_log2_rop",
    "binding_inf_log2_rop",
    "binding_l2_log2_rop",
    "binding_inf_exception",
    "binding_l2_exception",
    "opening_ring_polys",
    "randomness_ring_polys",
    "smallwood_rows_presign",
    "range_degree",
    "range_grade",
    "accepted",
    "rejection_reason",
    "manual_review",
    "raw_jsonl",
]


def _security(best: Any) -> float | None:
    return None if best is None else best.log2_rop


def _evaluate(
    LWE: Any,
    SIS: Any,
    ND: Any,
    oo: Any,
    N: int,
    q: int,
    profile: Any,
    ell_M: int,
    k_s: int,
    n_c: int,
    mode: str,
) -> dict[str, Any]:
    X = estimator_distribution(ND, profile)
    n_lwe = N * k_s
    m_lwe = N * n_c
    lwe_params = LWE.Parameters(n=n_lwe, q=q, Xs=X, Xe=X, m=m_lwe)
    hiding = run_estimator("commitment_hiding_mlwe", LWE, lwe_params, mode)

    L_bind = ell_M + k_s + n_c
    n_sis = N * n_c
    m_sis = N * L_bind
    beta_inf = 2 * profile.B
    beta_l2 = 2 * profile.B * math.sqrt(N * L_bind)

    inf_params = SIS.Parameters(n=n_sis, m=m_sis, q=q, length_bound=beta_inf, norm=oo)
    l2_params = SIS.Parameters(n=n_sis, m=m_sis, q=q, length_bound=float(beta_l2), norm=2)
    binding_inf = run_estimator("commitment_binding_msis_inf", SIS, inf_params, mode)
    binding_l2 = run_estimator("commitment_binding_msis_l2", SIS, l2_params, mode)

    return {
        "hiding": hiding,
        "binding_inf": binding_inf,
        "binding_l2": binding_l2,
        "params": {
            "lwe": repr(lwe_params),
            "sis_inf": repr(inf_params),
            "sis_l2": repr(l2_params),
        },
        "n_LWE": n_lwe,
        "m_LWE": m_lwe,
        "n_SIS": n_sis,
        "m_SIS": m_sis,
        "L_bind": L_bind,
        "beta_bind_inf": beta_inf,
        "beta_bind_l2": beta_l2,
    }


def _binding_choice(inf_best: Any, l2_best: Any) -> tuple[str, str, float | None]:
    candidates: list[tuple[str, Any]] = []
    if inf_best is not None and inf_best.log2_rop is not None:
        candidates.append(("inf", inf_best))
    if l2_best is not None and l2_best.log2_rop is not None:
        candidates.append(("l2", l2_best))
    if not candidates:
        return "", "", None
    norm, entry = min(candidates, key=lambda item: item[1].log2_rop)
    return entry.attack, norm, entry.log2_rop


def _row_from_outcome(
    N: int,
    q: int,
    profile: Any,
    ell_M: int,
    k_s: int,
    n_c: int,
    mode: str,
    estimator_commit: str,
    min_bits: float,
    s_sw: int,
    outcome: dict[str, Any] | None,
    rejection_prefix: list[str] | None = None,
    raw_jsonl: str = "",
) -> dict[str, Any]:
    reasons = list(rejection_prefix or [])
    q_prime = bool(is_prime(int(q)))
    split = full_split_condition(q, N)
    L_bind = ell_M + k_s + n_c
    beta_l2 = 2 * profile.B * math.sqrt(N * L_bind)

    if outcome is None:
        hide_best = inf_best = l2_best = None
        n_lwe = N * k_s
        m_lwe = N * n_c
        n_sis = N * n_c
        m_sis = N * L_bind
        binding_inf_exc = ""
        binding_l2_exc = ""
    else:
        hide_best = outcome["hiding"].best
        inf_best = outcome["binding_inf"].best
        l2_best = outcome["binding_l2"].best
        n_lwe = outcome["n_LWE"]
        m_lwe = outcome["m_LWE"]
        n_sis = outcome["n_SIS"]
        m_sis = outcome["m_SIS"]
        binding_inf_exc = outcome["binding_inf"].exception or ""
        binding_l2_exc = outcome["binding_l2"].exception or ""

        hide_sec = _security(hide_best)
        inf_sec = _security(inf_best)
        l2_sec = _security(l2_best)
        if outcome["hiding"].exception:
            reasons.append(f"hiding estimator exception: {outcome['hiding'].exception}")
        elif hide_sec is None:
            reasons.append("hiding estimate unavailable")
        elif hide_sec < min_bits:
            reasons.append("hiding below target")

        if outcome["binding_inf"].exception:
            reasons.append(f"binding inf estimator exception: {outcome['binding_inf'].exception}")
        elif inf_sec is None:
            reasons.append("binding inf estimate unavailable")
        elif inf_sec < min_bits:
            reasons.append("binding inf below target")

        if outcome["binding_l2"].exception:
            reasons.append(f"binding l2 estimator exception: {outcome['binding_l2'].exception}")
        elif l2_sec is None:
            reasons.append("binding l2 estimate unavailable")
        elif l2_sec < min_bits:
            reasons.append("binding l2 below target")

    if not q_prime:
        reasons.append("q not prime")
    if not split:
        reasons.append("q not fully split")
    if 2 * profile.B + 1 > 65:
        reasons.append("range degree requires decomposition")

    binding_attack, binding_norm, binding_sec = _binding_choice(inf_best, l2_best)
    row = {
        "N": N,
        "q": q,
        "log2_q": log2_value(q),
        "q_prime": str(q_prime).lower(),
        "fully_split": str(split).lower(),
        "B_profile": profile.profile,
        "B": profile.B,
        "distribution": profile.distribution,
        "support": profile.support,
        "sigma_B": profile.sigma_B,
        "ell_M": ell_M,
        "k_s": k_s,
        "n_c": n_c,
        "n_LWE": n_lwe,
        "m_LWE": m_lwe,
        "n_SIS": n_sis,
        "m_SIS": m_sis,
        "L_bind": L_bind,
        "beta_bind_inf": 2 * profile.B,
        "beta_bind_l2": beta_l2,
        "mode": mode,
        "estimator_commit": estimator_commit,
        "binding_attack": binding_attack,
        "binding_norm": binding_norm,
        "binding_log2_rop": binding_sec,
        "binding_inf_log2_rop": _security(inf_best),
        "binding_l2_log2_rop": _security(l2_best),
        "binding_inf_exception": binding_inf_exc,
        "binding_l2_exception": binding_l2_exc,
        "opening_ring_polys": L_bind,
        "randomness_ring_polys": k_s + n_c,
        "smallwood_rows_presign": (N * L_bind) / s_sw,
        "range_degree": 2 * profile.B + 1,
        "range_grade": range_grade(profile.B),
        "accepted": bool_text(len(reasons) == 0),
        "rejection_reason": "; ".join(dict.fromkeys(reasons)),
        "manual_review": bool_text(bool(binding_inf_exc or binding_l2_exc)),
        "raw_jsonl": raw_jsonl,
    }
    row.update(entry_columns("hiding", hide_best))
    return row


def run_search(args: argparse.Namespace) -> list[dict[str, Any]]:
    LWE, SIS, _NTRU, ND, oo, _sqrt, _pi, _log = load_estimator_modules(args.estimator_path)
    profiles = parse_bound_profiles(args.bounds)
    output = Path(args.output)
    raw_jsonl = output.with_suffix(output.suffix + ".raw.jsonl")
    if raw_jsonl.exists():
        raw_jsonl.unlink()

    run_rough = args.run_rough or not args.run_full
    if args.run_full:
        run_rough = True

    rows: list[dict[str, Any]] = []
    cache: dict[tuple[Any, ...], dict[str, Any]] = {}
    for N in args.Ns:
        for q in q_values_for_N(args, N):
            for profile in profiles:
                for ell_M in args.ell_M:
                    for k_s in args.k_s:
                        for n_c in args.n_c:
                            prefix_reasons: list[str] = []
                            if args.require_fully_split and not full_split_condition(q, N):
                                prefix_reasons.append("q not fully split")
                            if not is_prime(int(q)):
                                prefix_reasons.append("q not prime")

                            rough_row: dict[str, Any] | None = None
                            for mode in (["rough"] if run_rough else []):
                                outcome = None
                                if not prefix_reasons:
                                    key = (mode, N, q, profile.profile, ell_M, k_s, n_c)
                                    outcome = cache.get(key)
                                    if outcome is None:
                                        outcome = _evaluate(LWE, SIS, ND, oo, N, q, profile, ell_M, k_s, n_c, mode)
                                        cache[key] = outcome
                                        append_jsonl(
                                            raw_jsonl,
                                            {
                                                "N": N,
                                                "q": q,
                                                "B_profile": profile.profile,
                                                "ell_M": ell_M,
                                                "k_s": k_s,
                                                "n_c": n_c,
                                                "mode": mode,
                                                "params": outcome["params"],
                                                "hiding": outcome["hiding"],
                                                "binding_inf": outcome["binding_inf"],
                                                "binding_l2": outcome["binding_l2"],
                                            },
                                        )
                                rough_row = _row_from_outcome(
                                    N,
                                    q,
                                    profile,
                                    ell_M,
                                    k_s,
                                    n_c,
                                    mode,
                                    args.estimator_commit,
                                    args.min_bits,
                                    args.s_sw,
                                    outcome,
                                    prefix_reasons,
                                    str(raw_jsonl),
                                )
                                rows.append(rough_row)

                            should_run_full = args.run_full and rough_row is not None and rough_row.get("accepted") == "yes"
                            if args.run_full and not run_rough and not prefix_reasons:
                                should_run_full = True
                            if should_run_full:
                                mode = "full"
                                key = (mode, N, q, profile.profile, ell_M, k_s, n_c)
                                outcome = cache.get(key)
                                if outcome is None:
                                    outcome = _evaluate(LWE, SIS, ND, oo, N, q, profile, ell_M, k_s, n_c, mode)
                                    cache[key] = outcome
                                    append_jsonl(
                                        raw_jsonl,
                                        {
                                            "N": N,
                                            "q": q,
                                            "B_profile": profile.profile,
                                            "ell_M": ell_M,
                                            "k_s": k_s,
                                            "n_c": n_c,
                                            "mode": mode,
                                            "params": outcome["params"],
                                            "hiding": outcome["hiding"],
                                            "binding_inf": outcome["binding_inf"],
                                            "binding_l2": outcome["binding_l2"],
                                        },
                                    )
                                rows.append(
                                    _row_from_outcome(
                                        N,
                                        q,
                                        profile,
                                        ell_M,
                                        k_s,
                                        n_c,
                                        mode,
                                        args.estimator_commit,
                                        args.min_bits,
                                        args.s_sw,
                                        outcome,
                                        prefix_reasons,
                                        str(raw_jsonl),
                                    )
                                )

    write_csv(output, rows, COMMITMENT_FIELDS)
    return rows


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Search ARC-SPRUCE MLWE/MSIS commitment parameters.")
    parser.add_argument("--Ns", type=int, nargs="+", default=[256, 512])
    parser.add_argument("--bounds", nargs="+", default=["ternary", "3", "4", "6", "8"])
    parser.add_argument("--ell-M", "--l-M", dest="ell_M", type=int, nargs="+", default=[1])
    parser.add_argument("--k-s", "--k_s", dest="k_s", type=int, nargs="+", default=[1, 2, 3, 4, 5, 6, 8, 10, 12, 16])
    parser.add_argument("--n-c", "--n_c", dest="n_c", type=int, nargs="+", default=[1, 2, 3, 4, 5, 6, 8])
    parser.add_argument("--bits-start", type=int, default=12)
    parser.add_argument("--bits-end", type=int, default=30)
    parser.add_argument("--qs-per-bit", type=int, default=2)
    parser.add_argument("--max-delta-steps", type=int, default=20000)
    parser.add_argument("--q", type=int, nargs="+", default=None)
    parser.add_argument("--min-bits", type=float, default=128.0)
    parser.add_argument("--s-sw", type=int, default=16)
    parser.add_argument("--run-rough", action="store_true")
    parser.add_argument("--run-full", action="store_true")
    parser.add_argument("--require-fully-split", action="store_true", default=True)
    parser.add_argument("--estimator-path", default="/tmp/lattice-estimator-dklw")
    parser.add_argument("--estimator-commit", default="unknown")
    parser.add_argument("--output", default="parameter_search/results/commitment.csv")
    return parser.parse_args(argv)


if __name__ == "__main__":
    run_search(parse_args())
