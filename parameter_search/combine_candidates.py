#!/usr/bin/env python3
from __future__ import annotations

import argparse
import math
import sys
from collections import Counter
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from common import bool_text, is_yes, parse_float, read_csv, write_csv


COMBINED_FIELDS = [
    "N",
    "q",
    "log2_q",
    "B_profile",
    "B",
    "ell_M",
    "k_s",
    "n_c",
    "ell_m",
    "ell_r",
    "alpha",
    "commit_mode",
    "sig_mode",
    "ntru_mode",
    "all_full",
    "commit_hide_sec",
    "commit_bind_sec",
    "sig_sec",
    "ntru_sec",
    "min_sec",
    "gamma",
    "beta_sig",
    "beta_prime",
    "q_over_2_gt_gamma",
    "beta_sig_lt_q",
    "beta_prime_lt_q",
    "beta_prime_lt_q2",
    "x1_inv_prob",
    "x1_inv_failure",
    "L_presign",
    "rows_presign",
    "L_show",
    "rows_show",
    "range_degree",
    "range_grade",
    "combined_accepted",
    "rejection_reason",
    "notes",
]


def _sec(row: dict[str, str], key: str) -> float | None:
    return parse_float(row.get(key))


def _accepted(row: dict[str, str]) -> bool:
    return is_yes(row.get("accepted"))


def _mode_rank(row: dict[str, str]) -> int:
    return 0 if row.get("mode") == "full" else 1


def _best_by_key(rows: list[dict[str, str]], key_fn: Any, sec_key: str) -> dict[tuple[Any, ...], dict[str, str]]:
    out: dict[tuple[Any, ...], dict[str, str]] = {}
    for row in rows:
        try:
            key = key_fn(row)
        except Exception:
            continue
        cur = out.get(key)
        if cur is None:
            out[key] = row
            continue
        cur_tuple = (_mode_rank(cur), not _accepted(cur), -(_sec(cur, sec_key) or -1.0))
        row_tuple = (_mode_rank(row), not _accepted(row), -(_sec(row, sec_key) or -1.0))
        if row_tuple < cur_tuple:
            out[key] = row
    return out


def _f(row: dict[str, str], key: str, default: float = 0.0) -> float:
    value = parse_float(row.get(key))
    return default if value is None else value


def _i(row: dict[str, str], key: str, default: int = 0) -> int:
    try:
        return int(row.get(key, "") or default)
    except Exception:
        return default


def _x1_probs(q: int, N: int) -> tuple[float, float]:
    if q <= 1:
        return 0.0, 1.0
    log_prob = N * math.log1p(-1.0 / q)
    prob = math.exp(log_prob)
    failure = -math.expm1(log_prob)
    return prob, failure


def combine_rows(
    commitment_rows: list[dict[str, str]],
    signature_rows: list[dict[str, str]],
    ntru_rows: list[dict[str, str]],
    N: int,
    min_bits: float,
    s_sw: int,
    allow_target_expansion: bool = False,
) -> list[dict[str, Any]]:
    commits = _best_by_key(
        [r for r in commitment_rows if _i(r, "N") == N],
        lambda r: (
            _i(r, "N"),
            _i(r, "q"),
            r.get("B_profile", ""),
            _i(r, "ell_M"),
            _i(r, "k_s"),
            _i(r, "n_c"),
        ),
        "binding_log2_rop",
    )
    signatures = _best_by_key(
        [r for r in signature_rows if _i(r, "N") == N],
        lambda r: (_i(r, "N"), _i(r, "q"), _i(r, "ell_m"), _i(r, "ell_r"), r.get("alpha", "")),
        "sig_log2_rop",
    )
    ntrus = _best_by_key(
        [r for r in ntru_rows if _i(r, "N") == N],
        lambda r: (_i(r, "N"), _i(r, "q"), r.get("alpha", "")),
        "ntru_log2_rop",
    )

    rows: list[dict[str, Any]] = []
    for c in commits.values():
        q = _i(c, "q")
        for s_key, s in signatures.items():
            if s_key[0] != N or s_key[1] != q:
                continue
            alpha = s.get("alpha", "")
            ntru = ntrus.get((N, q, alpha))
            if ntru is None:
                continue

            B = _i(c, "B")
            ell_M = _i(c, "ell_M")
            k_s = _i(c, "k_s")
            n_c = _i(c, "n_c")
            ell_m = _i(s, "ell_m")
            ell_r = _i(s, "ell_r")
            gamma = B * math.sqrt(N * (ell_M + k_s + n_c))
            beta_sig = _f(s, "beta_sig")
            beta_prime = beta_sig + gamma
            q_over_2_gt_gamma = q / 2.0 > gamma
            beta_sig_lt_q = beta_sig < q
            beta_prime_lt_q = beta_prime < q
            beta_prime_lt_q2 = beta_prime < q / 2.0
            x1_prob, x1_failure = _x1_probs(q, N)

            L_presign = ell_M + k_s + n_c
            rows_presign = L_presign * N / s_sw
            L_show = 2 + ell_M + k_s + n_c + ell_m + ell_r + 1 + n_c
            rows_show = L_show * N / s_sw
            hide_sec = _sec(c, "hiding_log2_rop")
            bind_sec = _sec(c, "binding_log2_rop")
            sig_sec = _sec(s, "sig_log2_rop")
            ntru_sec = _sec(ntru, "ntru_log2_rop")
            sec_values = [x for x in [hide_sec, bind_sec, sig_sec, ntru_sec] if x is not None]
            min_sec = min(sec_values) if len(sec_values) == 4 else None

            reasons: list[str] = []
            if not _accepted(c):
                reasons.append("commitment rejected")
                if c.get("rejection_reason"):
                    reasons.append(c["rejection_reason"])
            if not _accepted(s):
                reasons.append("signature rejected")
                if s.get("rejection_reason"):
                    reasons.append(s["rejection_reason"])
            if not _accepted(ntru):
                reasons.append("NTRU rejected")
                if ntru.get("rejection_reason"):
                    reasons.append(ntru["rejection_reason"])
            for label, sec in [
                ("commitment hiding", hide_sec),
                ("commitment binding", bind_sec),
                ("signature SIS", sig_sec),
                ("NTRU", ntru_sec),
            ]:
                if sec is None:
                    reasons.append(f"{label} security unavailable")
                elif sec < min_bits:
                    reasons.append(f"{label} below target")
            all_full = c.get("mode") == "full" and s.get("mode") == "full" and ntru.get("mode") == "full"
            if not all_full:
                reasons.append("only rough-mode estimate available")
            if not q_over_2_gt_gamma:
                reasons.append("q/2 <= gamma")
            if not beta_sig_lt_q:
                reasons.append("beta_sig >= q")
            if not beta_prime_lt_q:
                reasons.append("beta_prime >= q")
            if int(c.get("range_degree", "0") or "0") > 65:
                reasons.append("range degree requires decomposition")
            notes = []
            if n_c != 1:
                notes.append("non-primary: target-dimension expansion required")
                if not allow_target_expansion:
                    reasons.append("n_c != 1 target-dimension expansion required")
            if c.get("range_grade"):
                notes.append(f"range: {c['range_grade']}")
            if x1_failure > 2**-64:
                notes.append("x1 invertibility failure is non-negligible; carry as admissibility error")

            rows.append(
                {
                    "N": N,
                    "q": q,
                    "log2_q": c.get("log2_q", ""),
                    "B_profile": c.get("B_profile", ""),
                    "B": B,
                    "ell_M": ell_M,
                    "k_s": k_s,
                    "n_c": n_c,
                    "ell_m": ell_m,
                    "ell_r": ell_r,
                    "alpha": alpha,
                    "commit_mode": c.get("mode", ""),
                    "sig_mode": s.get("mode", ""),
                    "ntru_mode": ntru.get("mode", ""),
                    "all_full": str(all_full).lower(),
                    "commit_hide_sec": hide_sec,
                    "commit_bind_sec": bind_sec,
                    "sig_sec": sig_sec,
                    "ntru_sec": ntru_sec,
                    "min_sec": min_sec,
                    "gamma": gamma,
                    "beta_sig": beta_sig,
                    "beta_prime": beta_prime,
                    "q_over_2_gt_gamma": str(q_over_2_gt_gamma).lower(),
                    "beta_sig_lt_q": str(beta_sig_lt_q).lower(),
                    "beta_prime_lt_q": str(beta_prime_lt_q).lower(),
                    "beta_prime_lt_q2": str(beta_prime_lt_q2).lower(),
                    "x1_inv_prob": x1_prob,
                    "x1_inv_failure": x1_failure,
                    "L_presign": L_presign,
                    "rows_presign": rows_presign,
                    "L_show": L_show,
                    "rows_show": rows_show,
                    "range_degree": c.get("range_degree", ""),
                    "range_grade": c.get("range_grade", ""),
                    "combined_accepted": bool_text(len(reasons) == 0),
                    "rejection_reason": "; ".join(dict.fromkeys(reasons)),
                    "notes": "; ".join(notes),
                }
            )

    rows.sort(
        key=lambda row: (
            0 if row["combined_accepted"] == "yes" else 1,
            0 if int(row["n_c"]) == 1 else 1,
            float(row["rows_show"]),
            float(row["rows_presign"]),
            int(row["q"]),
            float(row["beta_sig"]),
            -(float(row["min_sec"]) if row["min_sec"] not in (None, "") else -1.0),
        )
    )
    return rows


def rejection_counter(rows: list[dict[str, Any]]) -> Counter[str]:
    counter: Counter[str] = Counter()
    for row in rows:
        if row.get("combined_accepted") == "yes":
            continue
        for part in str(row.get("rejection_reason", "")).split(";"):
            reason = part.strip()
            if reason:
                counter[reason] += 1
    return counter


def run_combine(args: argparse.Namespace) -> list[dict[str, Any]]:
    commitment_rows = read_csv(args.commitment_csv)
    signature_rows = read_csv(args.signature_csv)
    ntru_rows = read_csv(args.ntru_csv)
    rows: list[dict[str, Any]] = []
    for N in args.Ns:
        rows.extend(
            combine_rows(
                commitment_rows,
                signature_rows,
                ntru_rows,
                N,
                min_bits=args.min_bits,
                s_sw=args.s_sw,
                allow_target_expansion=args.allow_target_expansion,
            )
        )
    write_csv(args.output, rows, COMBINED_FIELDS)
    return rows


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Combine ARC-SPRUCE parameter candidates.")
    parser.add_argument("--commitment-csv", required=True)
    parser.add_argument("--signature-csv", required=True)
    parser.add_argument("--ntru-csv", required=True)
    parser.add_argument("--Ns", type=int, nargs="+", default=[256, 512])
    parser.add_argument("--min-bits", type=float, default=128.0)
    parser.add_argument("--s-sw", type=int, default=16)
    parser.add_argument("--allow-target-expansion", action="store_true")
    parser.add_argument("--output", default="parameter_search/results/combined.csv")
    return parser.parse_args(argv)


if __name__ == "__main__":
    run_combine(parse_args())
