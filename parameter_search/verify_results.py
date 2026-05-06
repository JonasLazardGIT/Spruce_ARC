#!/usr/bin/env python3
from __future__ import annotations

import argparse
import math
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from common import full_split_condition, read_csv
from distributions import profile_for
from search_signature import dklw_signature_formulas


def _close(a: float, b: float, eps: float = 1e-9) -> bool:
    return abs(a - b) <= eps * max(1.0, abs(a), abs(b))


def run_formula_checks() -> list[str]:
    failures: list[str] = []
    expected_sigmas = {
        "ternary": math.sqrt(2 / 3),
        "3": math.sqrt(4),
        "4": math.sqrt(20 / 3),
        "6": math.sqrt(14),
        "8": math.sqrt(24),
    }
    for label, expected in expected_sigmas.items():
        got = profile_for(label).sigma_B
        if not _close(got, expected):
            failures.append(f"sigma_B {label}: got {got}, expected {expected}")

    for N in [256, 512]:
        if not full_split_condition(1054721, N):
            failures.append(f"1054721 should be fully split for N={N}")
        if full_split_condition(1054722, N):
            failures.append(f"1054722 should not be fully split for N={N}")

    for N in [256, 512]:
        formulas = dklw_signature_formulas(N, 1054721, 1, 2, 1.15, 128)
        if int(formulas["m_sig"]) != 6 * N:
            failures.append(f"m_sig for N={N}: got {formulas['m_sig']}, expected {6*N}")
        eta = math.sqrt(math.log(4 * N * (1 + 2**128)) / math.pi)
        beta = 1.15 * math.sqrt(1054721) * eta * math.sqrt(6 * N)
        if not _close(formulas["beta_sig"], beta):
            failures.append(f"beta_sig formula mismatch for N={N}")

    N = 512
    ell_M = 1
    k_s = 2
    n_c = 1
    if N * k_s != 1024 or N * n_c != 512:
        failures.append("commitment LWE dimension checkpoint failed")
    if N * n_c != 512 or N * (ell_M + k_s + n_c) != 2048:
        failures.append("commitment SIS dimension checkpoint failed")
    L_show = 2 + ell_M + k_s + n_c + 1 + 2 + 1 + n_c
    rows_show = L_show * N / 16
    if L_show != 11 or rows_show != 352:
        failures.append("N=512 showing inventory checkpoint failed")
    L_presign = ell_M + k_s + n_c
    rows_presign = L_presign * N / 16
    if L_presign != 4 or rows_presign != 128:
        failures.append("N=512 presign inventory checkpoint failed")

    N = 256
    k_s = 4
    L_show = 2 + ell_M + k_s + n_c + 1 + 2 + 1 + n_c
    rows_show = L_show * N / 16
    if L_show != 13 or rows_show != 208:
        failures.append("N=256 showing inventory checkpoint failed")
    L_presign = ell_M + k_s + n_c
    rows_presign = L_presign * N / 16
    if L_presign != 6 or rows_presign != 96:
        failures.append("N=256 presign inventory checkpoint failed")
    return failures


def run_results_checks(results_dir: str | None) -> list[str]:
    if not results_dir:
        return []
    path = Path(results_dir)
    failures: list[str] = []
    required = [
        "commitment_N256.csv",
        "commitment_N512.csv",
        "signature_N256.csv",
        "signature_N512.csv",
        "ntru_N256.csv",
        "ntru_N512.csv",
        "combined_N256.csv",
        "combined_N512.csv",
        "accepted_parameters.json",
        "accepted_parameters.md",
        "accepted_parameters.tex",
        "audit_summary.md",
    ]
    for name in required:
        if not (path / name).exists():
            failures.append(f"missing output {name}")
    for name in ["commitment_N256.csv", "commitment_N512.csv", "signature_N256.csv", "signature_N512.csv"]:
        csv_path = path / name
        if not csv_path.exists():
            continue
        rows = read_csv(csv_path)
        for row in rows:
            q = int(row["q"])
            N = int(row["N"])
            if row.get("fully_split") == "true" and not full_split_condition(q, N):
                failures.append(f"{name}: row marked fully split but q%2N != 1")
    return failures


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Verify ARC-SPRUCE parameter-search formulas and output files.")
    parser.add_argument("--results-dir", default=None)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    failures = run_formula_checks() + run_results_checks(args.results_dir)
    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        return 1
    print("verification checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
