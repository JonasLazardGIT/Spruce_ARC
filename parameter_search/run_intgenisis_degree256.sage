#!/usr/bin/env python
from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, os.pardir))
DEFAULT_Q = 1054721


def parse_targets(raw: str) -> list[int]:
    out: list[int] = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        out.append(int(part))
    if not out:
        raise ValueError("at least one target is required")
    return out


def run(cmd: list[str]) -> None:
    print("$ " + " ".join(cmd), flush=True)
    proc = subprocess.run(cmd, cwd=REPO_ROOT, check=False)
    if proc.returncode != 0:
        raise RuntimeError("command failed: " + " ".join(cmd))


def read_csv(path: str) -> list[dict[str, str]]:
    if not os.path.exists(path):
        return []
    with open(path, newline="") as fh:
        return list(csv.DictReader(fh))


def is_yes(value: object) -> bool:
    return str(value).strip().lower() == "yes"


def as_float(value: object, default: float = -1.0) -> float:
    try:
        if value is None or value == "":
            return default
        return float(value)
    except Exception:
        return default


def accepted_qs(rows: list[dict[str, str]], q_key: str = "q") -> set[int]:
    out: set[int] = set()
    for row in rows:
        if not is_yes(row.get("accepted")):
            continue
        try:
            out.add(int(row[q_key]))
        except Exception:
            pass
    return out


def accepted_count(rows: list[dict[str, str]], accepted_key: str = "accepted") -> int:
    return sum(1 for row in rows if is_yes(row.get(accepted_key)))


def top_combined(rows: list[dict[str, str]], limit: int) -> list[dict[str, object]]:
    accepted = [r for r in rows if is_yes(r.get("combined_accepted"))]

    def score(row: dict[str, str]) -> tuple[float, float, int]:
        secs = [
            as_float(row.get("commit_hide_sec")),
            as_float(row.get("commit_bind_sec")),
            as_float(row.get("sig_sec")),
            as_float(row.get("ntru_sec")),
        ]
        min_sec = min([s for s in secs if s >= 0], default=-1.0)
        rows_show = as_float(row.get("rows_show"), 1e18)
        q = int(row.get("q", "0") or "0")
        return (-min_sec, rows_show, q)

    accepted.sort(key=score)
    out: list[dict[str, object]] = []
    for row in accepted[:limit]:
        secs = {
            "commit_hide": as_float(row.get("commit_hide_sec"), 0),
            "commit_bind": as_float(row.get("commit_bind_sec"), 0),
            "signature": as_float(row.get("sig_sec"), 0),
            "ntru": as_float(row.get("ntru_sec"), 0),
        }
        out.append(
            {
                "N": int(row.get("N", "256") or "256"),
                "q": int(row.get("q", "0") or "0"),
                "log2_q": as_float(row.get("log2_q"), 0),
                "ell_M": int(row.get("l_M", "0") or "0"),
                "k_s": int(row.get("k_s", "0") or "0"),
                "n_c": int(row.get("n_c", "0") or "0"),
                "B_live_ternary": 1,
                "B_search": int(row.get("B", "0") or "0"),
                "l_m": int(row.get("l_m", "0") or "0"),
                "l_r": int(row.get("l_r", "0") or "0"),
                "alpha": as_float(row.get("alpha"), 0),
                "security_bits": secs,
                "min_security_bits": min(secs.values()),
                "beta_sig": as_float(row.get("beta_sig"), 0),
                "beta_plus_commitment_gamma": as_float(row.get("beta_prime_expr"), 0),
                "rows_show_estimate": as_float(row.get("rows_show"), 0),
                "range_degree": int(row.get("range_degree", "0") or "0"),
                "ntru_accepted": is_yes(row.get("ntru_accepted")),
            }
        )
    return out


def run_component_searches(args: argparse.Namespace, target: int, target_dir: str, suffix: str, q_values: list[int] | None, run_full: bool) -> dict[str, str]:
    py = sys.executable
    common = [
        "--Ns",
        "256",
        "--min-bits",
        str(float(target)),
        "--estimator-path",
        args.estimator_path,
    ]
    if q_values:
        q_args = ["--q"] + [str(q) for q in q_values]
    else:
        q_args = [
            "--bits-start",
            str(args.bits_start),
            "--bits-end",
            str(args.bits_end),
            "--qs-per-bit",
            str(args.qs_per_bit),
        ]
    commit_csv = os.path.join(target_dir, f"commitment_N256_{suffix}.csv")
    sig_csv = os.path.join(target_dir, f"signature_N256_{suffix}.csv")
    ntru_csv = os.path.join(target_dir, f"ntru_N256_{suffix}.csv")

    commit_cmd = [
        py,
        os.path.join("parameter_search", "search_commitment.sage"),
        *common,
        *q_args,
        "--l-M",
        "1",
        "--k_s",
        "4",
        "--n_c",
        "1",
        "--B",
        "1",
        "--output",
        commit_csv,
        "--write-summary",
    ]
    sig_cmd = [
        py,
        os.path.join("parameter_search", "search_signature.sage"),
        *common,
        *q_args,
        "--l-m",
        "1",
        "2",
        "4",
        "--l-r",
        "2",
        "--output",
        sig_csv,
    ]
    ntru_cmd = [
        py,
        os.path.join("parameter_search", "search_ntru.sage"),
        *common,
        *q_args,
        "--output",
        ntru_csv,
    ]
    if run_full:
        threshold = max(0.0, float(target) - 16.0)
        commit_cmd += ["--run-full", "--full-threshold", f"{threshold:.1f}"]
        sig_cmd += ["--run-full", "--full-threshold", f"{threshold:.1f}"]
        ntru_cmd += ["--run-full"]
    run(commit_cmd)
    run(sig_cmd)
    run(ntru_cmd)
    return {"commitment": commit_csv, "signature": sig_csv, "ntru": ntru_csv}


def combine(paths: dict[str, str], target_dir: str, suffix: str) -> str:
    run(
        [
            sys.executable,
            os.path.join("parameter_search", "combine_candidates.sage"),
            "--commitment-csv",
            paths["commitment"],
            "--signature-csv",
            paths["signature"],
            "--ntru-csv",
            paths["ntru"],
            "--Ns",
            "256",
            "--s-sw",
            "16",
        ]
    )
    combined_src = os.path.join(REPO_ROOT, "parameter_search", "results", "combined_N256.csv")
    combined_dst = os.path.join(target_dir, f"combined_N256_{suffix}.csv")
    if os.path.exists(combined_src):
        shutil.copyfile(combined_src, combined_dst)
    return combined_dst


def suggested_go_flags(target: int) -> dict[str, object]:
    if target <= 96:
        return {
            "preset": "n256-sw96",
            "benchmark_command": "go run ./cmd/issuance benchmark-intgenisis-e2e -preset n256-sw96 -artifact-dir /tmp/intgenisis_n256_sw96 -force -json-out /tmp/intgenisis_n256_sw96.json",
        }
    return {
        "preset": "n256-sw128",
        "benchmark_command": "go run ./cmd/issuance benchmark-intgenisis-e2e -preset n256-sw128 -artifact-dir /tmp/intgenisis_n256_sw128 -force -json-out /tmp/intgenisis_n256_sw128.json",
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run IntGenISIS N=256 parameter-search stages.")
    parser.add_argument("--targets", default="96,128", help="comma-separated target security levels")
    parser.add_argument("--estimator-path", default="/tmp/lattice-estimator-dklw")
    parser.add_argument("--bits-start", type=int, default=12)
    parser.add_argument("--bits-end", type=int, default=24)
    parser.add_argument("--qs-per-bit", type=int, default=2)
    parser.add_argument("--full-top", type=int, default=20, help="rerun full estimators on this many rough frontier q values; 0 disables")
    parser.add_argument("--out-dir", default=os.path.join("parameter_search", "results", "intgenisis_n256"))
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    targets = parse_targets(args.targets)
    os.makedirs(args.out_dir, exist_ok=True)
    summary: dict[str, object] = {
        "version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "N": 256,
        "default_q": DEFAULT_Q,
        "live_ternary_bound": 1,
        "compatibility_public_bound": 8,
        "fully_split_condition": "q % (2*N) == 1",
        "estimator_path": args.estimator_path,
        "targets": {},
    }
    for target in targets:
        target_dir = os.path.join(args.out_dir, f"target_{target}")
        os.makedirs(target_dir, exist_ok=True)
        fixed = run_component_searches(args, target, target_dir, "fixedq_rough", [DEFAULT_Q], False)
        qscan = run_component_searches(args, target, target_dir, "qscan_rough", None, False)
        fixed_combined = combine(fixed, target_dir, "fixedq_rough")
        qscan_combined = combine(qscan, target_dir, "qscan_rough")

        qscan_top = top_combined(read_csv(qscan_combined), max(args.full_top, 1))
        frontier_qs = [int(row["q"]) for row in qscan_top]
        if not frontier_qs:
            frontier_qs = sorted(
                accepted_qs(read_csv(qscan["commitment"]))
                & accepted_qs(read_csv(qscan["signature"]))
                & accepted_qs(read_csv(qscan["ntru"]))
            )
        full_paths = None
        full_combined = None
        if args.full_top > 0 and frontier_qs:
            frontier_qs = frontier_qs[: args.full_top]
            full_paths = run_component_searches(args, target, target_dir, "frontier_full", frontier_qs, True)
            full_combined = combine(full_paths, target_dir, "frontier_full")

        final_combined = full_combined or qscan_combined
        final_rows = read_csv(final_combined)
        target_summary = {
            "target_bits": target,
            "files": {
                "fixed": {**fixed, "combined": fixed_combined},
                "qscan": {**qscan, "combined": qscan_combined},
                "frontier_full": ({**full_paths, "combined": full_combined} if full_paths and full_combined else None),
            },
            "accepted_counts": {
                "fixed_commitment": accepted_count(read_csv(fixed["commitment"])),
                "fixed_signature": accepted_count(read_csv(fixed["signature"])),
                "fixed_ntru": accepted_count(read_csv(fixed["ntru"])),
                "qscan_commitment": accepted_count(read_csv(qscan["commitment"])),
                "qscan_signature": accepted_count(read_csv(qscan["signature"])),
                "qscan_ntru": accepted_count(read_csv(qscan["ntru"])),
                "combined": accepted_count(final_rows, "combined_accepted"),
            },
            "frontier_qs": frontier_qs,
            "top_candidates": top_combined(final_rows, 10),
            "suggested_go": suggested_go_flags(target),
            "notes": [
                "Commitment search is restricted to the live N=256 profile tuple ell_M=1,k_s=4,n_c=1 and B=1.",
                "The Go profile still records compatibility B=8 in public params; live M/s/e/key proof membership is ternary_v1.",
                "Promote an N=256 preset only after Go e2e issuance, showing, presentation verification, and replay rejection pass.",
            ],
        }
        summary["targets"][str(target)] = target_summary

    summary_path = os.path.join(args.out_dir, "intgenisis_n256_summary.json")
    with open(summary_path, "w") as fh:
        json.dump(summary, fh, indent=2, sort_keys=True)
        fh.write("\n")
    print(f"wrote {summary_path}")


if __name__ == "__main__":
    main()
