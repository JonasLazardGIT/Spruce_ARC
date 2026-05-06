#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import math
import sys
from collections import Counter
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from combine_candidates import COMBINED_FIELDS, rejection_counter, run_combine
from common import (
    DEFAULT_ESTIMATOR_PATH,
    command_text,
    parse_float,
    read_csv,
    require_sage_python_hint,
    results_path,
    runtime_summary,
    run_cmd,
    setup_estimator,
    write_csv,
    write_estimator_commit,
    write_json,
)
from distributions import B_PROFILE_ORDER, distribution_report_rows, parse_bound_profiles
from search_commitment import run_search as run_commitment
from search_ntru import run_search as run_ntru
from search_signature import run_search as run_signature
from verify_results import run_formula_checks


def _component_namespace(
    args: argparse.Namespace,
    N: int,
    output: Path,
    component: str,
    estimator_commit: str,
    run_full: bool | None = None,
) -> argparse.Namespace:
    common = {
        "Ns": [N],
        "bits_start": args.bits_start,
        "bits_end": args.bits_end,
        "qs_per_bit": args.qs_per_bit,
        "max_delta_steps": args.max_delta_steps,
        "q": args.q,
        "min_bits": args.min_bits,
        "run_rough": args.run_rough,
        "run_full": args.run_full if run_full is None else run_full,
        "require_fully_split": args.require_fully_split,
        "estimator_path": args.estimator_path,
        "estimator_commit": estimator_commit,
        "output": str(output),
    }
    if component == "commitment":
        common.update(
            {
                "bounds": args.bounds,
                "ell_M": [args.ell_M],
                "k_s": args.k_s,
                "n_c": args.n_c,
                "s_sw": args.s_sw,
            }
        )
    elif component == "signature":
        common.update(
            {
                "ell_m": [args.ell_m],
                "ell_r": [args.ell_r],
                "alpha": args.alpha,
                "lambda_bits": args.lambda_bits,
            }
        )
    elif component == "ntru":
        common.update({"alpha": args.alpha, "lambda_bits": args.lambda_bits})
    else:
        raise ValueError(component)
    return argparse.Namespace(**common)


def _equivalent_command(args: argparse.Namespace, component: str, N: int, output: Path, run_full: bool | None = None) -> list[str]:
    script = {
        "commitment": "search_commitment.py",
        "signature": "search_signature.py",
        "ntru": "search_ntru.py",
    }[component]
    cmd = [
        "python3",
        f"parameter_search/{script}",
        "--Ns",
        str(N),
        "--estimator-path",
        args.estimator_path,
        "--min-bits",
        str(args.min_bits),
        "--bits-start",
        str(args.bits_start),
        "--bits-end",
        str(args.bits_end),
        "--qs-per-bit",
        str(args.qs_per_bit),
        "--output",
        str(output),
    ]
    if args.q:
        cmd = [
            "python3",
            f"parameter_search/{script}",
            "--Ns",
            str(N),
            "--estimator-path",
            args.estimator_path,
            "--min-bits",
            str(args.min_bits),
            "--q",
            *[str(q) for q in args.q],
            "--output",
            str(output),
        ]
    if args.run_rough:
        cmd.append("--run-rough")
    effective_run_full = args.run_full if run_full is None else run_full
    if effective_run_full:
        cmd.append("--run-full")
    if component == "commitment":
        cmd.extend(["--bounds", *args.bounds, "--ell-M", str(args.ell_M), "--k-s", *[str(x) for x in args.k_s], "--n-c", *[str(x) for x in args.n_c]])
    if component == "signature":
        cmd.extend(["--ell-m", str(args.ell_m), "--ell-r", str(args.ell_r), "--alpha", *[str(x) for x in args.alpha]])
    if component == "ntru":
        cmd.extend(["--alpha", *[str(x) for x in args.alpha]])
    return cmd


def _row_score(row: dict[str, str]) -> tuple[Any, ...]:
    min_sec = parse_float(row.get("min_sec")) or -1.0
    return (
        0 if row.get("combined_accepted") == "yes" else 1,
        0 if int(row.get("n_c", "0") or "0") == 1 else 1,
        parse_float(row.get("rows_show")) or 1e100,
        parse_float(row.get("rows_presign")) or 1e100,
        int(row.get("q", "0") or "0"),
        parse_float(row.get("beta_sig")) or 1e100,
        -min_sec,
    )


def _frontier_score(row: dict[str, str]) -> tuple[Any, ...]:
    min_sec = parse_float(row.get("min_sec")) or -1.0
    component_count = sum(1 for key in ["commit_hide_sec", "commit_bind_sec", "sig_sec", "ntru_sec"] if parse_float(row.get(key)) is not None)
    component_ok = sum(
        1
        for key in ["commit_hide_sec", "commit_bind_sec", "sig_sec", "ntru_sec"]
        if (parse_float(row.get(key)) or -1.0) >= 128.0
    )
    full_count = sum(1 for key in ["commit_mode", "sig_mode", "ntru_mode"] if row.get(key) == "full")
    return (
        -component_ok,
        -full_count,
        -component_count,
        -min_sec,
        0 if int(row.get("n_c", "0") or "0") == 1 else 1,
        parse_float(row.get("rows_show")) or 1e100,
        int(row.get("q", "0") or "0"),
    )


def _summarize_candidate(row: dict[str, str]) -> dict[str, Any]:
    keys = [
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
        "commit_hide_sec",
        "commit_bind_sec",
        "sig_sec",
        "ntru_sec",
        "min_sec",
        "gamma",
        "beta_sig",
        "beta_prime",
        "x1_inv_failure",
        "L_presign",
        "rows_presign",
        "L_show",
        "rows_show",
        "rejection_reason",
        "notes",
    ]
    return {key: row.get(key, "") for key in keys}


def build_accepted_summary(args: argparse.Namespace, output_dir: Path, combined_by_N: dict[int, list[dict[str, str]]], setup: Any) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "estimator": {
            "path": setup.path,
            "commit": setup.commit,
            "requested_ref": setup.requested_ref,
            "checkout_ok": setup.checkout_ok,
            "messages": setup.messages,
        },
        "runtime": runtime_summary(),
        "selection_objectives": [
            "full-mode security components >= target",
            "n_c = 1 preferred",
            "smallest rows_show",
            "smallest rows_presign",
            "smallest q",
            "smallest beta_sig",
            "highest min_sec tie-breaker",
        ],
        "cells": {},
    }
    profiles = [p.profile for p in parse_bound_profiles(args.bounds)]
    for N in args.Ns:
        n_key = str(N)
        summary["cells"][n_key] = {}
        rows = combined_by_N.get(N, [])
        for profile in profiles:
            profile_rows = [r for r in rows if r.get("B_profile") == profile]
            accepted = [r for r in profile_rows if r.get("combined_accepted") == "yes"]
            if accepted:
                accepted.sort(key=_row_score)
                summary["cells"][n_key][profile] = {
                    "status": "accepted",
                    "candidate": _summarize_candidate(accepted[0]),
                }
            else:
                profile_rows.sort(key=_frontier_score)
                summary["cells"][n_key][profile] = {
                    "status": "no accepted candidate found",
                    "frontier": _summarize_candidate(profile_rows[0]) if profile_rows else {},
                }
    write_json(output_dir / "accepted_parameters.json", summary)
    return summary


def write_markdown_report(
    args: argparse.Namespace,
    output_dir: Path,
    setup: Any,
    commands: list[list[str]],
    summary: dict[str, Any],
    combined_by_N: dict[int, list[dict[str, str]]],
) -> None:
    all_rows = [row for rows in combined_by_N.values() for row in rows]
    counter = rejection_counter(all_rows)
    lines: list[str] = []
    lines.append("# ARC-SPRUCE Parameter Search Report")
    lines.append("")
    lines.append("## Estimator Setup")
    lines.append(f"- estimator path: `{setup.path}`")
    lines.append(f"- estimator commit: `{setup.commit}`")
    lines.append(f"- requested ref: `{setup.requested_ref or ''}`")
    old_ref = run_cmd(["git", "-C", setup.path, "cat-file", "-e", "162c5053^{commit}"])
    lines.append(f"- DKLW-compatible ref `162c5053` present: `{str(old_ref.returncode == 0).lower()}`")
    lines.append(f"- Sage version: `{runtime_summary()['sage']}`")
    lines.append(f"- Python version: `{runtime_summary()['python']}`")
    lines.append(f"- invocation note: {require_sage_python_hint()}")
    lines.append("")
    lines.append("Commands used/equivalent:")
    lines.append("```sh")
    for cmd in commands:
        lines.append(command_text(cmd))
    lines.append("```")
    lines.append("")
    lines.append("## Distribution Profiles")
    lines.append("| profile | B | distribution | support | sigma_B |")
    lines.append("|---|---:|---|---|---:|")
    for row in distribution_report_rows():
        if row["B_profile"] in [p.profile for p in parse_bound_profiles(args.bounds)]:
            lines.append(f"| {row['B_profile']} | {row['B']} | {row['distribution']} | `{row['support']}` | {row['sigma_B']} |")
    lines.append("")
    lines.append("## Search Space")
    q_desc = "explicit q = " + ", ".join(str(q) for q in args.q) if args.q else f"bits {args.bits_start}..{args.bits_end}, {args.qs_per_bit} q/bit"
    lines.append(f"- N: `{args.Ns}`")
    lines.append(f"- q: {q_desc}; condition `q % (2*N) == 1`")
    lines.append(f"- bounds: `{args.bounds}`")
    lines.append(f"- k_s grid: `{args.k_s}`")
    lines.append(f"- n_c grid: `{args.n_c}`")
    lines.append(f"- alpha grid: `{args.alpha}`")
    lines.append(f"- modes: rough={args.run_rough or args.run_full or not args.run_full}, full={args.run_full}")
    lines.append("- confirmation policy: downstream full estimates are run only for N/q/alpha branches with signature rough survivors; no combined candidate can survive otherwise.")
    lines.append("")
    lines.append("## Formula Summary")
    lines.append("- MLWE hiding: `n_LWE=N*k_s`, `m_LWE=N*n_c`, `Xs=Xe=profile distribution`.")
    lines.append("- MSIS binding: `n_SIS=N*n_c`, `m_SIS=N*(ell_M+k_s+n_c)`, bounds `2B` and `2B*sqrt(N*L_bind)`.")
    lines.append("- DKLW: `eta=sqrt(log(4*N*(1+2^lambda))/pi)`, `s_trap=alpha*sqrt(q)*eta`, `beta_sig=s_trap*sqrt(N*(3+ell_m+ell_r))`.")
    lines.append("- NTRU: `NTRU.Parameters(n=N,q=q,Xs=Xe=DiscreteGaussian(s_trap))`.")
    lines.append("- IntGenISIS side: `gamma=B*sqrt(N*(ell_M+k_s+n_c))`, `beta_prime=beta_sig+gamma`.")
    lines.append("")
    lines.append("## Accepted Parameter Table")
    any_accepted = False
    lines.append("| N | B profile | status | q | k_s | alpha | min sec | rows show | reason |")
    lines.append("|---:|---|---|---:|---:|---:|---:|---:|---|")
    for N in args.Ns:
        for profile in [p.profile for p in parse_bound_profiles(args.bounds)]:
            cell = summary["cells"][str(N)][profile]
            if cell["status"] == "accepted":
                any_accepted = True
                c = cell["candidate"]
                lines.append(
                    f"| {N} | {profile} | accepted | {c['q']} | {c['k_s']} | {c['alpha']} | {c['min_sec']} | {c['rows_show']} |  |"
                )
            else:
                f = cell.get("frontier", {})
                reason = str(f.get("rejection_reason", "none found in searched range")).replace("|", "/")
                lines.append(f"| {N} | {profile} | none found in searched range | {f.get('q','')} | {f.get('k_s','')} | {f.get('alpha','')} | {f.get('min_sec','')} | {f.get('rows_show','')} | {reason} |")
    if not any_accepted:
        lines.append("")
        lines.append("No full-mode accepted ARC-SPRUCE combined parameter set found in searched range.")
    lines.append("")
    lines.append("## Rejection Summary")
    if counter:
        for reason, count in counter.most_common(12):
            lines.append(f"- {reason}: {count}")
    else:
        lines.append("- no rejected combined rows")
    qscan_lines = _signature_qscan_notes(output_dir)
    if qscan_lines:
        lines.append("")
        lines.append("## Signature Q-Scan")
        lines.extend(qscan_lines)
    lines.append("")
    lines.append("## Paper Alignment Notes")
    lines.extend(_paper_alignment_notes(output_dir))
    lines.append("")
    lines.append("## Caveats")
    lines.append("- lattice-estimator outputs are heuristic concrete attack estimates.")
    lines.append("- module-to-LWE/SIS expansion is an estimator model.")
    lines.append("- NTRU/trapdoor admissibility is not proven by estimator output alone.")
    lines.append("- SmallWood rows are inventory arithmetic only; final proof sizes require rerunning optimizer.")
    (output_dir / "accepted_parameters.md").write_text("\n".join(lines) + "\n")


def _paper_alignment_notes(output_dir: Path) -> list[str]:
    notes: list[str] = []
    path = output_dir / "commitment_N512.csv"
    if path.exists():
        rows = read_csv(path)
        target = [
            r
            for r in rows
            if r.get("q") == "1054721"
            and r.get("B_profile") == "8"
            and r.get("ell_M") == "1"
            and r.get("k_s") == "2"
            and r.get("n_c") == "1"
        ]
        full = [r for r in target if r.get("mode") == "full"]
        row = full[0] if full else (target[0] if target else None)
        if row:
            notes.append(
                f"- N=512/B=8 paper checkpoint row present in `{row.get('mode')}` mode: "
                f"hiding={row.get('hiding_log2_rop')}, binding={row.get('binding_log2_rop')}."
            )
            notes.append("- Deviations from paper values should be attributed to estimator commit/mode/distribution/norm choices noted in CSV.")
        else:
            notes.append("- N=512/B=8/q=1054721/k_s=2 checkpoint not present in this run.")
    notes.append("- N=256 compact candidate support depends on signature SIS and NTRU rows in combined table.")
    notes.append("- Combined acceptance rejects `n_c != 1` unless target-dimension expansion is explicitly allowed.")
    return notes


def _signature_qscan_notes(output_dir: Path) -> list[str]:
    notes: list[str] = []
    for N in [256, 512]:
        path = output_dir / f"signature_qscan_N{N}.csv"
        if not path.exists():
            continue
        rows = read_csv(path)
        accepted = [r for r in rows if r.get("accepted") == "yes"]
        scored = []
        for row in rows:
            sec = parse_float(row.get("sig_log2_rop"))
            if sec is not None:
                scored.append((sec, row))
        if scored:
            sec, row = max(scored, key=lambda item: item[0])
            notes.append(
                f"- N={N}: rough q-scan rows={len(rows)}, accepted={len(accepted)}, "
                f"max signature SIS={sec:.3f} at q={row.get('q')} alpha={row.get('alpha')}."
            )
        else:
            notes.append(f"- N={N}: rough q-scan rows={len(rows)}, no numeric signature SIS estimate.")
    return notes


def write_tex_table(args: argparse.Namespace, output_dir: Path, summary: dict[str, Any]) -> None:
    lines = [
        "% Generated by parameter_search/run_all.py",
        "\\begin{tabular}{rrrrrrrrr}",
        "\\toprule",
        "$N$ & Profile & $q$ & $k_s$ & $\\alpha$ & min sec & $\\gamma$ & $\\beta_{sig}$ & rows \\\\",
        "\\midrule",
    ]
    count = 0
    for N in args.Ns:
        for profile in [p.profile for p in parse_bound_profiles(args.bounds)]:
            cell = summary["cells"][str(N)][profile]
            if cell["status"] != "accepted":
                continue
            c = cell["candidate"]
            count += 1
            lines.append(
                f"{N} & {profile} & {c['q']} & {c['k_s']} & {c['alpha']} & {c['min_sec']} & {c['gamma']} & {c['beta_sig']} & {c['rows_show']} \\\\"
            )
    if count == 0:
        lines.append("\\multicolumn{9}{l}{none found in searched range} \\\\")
    lines.extend(["\\bottomrule", "\\end{tabular}", ""])
    (output_dir / "accepted_parameters.tex").write_text("\n".join(lines))


def write_audit_summary(output_dir: Path) -> None:
    lines = [
        "# Parameter-Search Audit Summary",
        "",
        "## Sources Checked",
        "- `vSISSig.html`: not present in workspace; search found `vSIS-HASH/vSIS-BBS.go` instead.",
        "- `common.py` / `common.sage`: old shared helper duplicated Sage imports and rough parser assumptions.",
        "- `search_commitment.sage`: stale defaults included broad `ell_M`, no explicit bound-profile labels, rough rows could be accepted.",
        "- `search_signature.sage` / `.py`: DKLW formulas mostly present, but signature size divided by 8 and had unexplained factor 2.",
        "- `search_ntru.sage`: estimated NTRU but did not integrate cleanly into final acceptance.",
        "- `combine_candidates.sage`: contained obsolete `epsilon_stat`/LHL computation and omitted NTRU from `min_sec`.",
        "- `run_all.sage`: invoked `.sage` files with `python3` and wrote placeholder-style paths.",
        "- `run_intgenisis_degree256.sage`: restricted old N=256 probes and kept compatibility/live-bound language outside new profile grid.",
        "",
        "## Formula Corrections",
        "- q handling now uses actual prime q and checks `q % (2*N) == 1`.",
        "- Bound profiles are explicit: `ternary`, `3`, `4`, `6`, `8`; ternary maps to B=1 and `uniform_ternary`.",
        "- Commitment hiding uses MLWE estimator dimensions `N*k_s` by `N*n_c`.",
        "- Commitment binding uses `[C_M|A_s|I]` with both infinity and Euclidean SIS estimates.",
        "- DKLW defaults are `ell_m=1`, `ell_r=2`, hence `m_sig=6N`.",
        "- Signature size is `sig_bits=(2+ell_r)*N*log2(beta_sig)`; bytes/KiB are derived separately.",
        "- Combined acceptance includes MLWE hiding, MSIS binding, DKLW SIS, NTRU, gamma, beta, full-mode, and target-dimension checks.",
        "- Obsolete LHL/statistical target-hiding logic is not used.",
        "",
        "## Estimator Parsing",
        "- Attack, rop, red, mem, beta/block-size, and raw estimator outputs are stored in CSV/JSONL.",
        "- Estimator exceptions are recorded and force rejection/manual-review where relevant.",
        "",
        "## Execution",
        "- New top-level entry point: `parameter_search/run_all.py` under Sage-capable Python.",
        "- Local Sage wrapper supports `python3`; many Sage installs support `sage --python` or `sage -python`.",
    ]
    (output_dir / "audit_summary.md").write_text("\n".join(lines) + "\n")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run reproducible ARC-SPRUCE parameter-generation pipeline.")
    parser.add_argument("--estimator-path", default=DEFAULT_ESTIMATOR_PATH)
    parser.add_argument("--estimator-ref", default=None)
    parser.add_argument("--Ns", type=int, nargs="+", default=[256, 512])
    parser.add_argument("--bounds", nargs="+", default=B_PROFILE_ORDER)
    parser.add_argument("--bits-start", type=int, default=12)
    parser.add_argument("--bits-end", type=int, default=30)
    parser.add_argument("--qs-per-bit", type=int, default=2)
    parser.add_argument("--max-delta-steps", type=int, default=20000)
    parser.add_argument("--q", type=int, nargs="+", default=None)
    parser.add_argument("--min-bits", type=float, default=128.0)
    parser.add_argument("--lambda-bits", type=int, default=128)
    parser.add_argument("--s-sw", type=int, default=16)
    parser.add_argument("--ell-M", type=int, default=1)
    parser.add_argument("--ell-m", type=int, default=1)
    parser.add_argument("--ell-r", type=int, default=2)
    parser.add_argument("--k-s", "--k_s", dest="k_s", type=int, nargs="+", default=[1, 2, 3, 4, 5, 6, 8, 10, 12, 16])
    parser.add_argument("--n-c", "--n_c", dest="n_c", type=int, nargs="+", default=[1, 2, 3, 4, 5, 6, 8])
    parser.add_argument("--alpha", type=float, nargs="+", default=[1.15, 1.17, 1.23, 1.48, 2.04])
    parser.add_argument("--require-fully-split", action="store_true", default=True)
    parser.add_argument("--run-rough", action="store_true")
    parser.add_argument("--run-full", action="store_true")
    parser.add_argument("--jobs", type=int, default=1, help="accepted for future parallel sweeps; current runner is sequential")
    parser.add_argument("--allow-target-expansion", action="store_true")
    parser.add_argument("--output-dir", default="parameter_search/results")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    output_dir = Path(args.output_dir)
    if not output_dir.is_absolute():
        output_dir = Path.cwd() / output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    formula_failures = run_formula_checks()
    if formula_failures:
        for failure in formula_failures:
            print(f"formula check failed: {failure}", file=sys.stderr)
        return 1

    setup = setup_estimator(args.estimator_path, args.estimator_ref)
    write_estimator_commit(setup, output_dir)

    commands: list[list[str]] = [
        [
            "python3",
            "parameter_search/run_all.py",
            "--estimator-path",
            args.estimator_path,
            "--Ns",
            *[str(N) for N in args.Ns],
            "--bounds",
            *args.bounds,
            "--bits-start",
            str(args.bits_start),
            "--bits-end",
            str(args.bits_end),
            "--qs-per-bit",
            str(args.qs_per_bit),
            "--output-dir",
            str(output_dir),
            "--k-s",
            *[str(x) for x in args.k_s],
            "--n-c",
            *[str(x) for x in args.n_c],
            "--alpha",
            *[str(x) for x in args.alpha],
        ]
    ]
    if args.q:
        commands[0].extend(["--q", *[str(q) for q in args.q]])
    if args.run_rough:
        commands[0].append("--run-rough")
    if args.run_full:
        commands[0].append("--run-full")

    combined_by_N: dict[int, list[dict[str, str]]] = {}
    for N in args.Ns:
        commit_out = output_dir / f"commitment_N{N}.csv"
        sig_out = output_dir / f"signature_N{N}.csv"
        ntru_out = output_dir / f"ntru_N{N}.csv"
        commands.append(_equivalent_command(args, "signature", N, sig_out))
        run_signature(_component_namespace(args, N, sig_out, "signature", setup.commit))
        sig_rows = read_csv(sig_out)
        sig_survivor = any(row.get("accepted") == "yes" for row in sig_rows)
        downstream_full = args.run_full and sig_survivor
        commands.append(_equivalent_command(args, "commitment", N, commit_out, run_full=downstream_full))
        run_commitment(_component_namespace(args, N, commit_out, "commitment", setup.commit, run_full=downstream_full))
        commands.append(_equivalent_command(args, "ntru", N, ntru_out, run_full=downstream_full))
        run_ntru(_component_namespace(args, N, ntru_out, "ntru", setup.commit, run_full=downstream_full))
        combined_out = output_dir / f"combined_N{N}.csv"
        combine_args = argparse.Namespace(
            commitment_csv=str(commit_out),
            signature_csv=str(sig_out),
            ntru_csv=str(ntru_out),
            Ns=[N],
            min_bits=args.min_bits,
            s_sw=args.s_sw,
            allow_target_expansion=args.allow_target_expansion,
            output=str(combined_out),
        )
        run_combine(combine_args)
        combined_by_N[N] = read_csv(combined_out)

    summary = build_accepted_summary(args, output_dir, combined_by_N, setup)
    write_markdown_report(args, output_dir, setup, commands, summary, combined_by_N)
    write_tex_table(args, output_dir, summary)
    write_audit_summary(output_dir)
    write_json(output_dir / "runtime_commands.json", {"commands": [command_text(c) for c in commands], "runtime": runtime_summary()})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
