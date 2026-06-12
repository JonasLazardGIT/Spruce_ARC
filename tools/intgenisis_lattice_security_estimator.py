#!/usr/bin/env python3
"""Estimate implementation-aligned IntGenISIS lattice security surfaces.

The script models the parts that malb's lattice-estimator can represent:

* Ajtai/MLWE commitment hiding and MSIS binding for c = C_M*M + A_s*s + e.
* NTRU/vSIS short-preimage security for the public signature equation A*u = T.
* A bounded-linear surrogate for h_tran collision resistance.

The live h_tran sampler uses uniform R_q witnesses for mu_sig, x0, and x1, and
the inverse witness Z is not range-bounded. Therefore the h_tran section is
reported as a surrogate only, not as a valid current reduction.
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
        "preset_surface": "n512-compact96",
        "N": 512,
        "q": 1017857,
        "ell_M": 1,
        "k_s": 2,
        "n_c": 1,
        "ordinary_message_bound": 1,
        "prf_seed_bound": 4,
        "commitment_bound": 1,
        "prf_seed_len": 48,
        "semantic_tail_reserve": 64,
        "ell_mu_sig": 1,
        "ell_x0": 2,
        "ell_x1": 1,
        "ntru_beta": 6002,
        "mlwe_bits_recorded": 131.113,
        "mlwe_attack_recorded": "dual_hybrid",
        "msis_bits_recorded": 0,
        "msis_infinite_recorded": True,
    },
    {
        "name": "intgenisis_profile_c",
        "preset_surface": "n1024-compact96, n1024-compact125",
        "N": 1024,
        "q": 1017857,
        "ell_M": 1,
        "k_s": 1,
        "n_c": 1,
        "ordinary_message_bound": 1,
        "prf_seed_bound": 4,
        "commitment_bound": 1,
        "prf_seed_len": 48,
        "semantic_tail_reserve": 64,
        "ell_mu_sig": 1,
        "ell_x0": 1,
        "ell_x1": 1,
        "ntru_beta": 6142,
        "mlwe_bits_recorded": 131.113,
        "mlwe_attack_recorded": "dual_hybrid",
        "msis_bits_recorded": 0,
        "msis_infinite_recorded": True,
    },
]

SECURITY_LAMBDA = 128
DEFAULT_C_SMOOTHING = 1.32
ANTRAG_ALPHA = 1.25
ANTRAG_SLACK = 1.042
LEGACY_SEED_BOUND = 7


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--estimator-path",
        default="",
        help="path containing the estimator Python package; defaults to SPRUCE_LATTICE_ESTIMATOR",
    )
    parser.add_argument("--pretty", action="store_true", help="pretty-print JSON")
    return parser.parse_args()


def resolve_estimator_path(raw_path: str) -> Path:
    path_text = raw_path or os.environ.get("SPRUCE_LATTICE_ESTIMATOR", "")
    if path_text == "":
        raise SystemExit(
            "missing estimator checkout; pass --estimator-path or set "
            "SPRUCE_LATTICE_ESTIMATOR to a pinned malb/lattice-estimator checkout"
        )
    path = Path(path_text).resolve()
    if not (path / "estimator").is_dir():
        raise SystemExit(f"{path} does not contain the estimator Python package")
    return path


def estimator_commit(path: Path) -> str:
    try:
        return subprocess.check_output(
            ["git", "-C", str(path), "rev-parse", "HEAD"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        return ""


def log2_value(value, oo) -> float | str:
    if value == oo or str(value) in {"+Infinity", "Infinity", "inf"}:
        return "inf"
    as_float = float(value)
    if math.isinf(as_float):
        return "inf"
    return round(float(math.log(as_float, 2)), 3)


def summarize_estimate(result, oo) -> dict:
    entries = []
    for attack, cost in result.items():
        entries.append(
            {
                "attack": attack,
                "log2_rop": log2_value(cost.get("rop"), oo),
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
    b = profile["commitment_bound"]
    randomness = n * (k_s + n_c) * math.log2(2 * b + 1)
    required = n * n_c * math.log2(q) + 2 * SECURITY_LAMBDA
    return randomness - required


def statistical_binding_slack(profile: dict) -> float:
    n = profile["N"]
    q = profile["q"]
    n_c = profile["n_c"]
    codomain = n * n_c * math.log2(q)
    diff_space = binding_diff_space_bits(profile)
    return codomain - diff_space


def commitment_binding_l2_bound(profile: dict) -> float:
    n = profile["N"]
    ordinary_coeffs = n - profile["semantic_tail_reserve"]
    seed_coeffs = profile["prf_seed_len"]
    se_coeffs = n * (profile["k_s"] + profile["n_c"])
    ordinary = 2 * profile["ordinary_message_bound"]
    seed = 2 * profile["prf_seed_bound"]
    se = 2 * profile["commitment_bound"]
    return math.sqrt(
        ordinary_coeffs * ordinary * ordinary
        + seed_coeffs * seed * seed
        + se_coeffs * se * se
    )


def commitment_binding_linf_bound(profile: dict) -> int:
    return max(
        2 * profile["ordinary_message_bound"],
        2 * profile["prf_seed_bound"],
        2 * profile["commitment_bound"],
    )


def binding_diff_space_bits(profile: dict) -> float:
    n = profile["N"]
    ordinary_coeffs = n - profile["semantic_tail_reserve"]
    seed_coeffs = profile["prf_seed_len"]
    se_coeffs = n * (profile["k_s"] + profile["n_c"])
    return (
        ordinary_coeffs * math.log2(4 * profile["ordinary_message_bound"] + 1)
        + seed_coeffs * math.log2(4 * profile["prf_seed_bound"] + 1)
        + se_coeffs * math.log2(4 * profile["commitment_bound"] + 1)
    )


def ntru_c_l2_bound(profile: dict) -> float:
    n = profile["N"]
    q = profile["q"]
    return math.sqrt(
        2
        * n
        * (DEFAULT_C_SMOOTHING**2)
        * (ANTRAG_ALPHA**2)
        * q
        * (ANTRAG_SLACK**2)
    )


def ntru_default_linf_bound(profile: dict) -> float:
    q = profile["q"]
    return 4 * ANTRAG_SLACK * math.sqrt((DEFAULT_C_SMOOTHING**2) * (ANTRAG_ALPHA**2) * q)


def main() -> int:
    args = parse_args()
    estimator_path = resolve_estimator_path(args.estimator_path)
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
        b = profile["commitment_bound"]
        distribution = ND.Uniform(-b, b)

        lwe = LWE.Parameters(n=n * k_s, q=q, Xs=distribution, Xe=distribution, m=n * n_c)
        bind_len = ell_m + k_s + n_c
        commitment_l2 = SIS.Parameters(
            n=n * n_c,
            q=q,
            length_bound=float(commitment_binding_l2_bound(profile)),
            m=n * bind_len,
            norm=2,
            tag=f"{profile['name']}-commitment-msis-l2",
        )
        commitment_inf = SIS.Parameters(
            n=n * n_c,
            q=q,
            length_bound=commitment_binding_linf_bound(profile),
            m=n * bind_len,
            norm=oo,
            tag=f"{profile['name']}-commitment-msis-inf",
        )

        signature_linf = SIS.Parameters(
            n=n,
            q=q,
            length_bound=float(profile["ntru_beta"]),
            m=2 * n,
            norm=oo,
            tag=f"{profile['name']}-ntru-vsis-linf-beta",
        )
        signature_l2 = SIS.Parameters(
            n=n,
            q=q,
            length_bound=float(ntru_c_l2_bound(profile)),
            m=2 * n,
            norm=2,
            tag=f"{profile['name']}-ntru-vsis-cstyle-l2",
        )

        htran_rows = profile["ell_mu_sig"] + profile["ell_x0"] + 1
        htran_delta = 2 * LEGACY_SEED_BOUND
        htran_linf = SIS.Parameters(
            n=n,
            q=q,
            length_bound=htran_delta,
            m=htran_rows * n,
            norm=oo,
            tag=f"{profile['name']}-htran-linear-surrogate-linf",
        )
        htran_l2 = SIS.Parameters(
            n=n,
            q=q,
            length_bound=float(htran_delta * sqrt(htran_rows * n)),
            m=htran_rows * n,
            norm=2,
            tag=f"{profile['name']}-htran-linear-surrogate-l2",
        )

        estimates.append(
            {
                "profile": profile,
                "commitment": {
                    "mlwe_hiding": summarize_estimate(LWE.estimate.rough(lwe, quiet=True), oo),
                    "msis_binding_l2": summarize_estimate(SIS.estimate.rough(commitment_l2, quiet=True), oo),
                    "msis_binding_inf": summarize_estimate(SIS.estimate.rough(commitment_inf, quiet=True), oo),
                    "binding_l2_bound": round(commitment_binding_l2_bound(profile), 3),
                    "binding_linf_bound": commitment_binding_linf_bound(profile),
                    "binding_diff_space_bits": round(binding_diff_space_bits(profile), 3),
                    "statistical_hiding_satisfied": statistical_hiding_slack(profile) >= 0,
                    "statistical_hiding_slack_bits": round(statistical_hiding_slack(profile), 3),
                    "statistical_binding_slack_bits": round(statistical_binding_slack(profile), 3),
                },
                "ntru_vsis_signature": {
                    "model": "SIS/ISIS surrogate for A*u=T with A in R_q^{1x2}; estimates ignore trapdoor leakage and model short-preimage hardness only.",
                    "linf_beta": profile["ntru_beta"],
                    "cstyle_l2_bound": round(ntru_c_l2_bound(profile), 3),
                    "default_residual_linf_bound": round(ntru_default_linf_bound(profile), 3),
                    "sis_linf_beta": summarize_estimate(SIS.estimate.rough(signature_linf, quiet=True), oo),
                    "sis_l2_cstyle": summarize_estimate(SIS.estimate.rough(signature_l2, quiet=True), oo),
                },
                "h_tran": {
                    "current_sampler": "mu_sig, x0, x1 sampled uniformly over R_q; Z=(B3-x1)^(-1) is not range-bounded",
                    "estimator_applicability": "no direct lattice-estimator SIS/vSIS model for the live rational inverse relation with unbounded Z",
                    "bounded_linear_surrogate": {
                        "warning": "not a proof of live h_tran security; assumes bounded deltas for mu_sig, x0, and Z with |delta|<=14",
                        "rows": htran_rows,
                        "delta_bound": htran_delta,
                        "sis_linf": summarize_estimate(SIS.estimate.rough(htran_linf, quiet=True), oo),
                        "sis_l2": summarize_estimate(SIS.estimate.rough(htran_l2, quiet=True), oo),
                    },
                },
            }
        )

    output = {
        "estimator": {
            "path": str(estimator_path),
            "commit": estimator_commit(estimator_path),
            "mode": "rough",
        },
        "assumptions": {
            "security_lambda": SECURITY_LAMBDA,
            "ntru_c_smoothing": DEFAULT_C_SMOOTHING,
            "ntru_alpha": ANTRAG_ALPHA,
            "ntru_slack": ANTRAG_SLACK,
            "htran_surrogate_seed_bound": LEGACY_SEED_BOUND,
        },
        "estimates": estimates,
    }
    print(json.dumps(output, indent=2 if args.pretty else None, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
