#!/usr/bin/env python3
from __future__ import annotations

import contextlib
import io
import os
import sys
from dataclasses import dataclass
from typing import Any

from common import log2_value, safe_json_obj
from distributions import DistributionProfile


@dataclass
class EstimatorEntry:
    attack: str
    log2_rop: float | None
    log2_red: float | None
    log2_mem: float | None
    beta: float | None
    d: int | None
    bkz_beta: float | None
    tag: str | None
    raw: dict[str, Any]


@dataclass
class EstimateOutcome:
    problem: str
    mode: str
    ok: bool
    entries: list[EstimatorEntry]
    best: EstimatorEntry | None
    raw: Any
    stdout: str
    exception: str | None = None


def load_estimator_modules(estimator_path: str):
    estimator_path = os.path.abspath(os.path.expanduser(estimator_path))
    if estimator_path not in sys.path:
        sys.path.insert(0, estimator_path)
    from estimator import LWE, SIS, NTRU, ND
    from sage.all import oo, pi, sqrt, log

    return LWE, SIS, NTRU, ND, oo, sqrt, pi, log


def estimator_distribution(ND: Any, profile: DistributionProfile):
    if profile.profile == "ternary":
        if hasattr(ND, "Ternary"):
            return ND.Ternary
        return ND.Uniform(-1, 1)
    return ND.Uniform(-profile.B, profile.B)


def _float_or_none(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except Exception:
        return None


def _int_or_none(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except Exception:
        return None


def _raw_dict(value: Any) -> dict[str, Any]:
    if hasattr(value, "items"):
        try:
            return {str(k): safe_json_obj(v) for k, v in value.items()}
        except Exception:
            pass
    return {"repr": str(value)}


def entries_from_raw(raw: Any) -> list[EstimatorEntry]:
    entries: list[EstimatorEntry] = []
    if not raw or not hasattr(raw, "items"):
        return entries
    for attack_name, result in raw.items():
        if not hasattr(result, "get"):
            continue
        raw_entry = _raw_dict(result)
        beta_value = result.get("beta")
        if beta_value is None:
            beta_value = result.get("β")
        d_value = result.get("d")
        bkz_value = result.get("beta")
        if bkz_value is None:
            bkz_value = result.get("β")
        entries.append(
            EstimatorEntry(
                attack=str(attack_name),
                log2_rop=log2_value(result.get("rop")),
                log2_red=log2_value(result.get("red")),
                log2_mem=log2_value(result.get("mem")),
                beta=_float_or_none(beta_value),
                d=_int_or_none(d_value),
                bkz_beta=_float_or_none(bkz_value),
                tag=None if result.get("tag") is None else str(result.get("tag")),
                raw=raw_entry,
            )
        )
    return entries


def best_entry(entries: list[EstimatorEntry]) -> EstimatorEntry | None:
    finite = [entry for entry in entries if entry.log2_rop is not None]
    if not finite:
        return None
    return min(finite, key=lambda entry: entry.log2_rop)


def run_estimator(problem: str, estimate_obj: Any, params: Any, mode: str) -> EstimateOutcome:
    if mode not in {"rough", "full"}:
        raise ValueError(f"unsupported estimator mode {mode}")
    fn = estimate_obj.estimate.rough if mode == "rough" else estimate_obj.estimate
    stream = io.StringIO()
    try:
        with contextlib.redirect_stdout(stream), contextlib.redirect_stderr(stream):
            raw = fn(params)
        entries = entries_from_raw(raw)
        return EstimateOutcome(
            problem=problem,
            mode=mode,
            ok=True,
            entries=entries,
            best=best_entry(entries),
            raw=safe_json_obj(raw),
            stdout=stream.getvalue(),
        )
    except Exception as exc:
        return EstimateOutcome(
            problem=problem,
            mode=mode,
            ok=False,
            entries=[],
            best=None,
            raw=None,
            stdout=stream.getvalue(),
            exception=str(exc),
        )


def entry_columns(prefix: str, entry: EstimatorEntry | None) -> dict[str, Any]:
    if entry is None:
        return {
            f"{prefix}_attack": "",
            f"{prefix}_log2_rop": "",
            f"{prefix}_log2_red": "",
            f"{prefix}_log2_mem": "",
            f"{prefix}_bkz_beta": "",
        }
    return {
        f"{prefix}_attack": entry.attack,
        f"{prefix}_log2_rop": entry.log2_rop,
        f"{prefix}_log2_red": entry.log2_red,
        f"{prefix}_log2_mem": entry.log2_mem,
        f"{prefix}_bkz_beta": entry.bkz_beta if entry.bkz_beta is not None else entry.d,
    }
