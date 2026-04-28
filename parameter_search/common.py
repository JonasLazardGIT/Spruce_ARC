#!/usr/bin/env python
from __future__ import annotations

import csv
import itertools
import math
from contextlib import contextmanager
import io
import os
import sys
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple

from sage.all import RR, oo, pi, sqrt, floor, log, randint, is_prime


@dataclass
class EstimatorResult:
    attack: str
    log2_rop: Optional[float]
    log2_red: Optional[float]
    log2_mem: Optional[float]
    beta: Optional[float]
    d: Optional[int]
    bkz_beta: Optional[float]
    tag: Optional[str]
    raw: dict


@contextmanager
def _suppress_stdout_stderr():
    stream = io.StringIO()
    old_stdout, old_stderr = sys.stdout, sys.stderr
    sys.stdout = stream
    sys.stderr = stream
    try:
        yield
    finally:
        sys.stdout = old_stdout
        sys.stderr = old_stderr


def estimator_call_silent(fn, *args, **kwargs):
    with _suppress_stdout_stderr():
        return fn(*args, **kwargs)


def ensure_path(path: str) -> str:
    path = os.path.abspath(os.path.expanduser(path))
    if os.path.isdir(path) and path not in sys.path:
        sys.path.insert(0, path)
    return path


def load_estimator_modules(estimator_path: Optional[str] = None):
    if estimator_path is None:
        estimator_path = os.path.abspath('/tmp/lattice-estimator-dklw')
    estimator_path = ensure_path(estimator_path)
    from estimator import LWE, SIS, NTRU, ND
    from sage.all import oo, sqrt, pi
    return LWE, SIS, NTRU, ND, oo, sqrt, pi


def safe_float_log2(value) -> Optional[float]:
    if value is None:
        return None
    if value == oo:
        return None
    try:
        return float(RR(value).log(2))
    except Exception:
        try:
            return float(log(value, 2))
        except Exception:
            return None


def estimate_to_entry_dict(estimator_raw, include_attack_name: Optional[str] = None) -> List[EstimatorResult]:
    entries = []
    if not estimator_raw:
        return entries

    for attack_name, attack_res in estimator_raw.items():
        if not hasattr(attack_res, 'get'):
            continue
        rop = attack_res.get('rop')
        red = attack_res.get('red')
        mem = attack_res.get('mem')
        beta = attack_res.get('beta') or attack_res.get('β')
        d = attack_res.get('d')
        tag = attack_res.get('tag')

        entries.append(
            EstimatorResult(
                attack=include_attack_name or attack_name,
                log2_rop=safe_float_log2(rop),
                log2_red=safe_float_log2(red),
                log2_mem=safe_float_log2(mem),
                beta=float(beta) if beta not in (None, oo) else None,
                d=int(d) if d not in (None, oo) else None,
                bkz_beta=float(attack_res.get('beta') or attack_res.get('η') or 0.0)
                if attack_res.get('beta') not in (None, oo)
                else None,
                tag=tag,
                raw=attack_res,
            )
        )
    return entries


def best_estimator_entry(entries: List[EstimatorResult]) -> Optional[EstimatorResult]:
    best = None
    for e in entries:
        if e.log2_rop is None:
            continue
        if best is None or e.log2_rop < best.log2_rop:
            best = e
    return best


def _is_rough_prime(q: int) -> bool:
    try:
        return is_prime(int(q))
    except Exception:
        return False


def prime_candidates_for_bits(
    N: int,
    bits_start: int = 12,
    bits_end: int = 30,
    per_bit: int = 2,
    max_delta_steps: int = 2000,
) -> List[int]:
    mod = 2 * N
    candidates = set()
    for bits in range(bits_start, bits_end + 1):
        lower = 1 << (bits - 1)
        upper = (1 << bits) - 1
        center = 1 << bits
        base = center + ((1 - center) % mod)
        found = []

        for k in range(max_delta_steps + 1):
            deltas = [0] if k == 0 else [k, -k]
            for dk in deltas:
                q = int(base + dk * mod)
                if q < lower or q > upper:
                    continue
                if q % mod != 1:
                    continue
                if _is_rough_prime(q):
                    if q not in found:
                        found.append(q)
                    if len(found) >= per_bit:
                        break
            if len(found) >= per_bit:
                break

        candidates.update(found)
    return sorted(candidates)


def full_split_condition(q: int, N: int) -> bool:
    return q % (2 * N) == 1


def log2_int(x: int) -> float:
    return math.log2(x)


def l1_norm_sd(B: int) -> float:
    return math.sqrt(B * (B + 1) / 3)


def to_bool(v: bool) -> str:
    return 'yes' if v else 'no'


def write_csv(path: str, rows: List[dict], fieldnames: List[str]):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, '') for k in fieldnames})
