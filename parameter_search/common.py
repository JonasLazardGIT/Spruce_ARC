#!/usr/bin/env python3
from __future__ import annotations

import csv
import json
import math
import os
import platform
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable

try:
    from sage.all import RR, is_prime, oo
except Exception:  # pragma: no cover - these scripts are intended for Sage Python.
    RR = None
    oo = math.inf

    def is_prime(n: int) -> bool:
        if n < 2:
            return False
        if n % 2 == 0:
            return n == 2
        d = 3
        while d * d <= n:
            if n % d == 0:
                return False
            d += 2
        return True


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
DEFAULT_ESTIMATOR_PATH = "/tmp/lattice-estimator-dklw"
ESTIMATOR_REMOTE = "https://github.com/malb/lattice-estimator.git"


@dataclass
class EstimatorSetup:
    path: str
    commit: str
    requested_ref: str | None
    checkout_ok: bool
    messages: list[str]


def project_path(*parts: str) -> Path:
    return REPO_ROOT.joinpath(*parts)


def results_path(output_dir: str | os.PathLike[str], name: str) -> Path:
    path = Path(output_dir)
    if not path.is_absolute():
        path = REPO_ROOT / path
    path.mkdir(parents=True, exist_ok=True)
    return path / name


def run_cmd(cmd: list[str], cwd: str | os.PathLike[str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=str(cwd) if cwd is not None else None,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def command_text(cmd: Iterable[str]) -> str:
    return " ".join(str(x) for x in cmd)


def setup_estimator(estimator_path: str = DEFAULT_ESTIMATOR_PATH, estimator_ref: str | None = None) -> EstimatorSetup:
    path = Path(estimator_path).expanduser().resolve()
    messages: list[str] = []
    checkout_ok = True

    if not path.exists():
        proc = run_cmd(["git", "clone", ESTIMATOR_REMOTE, str(path)])
        if proc.returncode != 0:
            raise RuntimeError(f"git clone failed: {proc.stderr.strip() or proc.stdout.strip()}")
        messages.append(f"cloned {ESTIMATOR_REMOTE}")
    else:
        if not (path / ".git").exists():
            raise RuntimeError(f"estimator path is not a git repository: {path}")
        fetch = run_cmd(["git", "-C", str(path), "fetch", "--all", "--tags", "--prune"])
        if fetch.returncode == 0:
            messages.append("fetched estimator remotes")
        else:
            messages.append(f"estimator fetch failed: {fetch.stderr.strip() or fetch.stdout.strip()}")

        branch = run_cmd(["git", "-C", str(path), "rev-parse", "--abbrev-ref", "HEAD"])
        if branch.returncode == 0 and branch.stdout.strip() != "HEAD":
            pull = run_cmd(["git", "-C", str(path), "pull", "--ff-only"])
            if pull.returncode == 0:
                messages.append("updated estimator branch with --ff-only")
            else:
                messages.append(f"estimator pull skipped/failed: {pull.stderr.strip() or pull.stdout.strip()}")

    if estimator_ref:
        checkout = run_cmd(["git", "-C", str(path), "checkout", estimator_ref])
        if checkout.returncode == 0:
            messages.append(f"checked out estimator ref {estimator_ref}")
        else:
            checkout_ok = False
            messages.append(
                f"could not check out estimator ref {estimator_ref}: "
                f"{checkout.stderr.strip() or checkout.stdout.strip()}"
            )

    commit_proc = run_cmd(["git", "-C", str(path), "rev-parse", "HEAD"])
    commit = commit_proc.stdout.strip() if commit_proc.returncode == 0 else "unknown"
    setup = EstimatorSetup(str(path), commit, estimator_ref, checkout_ok, messages)
    write_estimator_commit(setup)
    return setup


def write_estimator_commit(setup: EstimatorSetup, output_dir: str | os.PathLike[str] | None = None) -> None:
    lines = [
        f"lattice_estimator_path={setup.path}",
        f"lattice_estimator_commit={setup.commit}",
        f"requested_ref={setup.requested_ref or ''}",
        f"checkout_ok={str(setup.checkout_ok).lower()}",
    ]
    for msg in setup.messages:
        lines.append(f"note={msg}")
    text = "\n".join(lines) + "\n"
    (SCRIPT_DIR / "estimator_commit.txt").write_text(text)
    if output_dir is not None:
        out = Path(output_dir)
        if not out.is_absolute():
            out = REPO_ROOT / out
        out.mkdir(parents=True, exist_ok=True)
        (out / "estimator_commit.txt").write_text(text)


def full_split_condition(q: int, N: int) -> bool:
    return int(q) % (2 * int(N)) == 1


def log2_value(x: Any) -> float | None:
    if x is None:
        return None
    if x == oo:
        return math.inf
    try:
        if hasattr(x, "log"):
            return float(x.log(2))
    except Exception:
        pass
    try:
        return float(math.log2(float(x)))
    except Exception:
        if RR is not None:
            try:
                return float(RR(x).log(2))
            except Exception:
                return None
        return None


def sigma_b(B: int) -> float:
    return math.sqrt(int(B) * (int(B) + 1) / 3.0)


def range_grade(B: int) -> str:
    degree = 2 * int(B) + 1
    if degree <= 17:
        return "direct preferred"
    if degree <= 33:
        return "direct likely acceptable; benchmark"
    if degree <= 65:
        return "benchmark-required"
    return "decomposition-required"


def prime_candidates_for_bits(
    N: int,
    bits_start: int = 12,
    bits_end: int = 30,
    per_bit: int = 2,
    max_delta_steps: int = 20000,
) -> list[int]:
    if bits_start > bits_end:
        raise ValueError("bits_start must be <= bits_end")
    candidates: set[int] = set()
    mod = 2 * int(N)
    for bits in range(bits_start, bits_end + 1):
        lower = 1 << (bits - 1)
        upper = (1 << bits) - 1
        center = 1 << bits
        base = center + ((1 - center) % mod)
        found: list[int] = []
        for k in range(max_delta_steps + 1):
            deltas = [0] if k == 0 else [k, -k]
            for delta in deltas:
                q = int(base + delta * mod)
                if q < lower or q > upper or not full_split_condition(q, N):
                    continue
                if is_prime(q):
                    if q not in found:
                        found.append(q)
                    if len(found) >= per_bit:
                        break
            if len(found) >= per_bit:
                break
        candidates.update(found)
    return sorted(candidates)


def q_values_for_N(args: Any, N: int) -> list[int]:
    if getattr(args, "q", None):
        return sorted(dict.fromkeys(int(q) for q in args.q))
    return prime_candidates_for_bits(
        N,
        bits_start=int(args.bits_start),
        bits_end=int(args.bits_end),
        per_bit=int(args.qs_per_bit),
        max_delta_steps=int(getattr(args, "max_delta_steps", 20000)),
    )


def write_csv(path: str | os.PathLike[str], rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({key: csv_value(row.get(key, "")) for key in fieldnames})


def read_csv(path: str | os.PathLike[str]) -> list[dict[str, str]]:
    with Path(path).open(newline="") as fh:
        return list(csv.DictReader(fh))


def csv_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, float):
        if math.isinf(value):
            return "inf"
        if math.isnan(value):
            return "nan"
        return f"{value:.12g}"
    return str(value)


def bool_text(value: bool) -> str:
    return "yes" if value else "no"


def is_yes(value: Any) -> bool:
    return str(value).strip().lower() in {"yes", "true", "1"}


def parse_float(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except Exception:
        return None


def parse_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except Exception:
        return None


def safe_json_obj(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, bool)):
        return value
    if isinstance(value, float):
        if math.isfinite(value):
            return value
        return str(value)
    if hasattr(value, "__dataclass_fields__"):
        return safe_json_obj(asdict(value))
    if isinstance(value, dict):
        return {str(k): safe_json_obj(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [safe_json_obj(v) for v in value]
    if RR is not None:
        try:
            return float(RR(value))
        except Exception:
            pass
    return str(value)


def append_jsonl(path: str | os.PathLike[str], record: dict[str, Any]) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as fh:
        fh.write(json.dumps(safe_json_obj(record), sort_keys=True) + "\n")


def write_json(path: str | os.PathLike[str], data: Any) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(safe_json_obj(data), indent=2, sort_keys=True) + "\n")


def sage_version_text() -> str:
    try:
        import sage.env

        return str(getattr(sage.env, "SAGE_VERSION", "unknown"))
    except Exception:
        return "unknown"


def runtime_summary() -> dict[str, str]:
    return {
        "python": sys.version.replace("\n", " "),
        "python_executable": sys.executable,
        "platform": platform.platform(),
        "sage": sage_version_text(),
    }


def format_float(value: float | None, digits: int = 3) -> str:
    if value is None:
        return ""
    if math.isinf(value):
        return "inf"
    return f"{value:.{digits}f}"


def require_sage_python_hint() -> str:
    return (
        "Use Sage Python. On this machine `python3` imports Sage; many Sage installs use "
        "`sage --python`; some use `sage -python`."
    )
