#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass

from common import sigma_b


B_PROFILE_ORDER = ["ternary", "3", "4", "6", "8"]


@dataclass(frozen=True)
class DistributionProfile:
    profile: str
    B: int
    distribution: str
    support: str
    sigma_B: float


def normalize_bound_label(raw: str | int) -> str:
    label = str(raw).strip().lower()
    if label in {"ternary", "uniform_ternary", "t"}:
        return "ternary"
    if label in {"1", "b1"}:
        # Keep ternary explicit; coefficient bound B=1 is this pipeline's ternary profile.
        return "ternary"
    if label in {"3", "4", "6", "8"}:
        return label
    raise ValueError(f"unsupported bound profile {raw!r}; expected ternary, 3, 4, 6, or 8")


def profile_for(raw: str | int) -> DistributionProfile:
    label = normalize_bound_label(raw)
    if label == "ternary":
        B = 1
        return DistributionProfile(
            profile="ternary",
            B=B,
            distribution="uniform_ternary",
            support="{-1,0,1}",
            sigma_B=sigma_b(B),
        )
    B = int(label)
    return DistributionProfile(
        profile=label,
        B=B,
        distribution="bounded_uniform",
        support=f"[-{B},{B}]",
        sigma_B=sigma_b(B),
    )


def parse_bound_profiles(raw_bounds: list[str] | tuple[str, ...] | None) -> list[DistributionProfile]:
    if raw_bounds is None:
        raw_bounds = B_PROFILE_ORDER
    seen: set[str] = set()
    out: list[DistributionProfile] = []
    for raw in raw_bounds:
        profile = profile_for(raw)
        if profile.profile in seen:
            continue
        seen.add(profile.profile)
        out.append(profile)
    return out


def distribution_report_rows() -> list[dict[str, str]]:
    return [
        {
            "B_profile": p.profile,
            "B": str(p.B),
            "distribution": p.distribution,
            "support": p.support,
            "sigma_B": f"{p.sigma_B:.12g}",
        }
        for p in parse_bound_profiles(B_PROFILE_ORDER)
    ]
