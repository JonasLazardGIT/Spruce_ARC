#!/usr/bin/env sage
from __future__ import annotations

import argparse
import os
import json

from math import sqrt
script_dir = os.path.dirname(os.path.abspath(__file__))
if script_dir not in os.sys.path:
    os.sys.path.insert(0, script_dir)

from common import (
    load_estimator_modules,
    prime_candidates_for_bits,
    full_split_condition,
    best_estimator_entry,
    estimate_to_entry_dict,
    safe_float_log2,
    write_csv,
    estimator_call_silent,
)


def explicit_qs_from_inputs(args):
    if args.q:
        return list(dict.fromkeys([int(v) for v in args.q]))
    if args.params_json is None:
        return None

    with open(args.params_json, 'r') as f:
        data = json.load(f)

    if isinstance(data, dict):
        if 'q' in data:
            return [int(data['q'])]
        if 'modulus' in data:
            return [int(data['modulus'])]
    if isinstance(data, list):
        qs = [int(row['q']) for row in data if isinstance(row, dict) and 'q' in row]
        qs += [int(row['modulus']) for row in data if isinstance(row, dict) and 'modulus' in row]
        if qs:
            return list(dict.fromkeys(qs))

    raise ValueError(f'could not extract q from params JSON: {args.params_json}')


def run_search(args):
    LWE, SIS, NTRU, ND, oo, sqrt, pi = load_estimator_modules(args.estimator_path)

    rows = []
    explicit_qs = explicit_qs_from_inputs(args)
    for N in args.Ns:
        qs = (
            explicit_qs
            if explicit_qs is not None
            else prime_candidates_for_bits(
                N,
                bits_start=args.bits_start,
                bits_end=args.bits_end,
                per_bit=args.qs_per_bit,
                max_delta_steps=args.max_delta_steps,
            )
        )

        for q in qs:
            if q % (2 * N) != 1 and args.require_fully_split:
                continue

            # if explicit candidate map file exists, keep those alpha/beta from signature file
            for alpha in args.alpha:
                s_trap = alpha * sqrt(q) * sqrt(__import__('math').log(4 * N * (1 + 2 ** args.lambda_bits) ) / pi)
                X = ND.DiscreteGaussian(float(s_trap))
                params = NTRU.Parameters(n=N, q=q, Xs=X, Xe=X)
                for mode in ['rough'] + (['full'] if args.run_full else []):
                    try:
                        if mode == 'rough':
                            raw = estimator_call_silent(NTRU.estimate.rough, params)
                        else:
                            raw = estimator_call_silent(NTRU.estimate, params)
                        entries = estimate_to_entry_dict(raw)
                        best = best_estimator_entry(entries)
                        log_sec = '' if best is None or best.log2_rop is None else f"{best.log2_rop:.3f}"
                        log_red = '' if best is None or best.log2_red is None else f"{best.log2_red:.3f}"
                        log_mem = '' if best is None or best.log2_mem is None else f"{best.log2_mem:.3f}"
                        attack = '' if best is None else best.attack
                        d = '' if best is None or best.d is None else str(best.d)
                        bkz = '' if best is None else str(best.d)
                        accepted = 'yes' if (best is not None and best.log2_rop is not None and best.log2_rop >= args.min_bits) else 'no'
                        reason = '' if accepted == 'yes' else 'below target'
                    except Exception as e:
                        log_sec = ''
                        log_red = ''
                        log_mem = ''
                        attack = 'error'
                        d = ''
                        bkz = ''
                        accepted = 'no'
                        reason = f'NTRU {mode} exception: {e}'

                    rows.append({
                        'N': N,
                        'q': q,
                        'log2_q': f"{safe_float_log2(q):.3f}",
                        'fully_split': str(q % (2 * N) == 1).lower(),
                        'mode': mode,
                        'alpha': alpha,
                        's_trap': f"{float(s_trap):.12g}",
                        'ntru_attack': attack,
                        'ntru_log2_rop': log_sec,
                        'ntru_log2_red': log_red,
                        'ntru_log2_mem': log_mem,
                        'ntru_d': d,
                        'ntru_bkz_beta': bkz,
                        'accepted': accepted,
                        'rejection_reason': reason,
                    })

    fieldnames = [
        'N', 'q', 'log2_q', 'fully_split', 'mode', 'alpha', 's_trap',
        'ntru_attack', 'ntru_log2_rop', 'ntru_log2_red', 'ntru_log2_mem',
        'ntru_d', 'ntru_bkz_beta', 'accepted', 'rejection_reason'
    ]
    write_csv(args.output, rows, fieldnames)


def parse_args():
    p = argparse.ArgumentParser(description='Run NTRU estimates for signature parameter candidates.')
    p.add_argument('--Ns', type=int, nargs='+', default=[256, 512])
    p.add_argument('--alpha', type=float, nargs='+', default=[1.15, 1.17, 1.23, 1.48, 2.04])
    p.add_argument('--lambda-bits', type=int, default=128)
    p.add_argument('--min-bits', type=float, default=128.0)
    p.add_argument('--run-full', action='store_true')
    p.add_argument('--require-fully-split', action='store_true', default=True)
    p.add_argument('--bits-start', type=int, default=12)
    p.add_argument('--bits-end', type=int, default=30)
    p.add_argument('--qs-per-bit', type=int, default=1)
    p.add_argument('--max-delta-steps', type=int, default=2000)
    p.add_argument('--q', type=int, nargs='+', default=None)
    p.add_argument('--params-json', type=str, default=None)
    p.add_argument('--estimator-path', dest='estimator_path', default='/tmp/lattice-estimator-dklw')
    p.add_argument('--output', default='parameter_search/results/ntru_placeholder.csv')
    return p.parse_args()


if __name__ == '__main__':
    run_search(parse_args())
