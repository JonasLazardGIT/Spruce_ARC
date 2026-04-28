#!/usr/bin/env sage
from __future__ import annotations

import argparse
import os
import json
import math

from sage.all import sqrt, log, pi

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


def vsis_sig_candidate_security(SIS, ND, N, q, l_m, l_r, alpha, mode='rough', bits=128):
    eta = sqrt(log(4 * N * (1 + 2 ** bits)) / pi)
    s_trap = alpha * sqrt(q) * eta
    m_sig = N * (3 + l_m + l_r)
    beta_sig = s_trap * sqrt(N * (3 + l_m + l_r))
    params = SIS.Parameters(n=N, m=m_sig, q=q, length_bound=float(beta_sig), norm=2)
    if mode == 'rough':
        raw = estimator_call_silent(SIS.estimate.rough, params)
    else:
        raw = estimator_call_silent(SIS.estimate, params)
    entries = estimate_to_entry_dict(raw)
    best = best_estimator_entry(entries)
    return {
        'params': params,
        'entries': entries,
        'best': best,
        'beta_sig': float(beta_sig),
        's_trap': float(s_trap),
        'm_sig': int(m_sig),
    }


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

            for l_m in args.l_m:
                for alpha in args.alpha:
                    try:
                        r = vsis_sig_candidate_security(
                            SIS,
                            ND,
                            N,
                            q,
                            l_m,
                            args.l_r,
                            alpha,
                            mode='rough',
                            bits=args.lambda_bits,
                        )
                    except Exception as e:
                        rows.append({
                            'N': N,
                            'q': q,
                            'log2_q': f"{safe_float_log2(q):.3f}",
                            'fully_split': str(q % (2 * N) == 1).lower(),
                            'l_m': l_m,
                            'l_r': args.l_r,
                            'alpha': alpha,
                            'mode': 'rough',
                            's_trap': '',
                            'beta_sig': '',
                            'm_sig': '',
                            'attack': 'error',
                            'log2_rop': '',
                            'log2_red': '',
                            'log2_mem': '',
                            'bkz_beta': '',
                            'd': '',
                            'd_bound': '',
                            'sec_bits': '',
                            'accepted': 'no',
                            'rejection_reason': f'SIS error: {e}',
                            'sig_bits': '',
                            'pk_bits': '',
                            'beta_lt_q': '',
                            'beta_lt_q2': '',
                        })
                        continue

                    best = r['best']
                    beta_sig = r['beta_sig']
                    sig_bits = 2 * (2 + args.l_r) * N * (safe_float_log2(beta_sig) if beta_sig > 0 else float('nan')) / 8.0
                    pk_bits = N * safe_float_log2(q) if q > 0 else float('nan')

                    rows.append({
                        'N': N,
                        'q': q,
                        'log2_q': f"{safe_float_log2(q):.3f}",
                        'fully_split': str(q % (2 * N) == 1).lower(),
                        'l_m': l_m,
                        'l_r': args.l_r,
                        'alpha': alpha,
                        'mode': 'rough',
                        's_trap': f"{r['s_trap']:.12g}",
                        'beta_sig': f"{beta_sig:.12g}",
                        'm_sig': r['m_sig'],
                        'attack': '' if best is None else best.attack,
                        'log2_rop': '' if best is None or best.log2_rop is None else f"{best.log2_rop:.3f}",
                        'log2_red': '' if best is None or best.log2_red is None else f"{best.log2_red:.3f}",
                        'log2_mem': '' if best is None or best.log2_mem is None else f"{best.log2_mem:.3f}",
                        'bkz_beta': '' if best is None or best.d is None else str(best.d),
                        'd': '' if best is None else str(best.beta) if best.beta is not None else '',
                        'd_bound': '',
                        'sec_bits': '' if best is None or best.log2_rop is None else f"{best.log2_rop:.3f}",
                        'accepted': 'yes' if (best is not None and best.log2_rop is not None and best.log2_rop >= args.min_bits) else 'no',
                        'rejection_reason': '' if (best is not None and best.log2_rop is not None and best.log2_rop >= args.min_bits) else 'SIS below target' if best is not None else 'estimate failed',
                        'sig_bits': f"{sig_bits:.3f}",
                        'pk_bits': f"{pk_bits:.3f}",
                        'beta_lt_q': str(beta_sig < q).lower(),
                        'beta_lt_q2': str(beta_sig < q / 2).lower(),
                    })

                    if args.run_full and best is not None and best.log2_rop is not None and best.log2_rop >= args.full_threshold:
                        try:
                            r_full = vsis_sig_candidate_security(
                                SIS,
                                ND,
                                N,
                                q,
                                l_m,
                                args.l_r,
                                alpha,
                                mode='full',
                                bits=args.lambda_bits,
                            )
                            b2 = r_full['best']
                            rows.append({
                                'N': N,
                                'q': q,
                                'log2_q': f"{safe_float_log2(q):.3f}",
                                'fully_split': str(q % (2 * N) == 1).lower(),
                                'l_m': l_m,
                                'l_r': args.l_r,
                                'alpha': alpha,
                                'mode': 'full',
                                's_trap': f"{r_full['s_trap']:.12g}",
                                'beta_sig': f"{r_full['beta_sig']:.12g}",
                                'm_sig': r_full['m_sig'],
                                'attack': '' if b2 is None else b2.attack,
                                'log2_rop': '' if b2 is None or b2.log2_rop is None else f"{b2.log2_rop:.3f}",
                                'log2_red': '' if b2 is None or b2.log2_red is None else f"{b2.log2_red:.3f}",
                                'log2_mem': '' if b2 is None or b2.log2_mem is None else f"{b2.log2_mem:.3f}",
                                'bkz_beta': '' if b2 is None or b2.d is None else str(b2.d),
                                'd': '' if b2 is None else str(b2.beta) if b2.beta is not None else '',
                                'd_bound': '',
                                'sec_bits': '' if b2 is None or b2.log2_rop is None else f"{b2.log2_rop:.3f}",
                                'accepted': 'yes' if (b2 is not None and b2.log2_rop is not None and b2.log2_rop >= args.min_bits) else 'no',
                                'rejection_reason': '' if (b2 is not None and b2.log2_rop is not None and b2.log2_rop >= args.min_bits) else 'SIS below target' if b2 is not None else 'estimate failed',
                                'sig_bits': f"{sig_bits:.3f}",
                                'pk_bits': f"{pk_bits:.3f}",
                                'beta_lt_q': str(r_full['beta_sig'] < q).lower(),
                                'beta_lt_q2': str(r_full['beta_sig'] < q / 2).lower(),
                            })
                        except Exception as e:
                            rows.append({
                                'N': N,
                                'q': q,
                                'log2_q': f"{safe_float_log2(q):.3f}",
                                'fully_split': str(q % (2 * N) == 1).lower(),
                                'l_m': l_m,
                                'l_r': args.l_r,
                                'alpha': alpha,
                                'mode': 'full',
                                's_trap': '',
                                'beta_sig': '',
                                'm_sig': r['m_sig'],
                                'attack': 'error',
                                'log2_rop': '',
                                'log2_red': '',
                                'log2_mem': '',
                                'bkz_beta': '',
                                'd': '',
                                'd_bound': '',
                                'sec_bits': '',
                                'accepted': 'no',
                                'rejection_reason': f'SIS full exception: {e}',
                                'sig_bits': f"{sig_bits:.3f}",
                                'pk_bits': f"{pk_bits:.3f}",
                                'beta_lt_q': str(r['beta_sig'] < q).lower(),
                                'beta_lt_q2': str(r['beta_sig'] < q / 2).lower(),
                            })

    fieldnames = [
        'N', 'q', 'log2_q', 'fully_split', 'l_m', 'l_r', 'alpha', 'mode', 's_trap',
        'beta_sig', 'm_sig', 'attack', 'log2_rop', 'log2_red', 'log2_mem',
        'bkz_beta', 'd', 'd_bound', 'sec_bits', 'accepted', 'rejection_reason',
        'sig_bits', 'pk_bits', 'beta_lt_q', 'beta_lt_q2'
    ]
    write_csv(args.output, rows, fieldnames)


def parse_args():
    p = argparse.ArgumentParser(description='Search signature parameters for DKLW/BB-tran.')
    p.add_argument('--Ns', type=int, nargs='+', default=[256, 512])
    p.add_argument('--l-m', dest='l_m', type=int, nargs='+', default=[1, 2, 4, 8, 16])
    p.add_argument('--l-r', dest='l_r', type=int, default=2)
    p.add_argument('--alpha', type=float, nargs='+', default=[1.15, 1.17, 1.23, 1.48, 2.04])
    p.add_argument('--lambda-bits', type=int, default=128)
    p.add_argument('--min-bits', type=float, default=128.0)
    p.add_argument('--full-threshold', type=float, default=120.0)
    p.add_argument('--run-full', action='store_true')
    p.add_argument('--require-fully-split', action='store_true', default=True)
    p.add_argument('--bits-start', type=int, default=12)
    p.add_argument('--bits-end', type=int, default=30)
    p.add_argument('--qs-per-bit', type=int, default=1)
    p.add_argument('--max-delta-steps', type=int, default=2000)
    p.add_argument('--q', type=int, nargs='+', default=None)
    p.add_argument('--params-json', type=str, default=None)
    p.add_argument('--estimator-path', dest='estimator_path', default='/tmp/lattice-estimator-dklw')
    p.add_argument('--output', default='parameter_search/results/signature_placeholder.csv')
    return p.parse_args()


if __name__ == '__main__':
    args = parse_args()
    run_search(args)
