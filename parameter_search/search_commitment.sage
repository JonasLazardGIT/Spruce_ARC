#!/usr/bin/env sage
from __future__ import annotations

import argparse
import csv
import itertools
import json
import os
from math import sqrt

script_dir = os.path.dirname(os.path.abspath(__file__))
if script_dir not in os.sys.path:
    os.sys.path.insert(0, script_dir)

from common import (
    load_estimator_modules,
    prime_candidates_for_bits,
    full_split_condition,
    safe_float_log2,
    best_estimator_entry,
    estimate_to_entry_dict,
    estimator_call_silent,
    write_csv,
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


def evaluate_lwe(LWE, ND, N, q, k_s, n_c, B, mode='rough'):
    n = N * k_s
    m = N * n_c
    X = ND.Uniform(-B, B)
    params = LWE.Parameters(n=n, q=q, Xs=X, Xe=X, m=m)
    if mode == 'rough':
        raw = estimator_call_silent(LWE.estimate.rough, params)
    else:
        raw = estimator_call_silent(LWE.estimate, params)

    entries = estimate_to_entry_dict(raw)
    best = best_estimator_entry(entries)
    return params, entries, best, {'n': n, 'm': m}


def evaluate_sis(SIS, ND, N, q, l_m, k_s, n_c, B, norm='infinity', mode='rough'):
    l = l_m + k_s + n_c
    n = N * n_c
    m = N * l
    if norm == 'infinity':
        from sage.all import oo

        lb = 2 * B
        params = SIS.Parameters(n=n, m=m, q=q, length_bound=lb, norm=oo)
    elif norm == 'euclidean':
        lb = 2 * B * sqrt(N * l)
        params = SIS.Parameters(n=n, m=m, q=q, length_bound=lb, norm=2)
    else:
        raise ValueError('unknown norm')

    if mode == 'rough':
        raw = estimator_call_silent(SIS.estimate.rough, params)
    else:
        raw = estimator_call_silent(SIS.estimate, params)

    entries = estimate_to_entry_dict(raw)
    best = best_estimator_entry(entries)
    return params, entries, best, {'n': n, 'm': m, 'norm': norm, 'length_bound': float(lb)}


def make_csv_row(
    N,
    q,
    l_m,
    k_s,
    n_c,
    B,
    mode,
    fully_split,
    hide_best,
    hide_entries,
    bind_inf_best,
    bind_inf_entries,
    bind_euc_best,
    bind_euc_entries,
    accept,
    rejection_reason,
    s_sw=16,
):
    l = l_m + k_s + n_c
    opening_len = l
    random_len = k_s + n_c
    rows = (N * opening_len) / s_sw
    range_deg = 2 * B + 1

    def pick_entry(entry):
        if entry is None:
            return {
                'attack': '',
                'log2_rop': '',
                'log2_red': '',
                'log2_mem': '',
                'beta': '',
                'd': '',
                'tag': '',
            }
        return {
            'attack': str(entry.attack),
            'log2_rop': '' if entry.log2_rop is None else f"{entry.log2_rop:.3f}",
            'log2_red': '' if entry.log2_red is None else f"{entry.log2_red:.3f}",
            'log2_mem': '' if entry.log2_mem is None else f"{entry.log2_mem:.3f}",
            'beta': '' if entry.beta is None else f"{entry.beta:.6g}",
            'd': '' if entry.d is None else str(entry.d),
            'tag': '' if entry.tag is None else str(entry.tag),
        }

    hide = pick_entry(hide_best)
    inf = pick_entry(bind_inf_best)
    euc = pick_entry(bind_euc_best)

    binding_candidates = [x for x in [bind_inf_best, bind_euc_best] if x is not None]
    binding_sec = 10 ** 9
    for x in binding_candidates:
        if x.log2_rop is not None and x.log2_rop < binding_sec:
            binding_sec = x.log2_rop
    if binding_sec == 10 ** 9:
        binding_sec = None

    binding_attack = ''
    binding_norm = ''
    binding_bkz = ''
    binding_beta = ''
    if bind_inf_best is not None and bind_inf_best.log2_rop is not None:
        if bind_euc_best is None or bind_euc_best.log2_rop is None or bind_inf_best.log2_rop <= bind_euc_best.log2_rop:
            binding_attack = inf['attack']
            binding_norm = 'inf'
            binding_bkz = inf['d']
            binding_beta = inf['beta']
        else:
            binding_attack = euc['attack']
            binding_norm = 'l2'
            binding_bkz = euc['d']
            binding_beta = euc['beta']

    return {
        'N': N,
        'q': q,
        'log2_q': f"{safe_float_log2(q):.3f}",
        'fully_split': str(bool(fully_split)).lower(),
        'problem': 'commitment_hiding+binding',
        'l_M': l_m,
        'k_s': k_s,
        'n_c': n_c,
        'B': B,
        'distribution': 'uniform',
        'dist_sd': f"{(B * (B + 1) / 3) ** 0.5:.6g}",
        'n_LWE': N * k_s,
        'm_LWE': N * n_c,
        'n_SIS': N * n_c,
        'm_SIS': N * (l_m + k_s + n_c),
        'mode': mode,
        'hiding_attack': hide['attack'],
        'hiding_log2_rop': hide['log2_rop'],
        'hiding_log2_red': hide['log2_red'],
        'hiding_log2_mem': hide['log2_mem'],
        'hiding_bkz_beta': hide['d'],
        'hiding_beta': hide['beta'],
        'hiding_tag': hide['tag'],
        'binding_attack': binding_attack,
        'binding_norm': binding_norm,
        'binding_log2_rop': '' if binding_sec is None else f"{binding_sec:.3f}",
        'binding_bkz_beta': binding_bkz,
        'binding_beta': binding_beta,
        'inf_binding_log2_rop': inf['log2_rop'],
        'inf_binding_attack': inf['attack'],
        'inf_binding_log2_red': inf['log2_red'],
        'inf_binding_log2_mem': inf['log2_mem'],
        'inf_binding_d': inf['d'],
        'l2_binding_log2_rop': euc['log2_rop'],
        'l2_binding_attack': euc['attack'],
        'l2_binding_log2_red': euc['log2_red'],
        'l2_binding_log2_mem': euc['log2_mem'],
        'l2_binding_d': euc['d'],
        'opening_length': N * (l_m + k_s + n_c),
        'random_length': N * (k_s + n_c),
        's_SW': s_sw,
        'smallwood_rows': f"{rows:.3f}",
        'range_degree': range_deg,
        'range_grade': (
            'direct' if range_deg <= 33 else ('benchmark-needed' if range_deg <= 65 else 'decompose')
        ),
        'accepted': 'yes' if accept else 'no',
        'rejection_reason': rejection_reason,
        'notes': '',
    }


def run_search(args):
    LWE, SIS, NTRU, ND, oo, sqrt, pi = load_estimator_modules(args.estimator_path)

    rows = []
    should_stop = False

    explicit_qs = explicit_qs_from_inputs(args)
    candidates_by_n = {
        N: (
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
        for N in args.Ns
    }

    for N in args.Ns:
        if should_stop:
            break
        qs = candidates_by_n[N]
        for q in qs:
            if should_stop:
                break
            is_fully_split = full_split_condition(q, N)
            fully_split = is_fully_split
            hide_cache = {}
            bind_inf_cache = {}
            bind_euc_cache = {}

            for l_m, k_s, n_c, B in itertools.product(
                args.l_M, args.k_s, args.n_c, args.B,
            ):
                if not is_fully_split and args.require_fully_split:
                    # rejected regardless of parameters
                    rows.append(
                        make_csv_row(
                            N,
                            q,
                            l_m,
                            k_s,
                            n_c,
                            B,
                            'rough',
                            False,
                            None,
                            [],
                            None,
                            [],
                            None,
                            [],
                            False,
                            'not fully split',
                        )
                    )
                    continue

                hide_key = (q, k_s, n_c, B)
                try:
                    if hide_key in hide_cache:
                        hide_best, hide_ctx = hide_cache[hide_key]
                    else:
                        _, _, hide_best, hide_ctx = evaluate_lwe(LWE, ND, N, q, k_s, n_c, B, mode='rough')
                        hide_cache[hide_key] = (hide_best, hide_ctx)
                except Exception as e:
                    rows.append(
                        make_csv_row(
                            N,
                            q,
                            l_m,
                            k_s,
                            n_c,
                            B,
                            'rough',
                            is_fully_split,
                            None,
                            [],
                            None,
                            [],
                            None,
                            [],
                            False,
                            f'LWE.estimate.rough exception: {e}',
                        )
                    )
                    continue

                hide_sec = hide_best.log2_rop if hide_best else None

                bind_inf_best = None
                bind_euc_best = None
                bind_inf_ctx = None
                bind_euc_ctx = None
                bind_inf_msg = ''
                bind_euc_msg = ''

                if hide_sec is not None and hide_sec >= args.min_bits:
                    # evaluate binding only if hiding is still competitive enough to avoid wasted runs
                    bind_inf_key = ('inf', q, N, l_m, k_s, n_c, B)
                    bind_euc_key = ('euc', q, N, l_m, k_s, n_c, B)

                    try:
                        if bind_inf_key in bind_inf_cache:
                            bind_inf_best, bind_inf_ctx = bind_inf_cache[bind_inf_key]
                        else:
                            _, _, bind_inf_best, bind_inf_ctx = evaluate_sis(
                                SIS, ND, N, q, l_m, k_s, n_c, B, norm='infinity', mode='rough'
                            )
                            bind_inf_cache[bind_inf_key] = (bind_inf_best, bind_inf_ctx)
                    except Exception as e:
                        bind_inf_msg = f'SIS inf exception: {e}'

                    try:
                        if bind_euc_key in bind_euc_cache:
                            bind_euc_best, bind_euc_ctx = bind_euc_cache[bind_euc_key]
                        else:
                            _, _, bind_euc_best, bind_euc_ctx = evaluate_sis(
                                SIS, ND, N, q, l_m, k_s, n_c, B, norm='euclidean', mode='rough'
                            )
                            bind_euc_cache[bind_euc_key] = (bind_euc_best, bind_euc_ctx)
                    except Exception as e:
                        bind_euc_msg = f'SIS l2 exception: {e}'
                else:
                    bind_inf_msg = 'skipped due to hiding below threshold'
                    bind_euc_msg = 'skipped due to hiding below threshold'

                bind_candidates = [x for x in [bind_inf_best, bind_euc_best] if x is not None]
                bind_sec = None
                for x in bind_candidates:
                    if x.log2_rop is None:
                        continue
                    bind_sec = x.log2_rop if bind_sec is None else min(bind_sec, x.log2_rop)

                reasons = []
                if hide_sec is None:
                    reasons.append('hiding failed')
                elif hide_sec < args.min_bits:
                    reasons.append('hiding below target')
                if bind_sec is None:
                    reasons.append('binding failed')
                elif bind_sec < args.min_bits:
                    reasons.append('binding below target')
                elif bind_inf_msg or bind_euc_msg:
                    reasons.append(' '.join(m for m in [bind_inf_msg, bind_euc_msg] if m))
                if range_degree := (2 * B + 1) > 65:
                    reasons.append('range check too large')

                accepted = (len(reasons) == 0)
                row = make_csv_row(
                    N,
                    q,
                    l_m,
                    k_s,
                    n_c,
                    B,
                    'rough',
                    fully_split,
                    hide_best,
                    hide_ctx,
                    bind_inf_best,
                    bind_inf_ctx,
                    bind_euc_best,
                    bind_euc_ctx,
                    accepted,
                    '; '.join(reasons),
                )

                rows.append(row)

                if accepted and args.stop_at_first:
                    should_stop = True
                    if args.echo_first:
                        if bind_sec is None:
                            combined = 'nan'
                        else:
                            combined = f"{min(hide_sec, bind_sec):.3f}"
                        print(
                            f"first accepted: N={N} q={q} l_M={l_m} k_s={k_s} n_c={n_c} B={B} "
                            f"hiding={hide_sec:.3f} binding={bind_sec if bind_sec is not None else 'n/a'} "
                            f"min={combined}"
                        )
                    break

                # optionally run full for frontier candidates that pass rough security
                if args.run_full and accepted and hide_sec is not None and hide_sec >= args.full_threshold:
                    try:
                        _, _, hide_full_best, _ = evaluate_lwe(LWE, ND, N, q, k_s, n_c, B, mode='full')
                    except Exception as e:
                        row = make_csv_row(
                            N,
                            q,
                            l_m,
                            k_s,
                            n_c,
                            B,
                            'full',
                            True,
                            None,
                            [],
                            None,
                            [],
                            None,
                            [],
                            False,
                            f'LWE.estimate exception: {e}',
                        )
                        rows.append(row)
                        continue
                    try:
                        _, _, bind_inf_full_best, _ = evaluate_sis(SIS, ND, N, q, l_m, k_s, n_c, B, norm='infinity', mode='full')
                    except Exception as e:
                        bind_inf_full_best = None
                    try:
                        _, _, bind_euc_full_best, _ = evaluate_sis(
                            SIS, ND, N, q, l_m, k_s, n_c, B, norm='euclidean', mode='full'
                        )
                    except Exception as e:
                        bind_euc_full_best = None

                    hide_for_full = hide_full_best
                    row_full = make_csv_row(
                        N,
                        q,
                        l_m,
                        k_s,
                        n_c,
                        B,
                        'full',
                        fully_split,
                        hide_for_full,
                        None,
                        bind_inf_full_best,
                        None,
                        bind_euc_full_best,
                        None,
                        accepted,
                        '; '.join(reasons),
                    )
                    rows.append(row_full)

            if should_stop:
                break

    path = args.output
    fieldnames = [
        'N', 'q', 'log2_q', 'fully_split', 'problem', 'l_M', 'k_s', 'n_c', 'B',
        'distribution', 'dist_sd', 'n_LWE', 'm_LWE', 'n_SIS', 'm_SIS', 'mode',
        'hiding_attack', 'hiding_log2_rop', 'hiding_log2_red', 'hiding_log2_mem',
        'hiding_bkz_beta', 'hiding_beta', 'hiding_tag',
        'binding_attack', 'binding_norm', 'binding_log2_rop', 'binding_bkz_beta', 'binding_beta',
        'inf_binding_log2_rop', 'inf_binding_attack', 'inf_binding_log2_red', 'inf_binding_log2_mem',
        'inf_binding_d',
        'l2_binding_log2_rop', 'l2_binding_attack', 'l2_binding_log2_red', 'l2_binding_log2_mem',
        'l2_binding_d',
        'opening_length', 'random_length', 's_SW', 'smallwood_rows', 'range_degree',
        'range_grade', 'accepted', 'rejection_reason', 'notes'
    ]
    write_csv(path, rows, fieldnames)

    if args.write_summary:
        with open(os.path.splitext(path)[0] + '_accepted.json', 'w') as f:
            json.dump([r for r in rows if r['accepted'] == 'yes'], f, indent=2)


def parse_args():
    p = argparse.ArgumentParser(description='Search commitment parameters.')
    p.add_argument('--Ns', type=int, nargs='+', default=[256, 512])
    p.add_argument('--l-M', dest='l_M', type=int, nargs='+', default=[1, 2, 4, 8, 16])
    p.add_argument('--k_s', dest='k_s', type=int, nargs='+', default=[1, 2, 3, 4, 6, 8])
    p.add_argument('--n_c', dest='n_c', type=int, nargs='+', default=[1, 2, 3, 4, 5, 6, 8, 10, 12])
    p.add_argument('--B', dest='B', type=int, nargs='+', default=[1, 2, 3, 4, 5, 8, 16])
    p.add_argument('--bits-start', type=int, default=12)
    p.add_argument('--bits-end', type=int, default=30)
    p.add_argument('--qs-per-bit', type=int, default=1)
    p.add_argument('--max-delta-steps', type=int, default=2000)
    p.add_argument('--q', type=int, nargs='+', default=None)
    p.add_argument('--params-json', type=str, default=None)
    p.add_argument('--min-bits', type=float, default=128.0)
    p.add_argument('--full-threshold', type=float, default=120.0)
    p.add_argument('--run-full', action='store_true')
    p.add_argument('--require-fully-split', dest='require_fully_split', action='store_true', default=True)
    p.add_argument('--estimator-path', dest='estimator_path', default='/tmp/lattice-estimator-dklw')
    p.add_argument('--output', default='parameter_search/results/commitment_placeholder.csv')
    p.add_argument('--write-summary', action='store_true')
    p.add_argument('--stop-at-first', action='store_true', default=False, help='stop after first accepted candidate (first in loop order)')
    p.add_argument('--echo-first', action='store_true', help='print first accepted candidate when --stop-at-first is used')
    return p.parse_args()


if __name__ == '__main__':
    args = parse_args()
    run_search(args)
