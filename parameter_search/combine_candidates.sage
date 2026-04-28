#!/usr/bin/env sage
from __future__ import annotations

import argparse
import csv
import os
import math


def read_csv(path):
    with open(path, newline='') as f:
        return list(csv.DictReader(f))


def parse_float(v):
    try:
        return float(v)
    except Exception:
        return None


def is_yes(v):
    return str(v).strip().lower() == 'yes'


def pick_best_ntru(ntru_rows, N, q, min_bits=128.0):
    cand = [r for r in ntru_rows if int(r['N']) == N and int(r['q']) == q and is_yes(r['accepted'])]
    if not cand:
        return None
    # choose full result where available, else rough; pick highest sec
    full_rows = [r for r in cand if r['mode'] == 'full']
    table = full_rows if full_rows else cand
    best = None
    best_sec = -1.0
    for r in table:
        s = parse_float(r.get('ntru_log2_rop'))
        if s is None:
            continue
        if s > best_sec:
            best_sec = s
            best = r
    return best


def combine_rows(commit_rows, sig_rows, ntru_rows, N, s_SW=16):
    sig_by_q = {}
    for r in sig_rows:
        if int(r['N']) != N or not is_yes(r['accepted']):
            continue
        q = int(r['q'])
        sec = parse_float(r.get('sec_bits'))
        if sec is None:
            continue
        if q not in sig_by_q or sec > parse_float(sig_by_q[q].get('sec_bits')):
            sig_by_q[q] = r

    combos = []
    for c in commit_rows:
        if int(c['N']) != N or not is_yes(c['accepted']):
            continue
        q = int(c['q'])
        if q not in sig_by_q:
            continue
        s = sig_by_q[q]
        ntru = pick_best_ntru(ntru_rows, N, q)
        if not ntru:
            ntru_sec = None
            ntru_ok = False
        else:
            ntru_sec = parse_float(ntru.get('ntru_log2_rop'))
            ntru_ok = ntru_sec is not None and ntru_sec >= 128.0

        l_M = int(c['l_M'])
        k_s = int(c['k_s'])
        n_c = int(c['n_c'])
        B = int(c['B'])
        l_m = int(s['l_m'])
        l_r = int(s['l_r'])

        n_t = n_c
        gamma = B * math.sqrt(N * (l_M + k_s + n_c))
        gamma_diff = 2 * B * math.sqrt(N * (l_M + k_s + n_c))
        beta_prime = parse_float(s['beta_sig'])
        beta_prime_expr = None if beta_prime is None else beta_prime + gamma

        L_show = 2 + l_M + k_s + n_c + l_m + l_r + 1 + n_t
        rows_show = L_show * N / s_SW

        # range benchmark check uses commitment bound degree
        range_deg = 2 * B + 1

        hide_sec = parse_float(c['hiding_log2_rop'])
        bind_sec = parse_float(c['binding_log2_rop'])
        sig_sec = parse_float(s['sec_bits'])

        min_sec = min(x for x in [hide_sec, bind_sec, sig_sec] if x is not None)

        # statistical LHL estimate
        l_hl = l_M + k_s + n_c
        try:
            lhs = N * (math.log2(q ** n_t) - l_hl * math.log2(2 * B + 1))
            if lhs > 1024:
                eps = float('inf')
            else:
                eps = 0.5 * math.sqrt((1 + 2 ** lhs) - 1)
        except Exception:
            eps = float('nan')

        combos.append({
            'N': N,
            'q': q,
            'log2_q': c['log2_q'],
            'l_M': l_M,
            'k_s': k_s,
            'n_c': n_c,
            'B': B,
            'l_m': l_m,
            'l_r': l_r,
            'alpha': s['alpha'],
            'commit_hide_sec': '' if hide_sec is None else f"{hide_sec:.3f}",
            'commit_bind_sec': '' if bind_sec is None else f"{bind_sec:.3f}",
            'sig_sec': '' if sig_sec is None else f"{sig_sec:.3f}",
            'ntru_sec': '' if ntru_sec is None else f"{ntru_sec:.3f}",
            'min_sec': '' if min_sec is None else f"{min_sec:.3f}",
            'gamma': f"{gamma:.3f}",
            'gamma_diff': f"{gamma_diff:.3f}",
            'beta_prime_expr': '' if beta_prime_expr is None else f"{beta_prime_expr:.3f}",
            'beta_sig': s['beta_sig'],
            'beta_lt_q': s['beta_lt_q'],
            'beta_lt_q2': s['beta_lt_q2'],
            'x1_inv_prob': f"{(1 - 1 / q) ** N:.8g}",
            'L_show': L_show,
            'rows_show': f"{rows_show:.3f}",
            'range_degree': range_deg,
            'epsilon_stat': '' if not math.isfinite(eps) else f"{eps:.3e}",
            'commit_accepted': c['accepted'],
            'sig_accepted': s['accepted'],
            'ntru_accepted': 'yes' if ntru_ok else 'no',
            'combined_accepted': 'yes' if (is_yes(c['accepted']) and is_yes(s['accepted']) and ntru_ok) else 'no',
            'notes': '',
        })

    combos.sort(key=lambda x: (-(float(x['min_sec']) if x['min_sec'] else -1e9), x['q']))
    return combos


def run_search(args):
    commits = read_csv(args.commitment_csv)
    sigs = read_csv(args.signature_csv)
    ntru = read_csv(args.ntru_csv)

    for N in args.Ns:
        comb = combine_rows(commits, sigs, ntru, N, s_SW=args.s_sw)
        path = f"parameter_search/results/combined_N{N}.csv"
        fieldnames = list(comb[0].keys()) if comb else [
            'N', 'q', 'log2_q', 'l_M', 'k_s', 'n_c', 'B', 'l_m', 'l_r', 'alpha',
            'commit_hide_sec', 'commit_bind_sec', 'sig_sec', 'ntru_sec', 'min_sec', 'gamma',
            'gamma_diff', 'beta_prime_expr', 'beta_sig', 'beta_lt_q', 'beta_lt_q2',
            'x1_inv_prob', 'L_show', 'rows_show', 'range_degree', 'epsilon_stat',
            'commit_accepted', 'sig_accepted', 'ntru_accepted', 'combined_accepted', 'notes'
        ]
        with open(path, 'w', newline='') as f:
            w = csv.DictWriter(f, fieldnames=fieldnames)
            w.writeheader()
            for r in comb:
                w.writerow(r)


def parse_args():
    p = argparse.ArgumentParser(description='Combine commitment, signature and NTRU candidates.')
    p.add_argument('--commitment-csv', default='parameter_search/results/commitment.csv')
    p.add_argument('--signature-csv', default='parameter_search/results/signature.csv')
    p.add_argument('--ntru-csv', default='parameter_search/results/ntru.csv')
    p.add_argument('--Ns', type=int, nargs='+', default=[256, 512])
    p.add_argument('--s-sw', type=int, default=16)
    return p.parse_args()


if __name__ == '__main__':
    run_search(parse_args())
