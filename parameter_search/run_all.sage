#!/usr/bin/env sage
from __future__ import annotations

import argparse
import csv
import os
import subprocess
import subprocess as sp
import json

from common import safe_float_log2

def read_rows(path):
    with open(path, newline='') as f:
        return list(csv.DictReader(f))


def run(cmd):
    print(f"$ {' '.join(cmd)}")
    p = sp.run(cmd, check=False)
    if p.returncode != 0:
        raise RuntimeError(f"command failed: {' '.join(cmd)}")


def top10(rows, key):
    out = []
    for r in rows:
        if r.get('accepted', '').lower() != 'yes':
            continue
        k = float(r.get(key, 'nan')) if r.get(key, '') else float('nan')
        out.append((k, r))
    out = [x for x in out if x[0] == x[0]]
    out.sort(key=lambda z: (-z[0], z[1].get('q', 0)))
    # preference closeness to 128 below and extra tie-breakers after selection
    return out[:10]


def write_summary(args, commit_paths, sig_paths, ntru_paths):
    c256 = read_rows(commit_paths[256])
    c512 = read_rows(commit_paths[512])
    s256 = read_rows(sig_paths[256])
    s512 = read_rows(sig_paths[512])
    n256 = read_rows(ntru_paths[256])
    n512 = read_rows(ntru_paths[512])

    def best_note(rows):
        acc = [r for r in rows if r.get('accepted') == 'yes']
        if not acc:
            return 'no candidate found'
        top = max(acc, key=lambda r: float(r.get('log2_rop', r.get('sec_bits', '0')) or 0))
        return f"q={top['q']}, sec={top.get('log2_rop') or top.get('sec_bits')}"

    lines = []
    lines.append('# parameter_search summary')
    lines.append('')
    lines.append('## Executed commands')
    lines.append('```')
    lines.append(' '.join(['estimator_path', args.estimator_path]))
    lines.append('```')
    lines.append('')

    lines.append('## Top candidate notes')
    lines.append(f"N=256 commitment: {best_note(c256)}")
    lines.append(f"N=512 commitment: {best_note(c512)}")
    lines.append(f"N=256 signature: {best_note(s256)}")
    lines.append(f"N=512 signature: {best_note(s512)}")
    lines.append(f"N=256 NTRU: {best_note(n256)}")
    lines.append(f"N=512 NTRU: {best_note(n512)}")

    lines.append('')
    lines.append('## Files')
    lines.append(f"- commitment_N256: {commit_paths[256]}")
    lines.append(f"- commitment_N512: {commit_paths[512]}")
    lines.append(f"- signature_N256: {sig_paths[256]}")
    lines.append(f"- signature_N512: {sig_paths[512]}")
    lines.append(f"- ntru_N256: {ntru_paths[256]}")
    lines.append(f"- ntru_N512: {ntru_paths[512]}")
    lines.append(f"- combined_N256: parameter_search/results/combined_N256.csv")
    lines.append(f"- combined_N512: parameter_search/results/combined_N512.csv")

    with open(args.summary, 'w') as f:
        f.write('\n'.join(lines) + '\n')


def write_estimator_commit(path):
    commit = 'unknown'
    try:
        commit = sp.check_output(['git', '-C', path, 'rev-parse', '--short', 'HEAD']).decode().strip()
    except Exception:
        pass
    with open('parameter_search/estimator_commit.txt', 'w') as f:
        f.write(f"lattice_estimator_path={os.path.abspath(path)}\n")
        f.write(f"lattice_estimator_commit={commit}\n")


def parse_args():
    p = argparse.ArgumentParser(description='Run full parameter search workflow.')
    p.add_argument('--estimator-path', default='/tmp/lattice-estimator-dklw')
    p.add_argument('--qs-per-bit', type=int, default=1)
    p.add_argument('--bits-start', type=int, default=12)
    p.add_argument('--bits-end', type=int, default=30)
    p.add_argument('--full', action='store_true', help='run full estimator modes')
    p.add_argument('--summary', default='parameter_search/results/summary.md')
    return p.parse_args()


if __name__ == '__main__':
    args = parse_args()

    base = os.getcwd()
    write_estimator_commit(args.estimator_path)

    commit_paths = {
        256: 'parameter_search/results/commitment_N256.csv',
        512: 'parameter_search/results/commitment_N512.csv',
    }
    sig_paths = {
        256: 'parameter_search/results/signature_N256.csv',
        512: 'parameter_search/results/signature_N512.csv',
    }
    ntru_paths = {
        256: 'parameter_search/results/ntru_N256.csv',
        512: 'parameter_search/results/ntru_N512.csv',
    }

    for N, out in commit_paths.items():
        cmd = [
            'python3', 'parameter_search/search_commitment.sage',
            '--Ns', str(N),
            '--output', out,
            '--qs-per-bit', str(args.qs_per_bit),
            '--bits-start', str(args.bits_start),
            '--bits-end', str(args.bits_end),
            '--estimator-path', args.estimator_path,
            '--write-summary',
        ]
        if args.full:
            cmd.append('--run-full')
        run(cmd)

    for N, out in sig_paths.items():
        cmd = [
            'python3', 'parameter_search/search_signature.sage',
            '--Ns', str(N),
            '--output', out,
            '--qs-per-bit', str(args.qs_per_bit),
            '--bits-start', str(args.bits_start),
            '--bits-end', str(args.bits_end),
            '--estimator-path', args.estimator_path,
        ]
        if args.full:
            cmd.append('--run-full')
        run(cmd)

    for N, out in ntru_paths.items():
        cmd = [
            'python3', 'parameter_search/search_ntru.sage',
            '--Ns', str(N),
            '--output', out,
            '--qs-per-bit', str(args.qs_per_bit),
            '--bits-start', str(args.bits_start),
            '--bits-end', str(args.bits_end),
            '--estimator-path', args.estimator_path,
        ]
        if args.full:
            cmd.append('--run-full')
        run(cmd)

    # combine candidates per N
    run([
        'python3', 'parameter_search/combine_candidates.sage',
        '--commitment-csv', commit_paths[256],
        '--signature-csv', sig_paths[256],
        '--ntru-csv', ntru_paths[256],
    ])
    run([
        'python3', 'parameter_search/combine_candidates.sage',
        '--commitment-csv', commit_paths[512],
        '--signature-csv', sig_paths[512],
        '--ntru-csv', ntru_paths[512],
    ])

    write_summary(args, commit_paths, sig_paths, ntru_paths)
