#!/usr/bin/env sage

import os
import sys

SCRIPT_DIR = os.path.join(os.getcwd(), "parameter_search")
if not os.path.isdir(SCRIPT_DIR):
    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

from run_all import main

default_args = [
    "--Ns",
    "256",
    "--bounds",
    "ternary",
    "3",
    "4",
    "6",
    "8",
    "--output-dir",
    "parameter_search/results/intgenisis_N256",
]

raise SystemExit(main(sys.argv[1:] or default_args))
