#!/usr/bin/env sage

import os
import sys

SCRIPT_DIR = os.path.join(os.getcwd(), "parameter_search")
if not os.path.isdir(SCRIPT_DIR):
    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

from common import *  # noqa: F401,F403
