#!/usr/bin/env python3
"""Evaluate a Terraform plan JSON against all controls using the Python oracle (no OPA needed). Exit 1 if violations."""
import json, os, sys
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "controls"))
from definitions import CONTROLS
import engine
plan = json.load(open(sys.argv[1], encoding="utf-8"))
v = [x for c in CONTROLS for x in engine.evaluate(c, plan)]
print("\n".join(v) or "no violations"); print(f"{len(v)} violation(s)")
sys.exit(1 if v else 0)
