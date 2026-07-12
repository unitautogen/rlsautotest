# Copyright 2026 Munaf Ibrahim Khatri
# SPDX-License-Identifier: Apache-2.0
"""Witness-strategy registry (F1). REGISTRY order IS the old emit_flat dispatch ladder.

To add a new pattern: write a module exposing run(ctx, baker, cmd) -> HANDLED|AUGMENT|PASS
(see strategies/base.py) and insert it here — no edits to emit_flat."""
from .base import AUGMENT, CONTINUE, HANDLED, PASS
from . import custom_role, synth, recursion, mock, solver, relstate, mockforce

REGISTRY = [
    custom_role.run, # F5: probe policies granted TO custom roles via SET ROLE (additive, CONTINUE)
    synth.run,       # GUC / JWT-claim / mocked-scalar-fn gate
    recursion.run,   # self-referential hierarchy (WITH RECURSIVE)
    mock.run,        # opaque boolean policy fn -> wiring proof (AUGMENT: identity battery still runs)
    solver.run,      # general witness solver + construct-first DB-oracle floors
    relstate.run,    # relational-state (cardinality/aggregate) floor
    mockforce.run,   # force-mock last resort (AUGMENT)
]
