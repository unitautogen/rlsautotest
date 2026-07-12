# Copyright 2026 Munaf Ibrahim Khatri
# SPDX-License-Identifier: Apache-2.0
"""The WitnessStrategy protocol (F1).

A strategy is a module exposing  run(ctx, baker, cmd) -> HANDLED | AUGMENT | PASS :

  HANDLED  the strategy fully tested this command (the driver skips the identity battery)
  AUGMENT  the strategy emitted wiring/extra tests but the identity battery still runs
  PASS     not applicable; the driver tries the next strategy in REGISTRY order
  CONTINUE emitted additive tests; the driver keeps trying the remaining strategies

Adding a new pattern = a new module registering itself in strategies/__init__.py — zero
edits to emit_flat. Ordering in the registry IS the old dispatch ladder, preserved:
synth gate -> recursion -> mock (opaque bool fn) -> solver -> relstate -> force-mock.
"""

HANDLED = "handled"
AUGMENT = "augment"
PASS = "pass"
CONTINUE = "continue"
