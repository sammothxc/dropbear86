# Performance log

Timings measured on real hardware: **Compaq Portable Plus, Intel 8088 @ 4.77 MHz**.

## Full SSH KEX + client auth to password prompt

Wall-clock time from `ssh user@host` to seeing the password prompt.

| Date       | Commit    | Time    | Notes                                            |
|------------|-----------|---------|--------------------------------------------------|
| 2026-09-27 | ~2bee5b8  | 41 min  | -Os baseline, pre-mul_widen                      |
| 2026-09-28 | 34b57a2   | 35 min  | -O2 + mul_widen + car25519 + M reduction cleanup |

## mathtest (curve25519 scalarmult isolated)

`time mathtest`, elapsed seconds reflect **ITERATIONS chained scalarmults**;
divide by ITERATIONS for per-op time.  Correctness check runs after (not
included in the timed elapsed).

| Date       | Commit    | Iters | Elapsed | Per-op   | Notes                            |
|------------|-----------|-------|---------|----------|----------------------------------|
| 2026-09-30 | 3694f3a   | 4     | 4316 s  | 1079 s   | Phase 2 baseline. -O2, mul_widen |
| 2026-10-01 | 7369018   | 1     | 31 s    | 31 s     | Phase 2: 8086 asm M/S/A/Z, 16-bit limbs (~35x) |

Per-op = ~18 min at the Phase 2 baseline; 31 s after Phase 2.
`time mathtest` reports ~2x elapsed (1m4s for the 31 s run) because the
untimed correctness check is a second scalarmult.

## Roadmap targets (rough)

- Phase 2 (ia16 asm for M/S): target was 3-5x; got ~35x (1079 s → 31 s). Done.
- Phase 3 (precomputed base tables): halves the first-Curve25519 mult per KEX
- Phase B (16-bit-limb C rewrite): 2-3x if pursued cleanly, alone or stacked with Phase 2
