# Performance log

Timings measured on real hardware: Compaq Portable Plus, Intel 8088 @ 4.77 MHz.

## Full SSH KEX + client auth to password prompt

Wall-clock time from `ssh user@host` to seeing the password prompt.

| Date       | Commit    | Time    | Notes                                            |
|------------|-----------|---------|--------------------------------------------------|
| 2026-09-27 | ~2bee5b8  | 41 min  | -Os baseline, pre-mul_widen                      |
| 2026-09-28 | 34b57a2   | 35 min  | -O2 + mul_widen + car25519 + M reduction cleanup |
| 2026-10-01 | 7369018   | 8m30s   | Phase 2 asm. Includes typing password, login, `exit` -- not to-prompt; needs server `LoginGraceTime` > 2m |
| 2026-10-01 | 66eca10   | ~3 min  | ~55 s binary load (ELKS relocations) + 124 s main() to password prompt. Double-scalar verify, first-guess key reuse, socket drain vs ktcp polling |

Phase timing for 66eca10 (`DROPBEAR_PHASE_TIMING=1`, seconds since main()): seedrandom 3.7, X25519 keygen 4-35, server KEXINIT 38, KEXDH_REPLY 39, shared secret + exchange hash 73, Ed25519 verify 122, password prompt 124.

## mathtest (curve25519 scalarmult isolated)

`time mathtest`, elapsed seconds reflect ITERATIONS chained scalarmults; divide by ITERATIONS for per-op time. Correctness check runs after (not included in the timed elapsed).

| Date       | Commit    | Iters | Elapsed | Per-op   | Notes                            |
|------------|-----------|-------|---------|----------|----------------------------------|
| 2026-09-30 | 3694f3a   | 4     | 4316 s  | 1079 s   | Phase 2 baseline. -O2, mul_widen |
| 2026-10-01 | 7369018   | 1     | 31 s    | 31 s     | Phase 2: 8086 asm M/S/A/Z, 16-bit limbs (~35x) |

Per-op = ~18 min at the Phase 2 baseline; 31 s after Phase 2. `time mathtest` reports ~2x elapsed (1m4s for the 31 s run) because the untimed correctness check is a second scalarmult.

## mathtest e (Ed25519 verify, RFC 8032 test 1)

Per-stage breakdown printed by `mathtest e` (seconds).

| Date       | Commit    | Total    | decompress A | SHA-512+modL | h*A + s*B          | pack (inv) | Notes |
|------------|-----------|----------|--------------|--------------|--------------------|------------|-------|
| 2026-10-01 | 2fe537b   | 136.28   | 5.26         | 3.65         | 122.11 (61.05+61.06) | 5.25     | Two constant-time ladders |
| 2026-10-01 | 5c2c457   | 47.33*   | 5.28         | 3.65         | 33.27              | 5.13       | Double-scalar sliding window (3.7x on this stage). *Sum of stages; total line not recorded |

## mathtest c (ChaCha20-Poly1305 per keystroke)

A keystroke round is what the client does per typed character: encrypt the 20-byte keystroke packet, then decrypt the echo. Interactive typing on the Compaq has ~1.5 s keystroke-to-echo latency in total (tracked in issue 3).

| Date | Commit | Per keystroke | Encrypt one packet | ChaCha20 block | Poly1305 MAC | Notes |
|------|--------|---------------|--------------------|----------------|--------------|-------|
| 2026-10-02 | 00448f1 | 562 ms | 250 ms | 56 ms | 84 ms | libtomcrypt C (Poly1305 via 64-bit libgcc multiplies) |
| 2026-10-02 | 886e5de | 504 ms | 221 ms | 57 ms | 54 ms | Poly1305 with 16-bit limbs (C) |
| 2026-10-02 | 9aee69c | 354 ms | 161 ms | 36 ms | 54 ms | ChaCha20 block in 8086 asm (26 ms; ~10 ms was libtomcrypt's C wrapper) |
| 2026-10-02 | a084bd0 | 254 ms | 123 ms | 30 ms | 23 ms | 16-bit ChaCha20 wrapper loops, length field decrypted once per received packet (6 blocks per keystroke, not 7), Poly1305 multiply in 8086 asm |

Per keystroke there were 7 ChaCha20 blocks (3 to send, 4 to receive, including the Poly1305 key and length blocks; 6 since a084bd0, which decrypts each received length field once) and 2 Poly1305 MACs; the per-primitive numbers add up to within ~10% of the measured round.

## Roadmap targets (rough)

- Phase 2 (ia16 asm for M/S): target was 3-5x; got ~35x (1079 s → 31 s). Done.
- Phase 3 (precomputed base tables): halves the first-Curve25519 mult per KEX
- Phase B (16-bit-limb C rewrite): 2-3x if pursued cleanly, alone or stacked with Phase 2
