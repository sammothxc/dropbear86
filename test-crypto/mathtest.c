/*
 * mathtest — standalone Curve25519 scalarmult benchmark for ELKS.
 *
 * Builds against the exact src/curve25519.c that ships in `ssh`.  Runs a
 * fixed number of scalar mults against a known-answer test vector and
 * prints elapsed time.  Wrap with `time ./mathtest` on ELKS to get an
 * accurate wall-clock measurement of the field-arithmetic hot path
 * without waiting for a full SSH handshake.
 *
 * Iteration count is deliberately small so the whole run fits comfortably
 * inside a few minutes of a 4.77 MHz 8086.  Bump ITERATIONS if you have
 * patience.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "curve25519.h"

/* One chained scalarmult + one correctness check = 2 scalarmults total.
 * On a 4.77 MHz 8088, each Curve25519 scalarmult is roughly 8-12 minutes
 * with the current implementation, so this keeps the whole run under
 * ~25 minutes. Bump this if you want more averaging — but 8088 timing
 * is fully deterministic (no cache, no branch prediction, no DVFS), so
 * one iteration is a solid measurement on its own. */
#define ITERATIONS 1

/* Fixed known-answer values from RFC 7748 §5.2 vector 1.
 * Every iteration folds the previous output back into the scalar so the
 * loop can't be constant-folded by the optimiser. */
static const unsigned char scalar_init[32] = {
    0xa5, 0x46, 0xe3, 0x6b, 0xf0, 0x52, 0x7c, 0x9d,
    0x3b, 0x16, 0x15, 0x4b, 0x82, 0x46, 0x5e, 0xdd,
    0x62, 0x14, 0x4c, 0x0a, 0xc1, 0xfc, 0x5a, 0x18,
    0x50, 0x6a, 0x22, 0x44, 0xba, 0x44, 0x9a, 0xc4
};
static const unsigned char u_init[32] = {
    0xe6, 0xdb, 0x68, 0x67, 0x58, 0x30, 0x30, 0xdb,
    0x35, 0x94, 0xc1, 0xa4, 0x24, 0xb1, 0x5f, 0x7c,
    0x72, 0x66, 0x24, 0xec, 0x26, 0xb3, 0x35, 0x3b,
    0x10, 0xa9, 0x03, 0xa6, 0xd0, 0xab, 0x1c, 0x4c
};
static const unsigned char expected[32] = {
    0xc3, 0xda, 0x55, 0x37, 0x9d, 0xe9, 0xc6, 0x90,
    0x8e, 0x94, 0xea, 0x4d, 0xf2, 0x8d, 0x08, 0x4f,
    0x32, 0xec, 0xcf, 0x03, 0x49, 0x1c, 0x71, 0xf7,
    0x54, 0xb4, 0x07, 0x55, 0x77, 0xa2, 0x85, 0x52
};

int main(void) {
    unsigned char scalar[32], u[32], out[32];
    int i;
    time_t t0, t1;

    memcpy(scalar, scalar_init, 32);
    memcpy(u, u_init, 32);

    printf("mathtest: %d chained scalarmult%s + 1 correctness check\n",
           ITERATIONS, ITERATIONS == 1 ? "" : "s");
    fflush(stdout);

    /* Blank the console for the duration: clear screen + cursor home +
     * hide cursor.  Reduces phosphor wear on the CRT during long runs
     * (mathtest can take 15-25 min on real 8088 hardware).  Restored
     * to normal at the end so the elapsed line is visible. */
    fputs("\033[2J\033[H\033[?25l", stdout);
    fflush(stdout);

    t0 = time(NULL);
    for (i = 0; i < ITERATIONS; i++) {
        dropbear_curve25519_scalarmult(out, scalar, u);
        /* Chain output into scalar so the loop is data-dependent. */
        memcpy(scalar, out, 32);
        scalar[0] &= 248;
        scalar[31] &= 127;
        scalar[31] |= 64;
    }
    t1 = time(NULL);

    /* Restore cursor + clear one more time so the result lands on a
     * fresh screen. */
    fputs("\033[?25h\033[2J\033[H", stdout);
    fflush(stdout);

    printf("elapsed: %ld seconds\n", (long)(t1 - t0));

    /* Only the FIRST iteration matches RFC 7748 vector 1 (before we started
     * chaining), so we can't just check the final output.  Re-run once with
     * fixed inputs to prove the algorithm is still correct. */
    dropbear_curve25519_scalarmult(out, scalar_init, u_init);
    if (memcmp(out, expected, 32) == 0) {
        printf("correctness: PASS\n");
        return 0;
    } else {
        printf("correctness: FAIL\n");
        return 1;
    }
}
