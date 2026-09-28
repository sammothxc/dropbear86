/*
 * Desktop test harness for src/curve25519.c
 *
 * Runs RFC 7748 §5.2 X25519 vectors and a timing benchmark on top of the
 * exact same source file that ships in the ELKS build. Used to iterate on
 * field-arithmetic changes without having to redeploy to a slow target.
 *
 * Build: cd test-crypto && make
 * Run:   ./test_x25519            # correctness + benchmark
 */

#define _POSIX_C_SOURCE 200112L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

#include "curve25519.h"

/* -- Vector helpers -- */

static int hex2bin(const char *hex, unsigned char *out, size_t out_len) {
    size_t i;
    if (strlen(hex) != 2 * out_len) return -1;
    for (i = 0; i < out_len; i++) {
        unsigned int b;
        if (sscanf(hex + 2 * i, "%2x", &b) != 1) return -1;
        out[i] = (unsigned char)b;
    }
    return 0;
}

static void hex_print(const unsigned char *buf, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) printf("%02x", buf[i]);
}

static int check_vector(const char *label,
                        const char *scalar_hex,
                        const char *u_hex,
                        const char *expect_hex) {
    unsigned char scalar[32], u[32], out[32], expect[32];
    if (hex2bin(scalar_hex, scalar, 32) < 0 ||
        hex2bin(u_hex, u, 32) < 0 ||
        hex2bin(expect_hex, expect, 32) < 0) {
        fprintf(stderr, "%s: hex parse failed\n", label);
        return 1;
    }

    dropbear_curve25519_scalarmult(out, scalar, u);

    if (memcmp(out, expect, 32) != 0) {
        printf("%-32s FAIL\n", label);
        printf("  got:      "); hex_print(out, 32); printf("\n");
        printf("  expected: "); hex_print(expect, 32); printf("\n");
        return 1;
    }
    printf("%-32s ok\n", label);
    return 0;
}

/* -- Benchmark -- */

static void benchmark(int iterations) {
    unsigned char scalar[32], base[32], out[32];
    struct timespec t0, t1;
    int i;
    double elapsed_ms, per_op_ms;

    memset(scalar, 0x11, 32);
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;
    memset(base, 0, 32);
    base[0] = 9;   /* Curve25519 basepoint */

    printf("\nBenchmarking dropbear_curve25519_scalarmult (%d iterations)...\n",
           iterations);
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (i = 0; i < iterations; i++) {
        dropbear_curve25519_scalarmult(out, scalar, base);
        /* chain output into next scalar so the loop can't be hoisted */
        scalar[0] ^= out[0];
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);

    elapsed_ms = (t1.tv_sec - t0.tv_sec) * 1000.0
               + (t1.tv_nsec - t0.tv_nsec) / 1e6;
    per_op_ms = elapsed_ms / iterations;

    printf("  total:  %.2f ms\n", elapsed_ms);
    printf("  per op: %.3f ms (%.0f ops/sec)\n",
           per_op_ms, 1000.0 / per_op_ms);
}

int main(void) {
    int fails = 0;

    /* RFC 7748 §5.2 test vectors */
    fails += check_vector(
        "RFC 7748 §5.2 vector 1",
        "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
        "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
        "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");

    fails += check_vector(
        "RFC 7748 §5.2 vector 2",
        "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
        "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
        "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");

    /* RFC 7748 §6.1: alice_public = X25519(alice_priv, 9) */
    fails += check_vector(
        "RFC 7748 §6.1 Alice pub",
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        "0900000000000000000000000000000000000000000000000000000000000000",
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");

    fails += check_vector(
        "RFC 7748 §6.1 Bob pub",
        "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
        "0900000000000000000000000000000000000000000000000000000000000000",
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");

    fails += check_vector(
        "RFC 7748 §6.1 shared secret",
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
        "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

    printf("\n%s: %d failure(s)\n", fails ? "FAIL" : "PASS", fails);

    if (fails == 0) {
        benchmark(50);
    }

    return fails ? 1 : 0;
}
