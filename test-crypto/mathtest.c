/*
 * mathtest — standalone Curve25519 / Ed25519 benchmark for ELKS.
 *
 * Builds against the exact src/curve25519.c that ships in `ssh` (same
 * options: X25519 + Ed25519 verify).  Wrap with `time mathtest` on ELKS
 * to measure the field-arithmetic hot paths without waiting for a full
 * SSH handshake.
 *
 *   mathtest       all of the below
 *   mathtest x     X25519 only: 1 timed scalarmult + 1 untimed check
 *   mathtest e     Ed25519 only: 1 timed verify (it is its own check),
 *                  with a per-stage breakdown
 *   mathtest c     ChaCha20-Poly1305 cost per keystroke (mathtest_chacha.c)
 *
 * 8088 timing is deterministic (no cache, no branch prediction, no DVFS),
 * so a single run is a solid measurement.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>

#include "curve25519.h"
#include "ed25519_vectors.h"

/* Fixed known-answer values from RFC 7748 §5.2 vector 1. */
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

int test_chachapoly(void);   /* mathtest_chacha.c */

/* curve25519.c only references genrandom() from key generation and
 * signing, which mathtest never calls. */
void genrandom(unsigned char *buf, unsigned int len)
{
    memset(buf, 0, len);
}

/* Stage timestamps, recorded silently and printed once the screen is
 * restored.  Filled by curve25519_profile_mark() from inside verify. */
#define MAX_MARKS 8
static struct { const char *what; long cs; } marks[MAX_MARKS];
static int nmarks;
static struct timeval mark_t0;

static long cs_since(const struct timeval *t0)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (long)(tv.tv_sec - t0->tv_sec) * 100
        + (long)(tv.tv_usec - t0->tv_usec) / 10000;
}

void curve25519_profile_mark(const char *what)
{
    if (nmarks == 0) {
        gettimeofday(&mark_t0, NULL);
    }
    if (nmarks < MAX_MARKS) {
        marks[nmarks].what = what;
        marks[nmarks].cs = cs_since(&mark_t0);
        nmarks++;
    }
}

/* Blank the console for long runs: clear screen + cursor home + hide
 * cursor.  Reduces phosphor wear on the CRT. */
static void blank(void)
{
    fputs("\033[2J\033[H\033[?25l", stdout);
    fflush(stdout);
}

static void unblank(void)
{
    fputs("\033[?25h\033[2J\033[H", stdout);
    fflush(stdout);
}

static int test_x25519(void)
{
    unsigned char out[32];
    time_t t0, t1;

    printf("x25519: 1 timed scalarmult + 1 correctness check\n");
    fflush(stdout);
    blank();
    t0 = time(NULL);
    dropbear_curve25519_scalarmult(out, scalar_init, u_init);
    t1 = time(NULL);
    unblank();
    printf("x25519 elapsed: %ld seconds\n", (long)(t1 - t0));

    /* Separate untimed run so the check can't be skipped by accident. */
    dropbear_curve25519_scalarmult(out, scalar_init, u_init);
    if (memcmp(out, expected, 32) == 0) {
        printf("x25519 correctness: PASS\n");
        return 0;
    }
    printf("x25519 correctness: FAIL\n");
    return 1;
}

static int test_ed25519(void)
{
    /* RFC 8032 §7.1 test 1 (empty message). */
    const unsigned char *pk = (const unsigned char *)ed_vectors[0].pk;
    const unsigned char *sig = (const unsigned char *)ed_vectors[0].sig;
    const unsigned char *msg = (const unsigned char *)ed_vectors[0].msg;
    unsigned long mlen = ed_vectors[0].mlen;
    struct timeval t0;
    long total;
    int rc, i;

    printf("ed25519: 1 timed verify (RFC 8032 test 1)\n");
    fflush(stdout);
    nmarks = 0;
    blank();
    gettimeofday(&t0, NULL);
    rc = dropbear_ed25519_verify(msg, mlen, sig, 64, pk);
    total = cs_since(&t0);
    unblank();

    printf("ed25519 elapsed: %ld.%02ld seconds\n", total / 100, total % 100);
    for (i = 1; i < nmarks; i++) {
        long d = marks[i].cs - marks[i-1].cs;
        printf("  %-28s %5ld.%02ld s\n", marks[i].what, d / 100, d % 100);
    }
    /* A wrong field result makes the recomputed R differ from the one in
     * the signature, so acceptance of a valid signature is the check. */
    printf("ed25519 correctness: %s\n", rc == 0 ? "PASS" : "FAIL");
    return rc == 0 ? 0 : 1;
}

int main(int argc, char **argv)
{
    int do_x = 1, do_e = 1, do_c = 1, fails = 0;

    if (argc > 1) {
        do_x = strchr(argv[1], 'x') != NULL;
        do_e = strchr(argv[1], 'e') != NULL;
        do_c = strchr(argv[1], 'c') != NULL;
        if (!do_x && !do_e && !do_c) {
            fprintf(stderr, "usage: %s [x|e|c, combinable]\n", argv[0]);
            return 2;
        }
    }
    if (do_c) {
        fails += test_chachapoly();
    }
    if (do_x) {
        fails += test_x25519();
    }
    if (do_e) {
        fails += test_ed25519();
    }
    return fails ? 1 : 0;
}
