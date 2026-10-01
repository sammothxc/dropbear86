/*
 * Desktop test for the Ed25519 half of src/curve25519.c (host-key
 * signature verification in ssh).  Checks key derivation, deterministic
 * signatures and verification against a reference implementation, plus
 * rejection of corrupted signatures/messages.
 *
 * Build: cd test-crypto && make test
 */

#include <stdio.h>
#include <string.h>

#include "curve25519.h"
#include "ed25519_vectors.h"

/* dropbear_ed25519_make_key() draws the secret key from here. */
static const unsigned char *next_random;
void genrandom(unsigned char *buf, unsigned int len)
{
    memcpy(buf, next_random, len);
}

int main(void)
{
    unsigned int n, fails = 0;
    unsigned char pk[32], sk[32], sig[64], bad[64], msg[256];
    unsigned long slen;

    for (n = 0; n < sizeof(ed_vectors) / sizeof(ed_vectors[0]); n++) {
        const unsigned char *vsk = (const unsigned char *)ed_vectors[n].sk;
        const unsigned char *vpk = (const unsigned char *)ed_vectors[n].pk;
        const unsigned char *vsig = (const unsigned char *)ed_vectors[n].sig;
        unsigned long mlen = ed_vectors[n].mlen;
        int f = 0;

        memcpy(msg, ed_vectors[n].msg, mlen);
        next_random = vsk;
        dropbear_ed25519_make_key(pk, sk);
        if (memcmp(pk, vpk, 32) != 0) {
            printf("vector %u: public key mismatch\n", n);
            f = 1;
        }
        dropbear_ed25519_sign(msg, mlen, sig, &slen, vsk, vpk);
        if (slen != 64 || memcmp(sig, vsig, 64) != 0) {
            printf("vector %u: signature mismatch\n", n);
            f = 1;
        }
        if (dropbear_ed25519_verify(msg, mlen, vsig, 64, vpk) != 0) {
            printf("vector %u: valid signature rejected\n", n);
            f = 1;
        }
        memcpy(bad, vsig, 64);
        bad[n % 32] ^= 0x01;            /* corrupt R */
        if (dropbear_ed25519_verify(msg, mlen, bad, 64, vpk) == 0) {
            printf("vector %u: corrupted R accepted\n", n);
            f = 1;
        }
        memcpy(bad, vsig, 64);
        bad[32 + n % 31] ^= 0x04;       /* corrupt S */
        if (dropbear_ed25519_verify(msg, mlen, bad, 64, vpk) == 0) {
            printf("vector %u: corrupted S accepted\n", n);
            f = 1;
        }
        if (mlen > 0) {
            msg[mlen - 1] ^= 0x80;
            if (dropbear_ed25519_verify(msg, mlen, vsig, 64, vpk) == 0) {
                printf("vector %u: corrupted message accepted\n", n);
                f = 1;
            }
        }
        printf("Ed25519 vector %-2u %s\n", n, f ? "FAIL" : "ok");
        fails += f;
    }
    printf("\n%s: %u failure(s)\n", fails ? "FAIL" : "PASS", fails);
    return fails ? 1 : 0;
}
