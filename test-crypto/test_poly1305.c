/*
 * Host test for src/poly1305_16.c (the 16-bit-limb Poly1305 used on ia16).
 * Compares against vectors from Python cryptography, feeding each message
 * in one piece and in several chunk sizes to exercise the buffering.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Just enough of libtomcrypt for poly1305_16.c. */
#define LTC_POLY1305_16BIT
#define CRYPT_OK 0
#define LTC_ARGCHK(x) do { if (!(x)) { printf("ARGCHK failed: %s\n", #x); return 1; } } while (0)
typedef struct {
	unsigned short r[20];
	unsigned short h[10];
	unsigned short pad[8];
	unsigned long leftover;
	unsigned char buffer[16];
	int final;
} poly1305_state;
static void m_burn(void *p, unsigned int n) { memset(p, 0, n); }

#define POLY1305_16_HOST_TEST
#include "../src/poly1305_16.c"

#include "poly1305_vectors.h"

int main(void)
{
	static const unsigned long chunks[] = {0, 1, 3, 7, 15, 16, 17, 33};
	unsigned int n, k, fails = 0, checks = 0;
	unsigned char tag[16];

	for (n = 0; n < sizeof(p_vectors) / sizeof(p_vectors[0]); n++) {
		const unsigned char *key = (const unsigned char *)p_vectors[n].key;
		const unsigned char *msg = (const unsigned char *)p_vectors[n].msg;
		unsigned long len = p_vectors[n].len;

		for (k = 0; k < sizeof(chunks) / sizeof(chunks[0]); k++) {
			poly1305_state st;
			unsigned long pos = 0, step = chunks[k] ? chunks[k] : len, taglen = 16;

			poly1305_init(&st, key, 32);
			while (pos < len) {
				unsigned long take = len - pos < step ? len - pos : step;
				poly1305_process(&st, msg + pos, take);
				pos += take;
			}
			poly1305_done(&st, tag, &taglen);
			checks++;
			if (memcmp(tag, p_vectors[n].tag, 16) != 0) {
				printf("vector %u (len %lu, chunk %lu): FAIL\n", n, len, chunks[k]);
				fails++;
			}
		}
	}
	printf("Poly1305 (16-bit limbs): %u checks over %u vectors\n", checks,
		(unsigned)(sizeof(p_vectors) / sizeof(p_vectors[0])));
	printf("\n%s: %u failure(s)\n", fails ? "FAIL" : "PASS", fails);
	return fails ? 1 : 0;
}
