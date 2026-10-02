/*
 * mathtest c -- ChaCha20-Poly1305 cost per keystroke on ELKS.
 *
 * Calls Dropbear's real chacha20-poly1305@openssh.com code
 * (dropbear_mode_chachapoly in src/chachapoly.c) the same way packet.c
 * does, on a keystroke-sized packet.  One "keystroke round" is what the
 * client does per typed character: encrypt the outgoing packet, then
 * read the echo (aead_getlength on the first 8 bytes, then aead_crypt
 * to verify the tag and decrypt).
 *
 * Built with Dropbear's real headers (see Makefile.elks), separately from
 * mathtest.c, which uses the test-crypto shadow headers.
 */

/* ../src explicitly: this directory has a shadow includes.h for the
 * host tests. */
#include "../src/includes.h"
#include "algo.h"
#include "chachapoly.h"

#include <sys/time.h>

#include "chachapoly_vectors.h"

#ifdef __ia16__
void chacha_block_ia16(unsigned char *output, const ulong32 *input);
#endif

#define ROUNDS 10       /* timed keystroke rounds */
#define OPS 20          /* timed iterations for the per-primitive figures */

/* Dropbear helpers that chachapoly.c and libtomcrypt's zeromem() call,
 * so mathtest doesn't need the rest of Dropbear. */
void m_burn(void *data, unsigned int len)
{
	volatile unsigned char *p = data;

	while (len--) {
		*p++ = 0;
	}
}

int constant_time_memcmp(const void *a, const void *b, size_t n)
{
	const unsigned char *xa = a, *xb = b;
	unsigned char c = 0;
	size_t i;

	for (i = 0; i < n; i++) {
		c |= (xa[i] ^ xb[i]);
	}
	return c;
}

static long cs_since(const struct timeval *t0)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);
	return (long)(tv.tv_sec - t0->tv_sec) * 100
		+ (long)(tv.tv_usec - t0->tv_usec) / 10000;
}

/* Print total centiseconds as milliseconds per iteration. */
static void report(const char *what, long cs, int n)
{
	long ms = cs * 10 / n;

	printf("  %-36s %5ld ms\n", what, ms);
}

int test_chachapoly(void)
{
	const struct dropbear_cipher_mode *m = &dropbear_mode_chachapoly;
	dropbear_chachapoly_state st;
	poly1305_state poly;
	unsigned char ct[CP_LEN + 16], pt[CP_LEN + 16], blk[64], tag[16];
	unsigned long taglen;
	uint32_t plen;
	struct timeval t0;
	long cs;
	int i, fails = 0;

	printf("chachapoly: %d-byte keystroke packet\n", CP_LEN);
	fflush(stdout);

	if (m->start(0, NULL, cp_key, 64, 0, &st) != CRYPT_OK) {
		printf("chachapoly correctness: FAIL (start)\n");
		return 1;
	}

	/* Known answer: encrypt must match the independently computed
	 * ciphertext + tag, and decrypting it must give the packet back. */
	memcpy(ct, cp_plain, CP_LEN);
	if (m->aead_crypt(CP_SEQ, ct, ct, CP_LEN, 16, &st, LTC_ENCRYPT) != CRYPT_OK
			|| memcmp(ct, cp_cipher, CP_LEN + 16) != 0) {
		printf("chachapoly encrypt: FAIL\n");
		fails++;
	}
	if (m->aead_getlength(CP_SEQ, cp_cipher, &plen, 8, &st) != CRYPT_OK
			|| plen != CP_LEN - 4) {
		printf("chachapoly length: FAIL\n");
		fails++;
	}
	memcpy(pt, cp_cipher, CP_LEN + 16);
	if (m->aead_crypt(CP_SEQ, pt, pt, CP_LEN, 16, &st, LTC_DECRYPT) != CRYPT_OK
			|| memcmp(pt, cp_plain, CP_LEN) != 0) {
		printf("chachapoly decrypt: FAIL\n");
		fails++;
	}
	memcpy(pt, cp_cipher, CP_LEN + 16);
	pt[CP_LEN + 3] ^= 1;
	if (m->aead_crypt(CP_SEQ, pt, pt, CP_LEN, 16, &st, LTC_DECRYPT) == CRYPT_OK) {
		printf("chachapoly bad-tag rejection: FAIL\n");
		fails++;
	}

	/* One keystroke round: encrypt ours, then length + decrypt the echo. */
	gettimeofday(&t0, NULL);
	for (i = 0; i < ROUNDS; i++) {
		memcpy(ct, cp_plain, CP_LEN);
		m->aead_crypt(CP_SEQ + i, ct, ct, CP_LEN, 16, &st, LTC_ENCRYPT);
		m->aead_getlength(CP_SEQ + i, ct, &plen, 8, &st);
		m->aead_crypt(CP_SEQ + i, ct, pt, CP_LEN, 16, &st, LTC_DECRYPT);
	}
	cs = cs_since(&t0);
	printf("chachapoly elapsed: %ld.%02ld seconds for %d rounds\n",
		cs / 100, cs % 100, ROUNDS);
	report("per keystroke (send + receive)", cs, ROUNDS);

	gettimeofday(&t0, NULL);
	for (i = 0; i < ROUNDS; i++) {
		memcpy(ct, cp_plain, CP_LEN);
		m->aead_crypt(CP_SEQ + i, ct, ct, CP_LEN, 16, &st, LTC_ENCRYPT);
	}
	report("  encrypt one packet", cs_since(&t0), ROUNDS);

	/* The two primitives on their own. */
	memset(blk, 0, sizeof(blk));
	gettimeofday(&t0, NULL);
	for (i = 0; i < OPS; i++) {
		chacha_crypt(&st.chacha, blk, sizeof(blk), blk);
	}
	report("  ChaCha20, one 64-byte block", cs_since(&t0), OPS);

#ifdef __ia16__
	/* The asm block alone, without chacha_crypt()'s C wrapper (byte-wise
	 * XOR, keystream copy, counter update). */
	gettimeofday(&t0, NULL);
	for (i = 0; i < OPS; i++) {
		chacha_block_ia16(blk, st.chacha.input);
	}
	report("    of which the asm block itself", cs_since(&t0), OPS);
#endif

	gettimeofday(&t0, NULL);
	for (i = 0; i < OPS; i++) {
		poly1305_init(&poly, cp_key, 32);
		poly1305_process(&poly, cp_cipher, CP_LEN);
		taglen = sizeof(tag);
		poly1305_done(&poly, tag, &taglen);
	}
	report("  Poly1305 MAC of one packet", cs_since(&t0), OPS);

	printf("chachapoly correctness: %s\n", fails ? "FAIL" : "PASS");
	return fails ? 1 : 0;
}
