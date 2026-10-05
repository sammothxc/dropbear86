/*
 * Poly1305 with 16-bit limbs, for ia16.
 *
 * Drop-in replacement for libtomcrypt's poly1305_init/process/done on
 * ELKS.  libtomcrypt's version keeps the 130-bit accumulator in 26-bit
 * limbs and multiplies them into 64-bit products, which ia16-elf-gcc turns
 * into library calls (~84 ms per keystroke packet on a 4.77 MHz 8088).
 * Here h and r are ten 13-bit limbs in 16-bit words, so every product is
 * 16x16->32: one MUL instruction on the 8086.
 *
 * Same algorithm and limb layout as poly1305-donna's 16-bit variant by
 * Andrew Moon (public domain / MIT).  On ia16 the multiply-and-reduce step
 * (p16_mulmod, 100 products per block) is 8086 assembly in
 * src/poly1305_ia16.S, which must match the C version bit for bit.  Selected by LTC_POLY1305_16BIT,
 * which tomcrypt_mac.h defines for __ia16__ along with the matching
 * poly1305_state layout; Makefile.elks builds this file instead of
 * libtomcrypt's mac/poly1305/poly1305.c.
 */

#ifndef POLY1305_16_HOST_TEST
#include "includes.h"
#endif

#ifdef LTC_POLY1305_16BIT

#define P16_BLOCK 16

static uint16_t p16_load(const unsigned char *p)
{
	return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static void p16_store(unsigned char *p, uint16_t v)
{
	p[0] = (unsigned char)v;
	p[1] = (unsigned char)(v >> 8);
}

int poly1305_init(poly1305_state *st, const unsigned char *key, unsigned long keylen)
{
	uint16_t t0, t1, t2, t3, t4, t5, t6, t7;
	int i;

	LTC_ARGCHK(st != NULL);
	LTC_ARGCHK(key != NULL);
	LTC_ARGCHK(keylen == 32);

	/* r = key[0..15], clamped, as 13-bit limbs */
	t0 = p16_load(&key[0]);
	t1 = p16_load(&key[2]);
	t2 = p16_load(&key[4]);
	t3 = p16_load(&key[6]);
	t4 = p16_load(&key[8]);
	t5 = p16_load(&key[10]);
	t6 = p16_load(&key[12]);
	t7 = p16_load(&key[14]);
	st->r[0] = t0 & 0x1fff;
	st->r[1] = ((t0 >> 13) | (t1 << 3)) & 0x1fff;
	st->r[2] = ((t1 >> 10) | (t2 << 6)) & 0x1f03;
	st->r[3] = ((t2 >> 7) | (t3 << 9)) & 0x1fff;
	st->r[4] = ((t3 >> 4) | (t4 << 12)) & 0x00ff;
	st->r[5] = (t4 >> 1) & 0x1ffe;
	st->r[6] = ((t4 >> 14) | (t5 << 2)) & 0x1fff;
	st->r[7] = ((t5 >> 11) | (t6 << 5)) & 0x1f81;
	st->r[8] = ((t6 >> 8) | (t7 << 8)) & 0x1fff;
	st->r[9] = (t7 >> 5) & 0x007f;
	/* 2^130 == 5 mod p, so products wrapping past limb 9 use 5*r */
	for (i = 0; i < 10; i++) {
		st->r[10 + i] = (uint16_t)(st->r[i] * 5);
	}

	/* s = key[16..31], added at the end */
	for (i = 0; i < 8; i++) {
		st->pad[i] = p16_load(&key[16 + 2 * i]);
		st->h[i] = 0;
	}
	st->h[8] = 0;
	st->h[9] = 0;
	st->leftover = 0;
	st->final = 0;
	return CRYPT_OK;
}

#ifdef __ia16__
void poly1305_mulmod_ia16(uint16_t h[10], const uint16_t r[20]);
#define p16_mulmod poly1305_mulmod_ia16
#else
/* h = h * r, partially reduced mod 2^130 - 5.  r[10..19] holds 5*r. */
static void p16_mulmod(uint16_t h[10], const uint16_t r[20])
{
	uint32_t d[10];
	uint32_t c;
	int i, j;

	for (i = 0, c = 0; i < 10; i++) {
		d[i] = c;
		for (j = 0; j < 10; j++) {
			d[i] += (uint32_t)h[j] * ((j <= i) ? r[i - j] : r[10 + i + 10 - j]);
			/* carry part-way through so the sum can't overflow 32 bits */
			if (j == 4) {
				c = d[i] >> 13;
				d[i] &= 0x1fff;
			}
		}
		c += d[i] >> 13;
		d[i] &= 0x1fff;
	}
	c = (c << 2) + c;	/* c *= 5 */
	c += d[0];
	d[0] = c & 0x1fff;
	c >>= 13;
	d[1] += c;

	for (i = 0; i < 10; i++) {
		h[i] = (uint16_t)d[i];
	}
}
#endif

static void p16_blocks(poly1305_state *st, const unsigned char *m, unsigned long bytes)
{
	const uint16_t hibit = st->final ? 0 : (1 << 11);	/* 2^128 */
	uint16_t t0, t1, t2, t3, t4, t5, t6, t7;

	while (bytes >= P16_BLOCK) {
		t0 = p16_load(&m[0]);
		t1 = p16_load(&m[2]);
		t2 = p16_load(&m[4]);
		t3 = p16_load(&m[6]);
		t4 = p16_load(&m[8]);
		t5 = p16_load(&m[10]);
		t6 = p16_load(&m[12]);
		t7 = p16_load(&m[14]);

		/* h += m */
		st->h[0] += t0 & 0x1fff;
		st->h[1] += ((t0 >> 13) | (t1 << 3)) & 0x1fff;
		st->h[2] += ((t1 >> 10) | (t2 << 6)) & 0x1fff;
		st->h[3] += ((t2 >> 7) | (t3 << 9)) & 0x1fff;
		st->h[4] += ((t3 >> 4) | (t4 << 12)) & 0x1fff;
		st->h[5] += (t4 >> 1) & 0x1fff;
		st->h[6] += ((t4 >> 14) | (t5 << 2)) & 0x1fff;
		st->h[7] += ((t5 >> 11) | (t6 << 5)) & 0x1fff;
		st->h[8] += ((t6 >> 8) | (t7 << 8)) & 0x1fff;
		st->h[9] += (t7 >> 5) | hibit;

		p16_mulmod(st->h, st->r);

		m += P16_BLOCK;
		bytes -= P16_BLOCK;
	}
}

int poly1305_process(poly1305_state *st, const unsigned char *in, unsigned long inlen)
{
	unsigned long i, want;

	LTC_ARGCHK(st != NULL);
	if (inlen == 0) {
		return CRYPT_OK;
	}
	LTC_ARGCHK(in != NULL);

	/* finish a partial block first */
	if (st->leftover) {
		want = P16_BLOCK - st->leftover;
		if (want > inlen) {
			want = inlen;
		}
		for (i = 0; i < want; i++) {
			st->buffer[st->leftover + i] = in[i];
		}
		inlen -= want;
		in += want;
		st->leftover += want;
		if (st->leftover < P16_BLOCK) {
			return CRYPT_OK;
		}
		p16_blocks(st, st->buffer, P16_BLOCK);
		st->leftover = 0;
	}

	/* whole blocks */
	if (inlen >= P16_BLOCK) {
		want = inlen & ~(unsigned long)(P16_BLOCK - 1);
		p16_blocks(st, in, want);
		in += want;
		inlen -= want;
	}

	/* keep the rest */
	for (i = 0; i < inlen; i++) {
		st->buffer[st->leftover + i] = in[i];
	}
	st->leftover += inlen;
	return CRYPT_OK;
}

int poly1305_done(poly1305_state *st, unsigned char *mac, unsigned long *maclen)
{
	uint16_t c, mask, g[10];
	uint32_t f;
	int i;

	LTC_ARGCHK(st != NULL);
	LTC_ARGCHK(mac != NULL);
	LTC_ARGCHK(maclen != NULL);
	LTC_ARGCHK(*maclen >= 16);

	/* last partial block: pad with 1 then zeros, without the 2^128 bit */
	if (st->leftover) {
		i = (int)st->leftover;
		st->buffer[i++] = 1;
		for (; i < P16_BLOCK; i++) {
			st->buffer[i] = 0;
		}
		st->final = 1;
		p16_blocks(st, st->buffer, P16_BLOCK);
	}

	/* fully carry h */
	c = st->h[1] >> 13;
	st->h[1] &= 0x1fff;
	for (i = 2; i < 10; i++) {
		st->h[i] += c;
		c = st->h[i] >> 13;
		st->h[i] &= 0x1fff;
	}
	st->h[0] += (uint16_t)(c * 5);
	c = st->h[0] >> 13;
	st->h[0] &= 0x1fff;
	st->h[1] += c;
	c = st->h[1] >> 13;
	st->h[1] &= 0x1fff;
	st->h[2] += c;

	/* g = h + 5 - 2^130; use it if it didn't go negative (h >= p) */
	g[0] = st->h[0] + 5;
	c = g[0] >> 13;
	g[0] &= 0x1fff;
	for (i = 1; i < 9; i++) {
		g[i] = st->h[i] + c;
		c = g[i] >> 13;
		g[i] &= 0x1fff;
	}
	/* Not masked: the carry into bit 13 here is what says h >= p. */
	g[9] = (uint16_t)(st->h[9] + c - (1 << 13));

	mask = (uint16_t)((g[9] >> 15) - 1);	/* all ones if h >= p */
	for (i = 0; i < 10; i++) {
		g[i] &= mask;
	}
	mask = (uint16_t)~mask;
	for (i = 0; i < 10; i++) {
		st->h[i] = (st->h[i] & mask) | g[i];
	}

	/* h mod 2^128, as eight 16-bit words */
	st->h[0] = (uint16_t)(st->h[0] | (st->h[1] << 13));
	st->h[1] = (uint16_t)((st->h[1] >> 3) | (st->h[2] << 10));
	st->h[2] = (uint16_t)((st->h[2] >> 6) | (st->h[3] << 7));
	st->h[3] = (uint16_t)((st->h[3] >> 9) | (st->h[4] << 4));
	st->h[4] = (uint16_t)((st->h[4] >> 12) | (st->h[5] << 1) | (st->h[6] << 14));
	st->h[5] = (uint16_t)((st->h[6] >> 2) | (st->h[7] << 11));
	st->h[6] = (uint16_t)((st->h[7] >> 5) | (st->h[8] << 8));
	st->h[7] = (uint16_t)((st->h[8] >> 8) | (st->h[9] << 5));

	/* mac = (h + s) mod 2^128 */
	f = (uint32_t)st->h[0] + st->pad[0];
	st->h[0] = (uint16_t)f;
	for (i = 1; i < 8; i++) {
		f = (uint32_t)st->h[i] + st->pad[i] + (f >> 16);
		st->h[i] = (uint16_t)f;
	}
	for (i = 0; i < 8; i++) {
		p16_store(mac + 2 * i, st->h[i]);
	}
	*maclen = 16;

	m_burn(st, sizeof(*st));
	return CRYPT_OK;
}

#endif /* LTC_POLY1305_16BIT */
