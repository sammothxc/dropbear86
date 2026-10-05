/*
 * Dropbear SSH
 * 
 * Copyright (c) 2002,2003 Matt Johnston
 * Copyright (c) 2020 by Vladislav Grishenko
 * All rights reserved.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE. */

#include "includes.h"
#include "algo.h"
#include "dbutil.h"
#include "chachapoly.h"

#if DROPBEAR_CHACHA20POLY1305

#define CHACHA20_KEY_LEN 32
#define CHACHA20_BLOCKSIZE 8
#define POLY1305_KEY_LEN 32
#define POLY1305_TAG_LEN 16

static const struct ltc_cipher_descriptor dummy = {.name = NULL};

static const struct dropbear_hash dropbear_chachapoly_mac =
	{NULL, POLY1305_KEY_LEN, POLY1305_TAG_LEN};

const struct dropbear_cipher dropbear_chachapoly =
	{&dummy, CHACHA20_KEY_LEN*2, CHACHA20_BLOCKSIZE};

static int dropbear_chachapoly_start(int UNUSED(cipher), const unsigned char* UNUSED(IV),
			const unsigned char *key, int keylen,
			int UNUSED(num_rounds), dropbear_chachapoly_state *state) {
	int err;

	TRACE2(("enter dropbear_chachapoly_start"))

	if (keylen != CHACHA20_KEY_LEN*2) {
		return CRYPT_ERROR;
	}

	if ((err = chacha_setup(&state->chacha, key,
				CHACHA20_KEY_LEN, 20)) != CRYPT_OK) {
		return err;
	}

	if ((err = chacha_setup(&state->header, key + CHACHA20_KEY_LEN,
				CHACHA20_KEY_LEN, 20) != CRYPT_OK)) {
		return err;
	}
	state->len_valid = 0;
	state->pre_seq = 0;
	state->pre_have = 0;

	TRACE2(("leave dropbear_chachapoly_start"))
	return CRYPT_OK;
}

static int dropbear_chachapoly_crypt(unsigned int seq,
			const unsigned char *in, unsigned char *out,
			unsigned long len, unsigned long taglen,
			dropbear_chachapoly_state *state, int direction) {
	poly1305_state poly;
	unsigned char seqbuf[8], key[POLY1305_KEY_LEN], tag[POLY1305_TAG_LEN];
	unsigned char pre;
	unsigned long i;
	int err;

	TRACE2(("enter dropbear_chachapoly_crypt"))

	if (len < 4 || taglen != POLY1305_TAG_LEN) {
		return CRYPT_ERROR;
	}

	STORE64H((uint64_t)seq, seqbuf);
	pre = (state->pre_seq == seq) ? state->pre_have : 0;
	if (pre & 1) {
		memcpy(key, state->pre_polykey, sizeof(key));
	} else {
		chacha_ivctr64(&state->chacha, seqbuf, sizeof(seqbuf), 0);
		if ((err = chacha_keystream(&state->chacha, key, sizeof(key))) != CRYPT_OK) {
			return err;
		}
	}

	poly1305_init(&poly, key, sizeof(key));
	if (direction == LTC_DECRYPT) {
		poly1305_process(&poly, in, len);
		poly1305_done(&poly, tag, &taglen);
		if (constant_time_memcmp(in + len, tag, taglen) != 0) {
			state->len_valid = 0;
			return CRYPT_ERROR;
		}
	}

	if (direction == LTC_DECRYPT && state->len_valid && state->len_seq == seq) {
		/* already decrypted by dropbear_chachapoly_getlength() */
		memcpy(out, state->len_plain, 4);
	} else if (pre & 2) {
		for (i = 0; i < 4; i++) {
			out[i] = in[i] ^ state->pre_len[i];
		}
	} else {
		chacha_ivctr64(&state->header, seqbuf, sizeof(seqbuf), 0);
		if ((err = chacha_crypt(&state->header, in, 4, out)) != CRYPT_OK) {
			return err;
		}
	}
	state->len_valid = 0;

	if ((pre & 4) && len - 4 <= sizeof(state->pre_payload)) {
		for (i = 0; i < len - 4; i++) {
			out[4 + i] = in[4 + i] ^ state->pre_payload[i];
		}
	} else {
		chacha_ivctr64(&state->chacha, seqbuf, sizeof(seqbuf), 1);
		if ((err = chacha_crypt(&state->chacha, in + 4, len - 4, out + 4)) != CRYPT_OK) {
			return err;
		}
	}
	if (pre) {
		/* used up: this keystream must never be applied twice */
		state->pre_have = 0;
		m_burn(state->pre_polykey, sizeof(state->pre_polykey));
		m_burn(state->pre_len, sizeof(state->pre_len));
		m_burn(state->pre_payload, sizeof(state->pre_payload));
	}

	if (direction == LTC_ENCRYPT) {
		poly1305_process(&poly, out, len);
		poly1305_done(&poly, out + len, &taglen);
	}

	TRACE2(("leave dropbear_chachapoly_crypt"))
	return CRYPT_OK;
}

static int dropbear_chachapoly_getlength(unsigned int seq,
			const unsigned char *in, uint32_t *outlen,
			unsigned long len, dropbear_chachapoly_state *state) {
	unsigned char seqbuf[8], buf[4];
	int i, err;

	TRACE2(("enter dropbear_chachapoly_getlength"))

	if (len < sizeof(buf)) {
		return CRYPT_ERROR;
	}

	if (state->pre_seq == seq && (state->pre_have & 2)) {
		for (i = 0; i < (int)sizeof(buf); i++) {
			buf[i] = in[i] ^ state->pre_len[i];
		}
	} else {
		STORE64H((uint64_t)seq, seqbuf);
		chacha_ivctr64(&state->header, seqbuf, sizeof(seqbuf), 0);
		if ((err = chacha_crypt(&state->header, in, sizeof(buf), buf)) != CRYPT_OK) {
			return err;
		}
	}

	LOAD32H(*outlen, buf);
	memcpy(state->len_plain, buf, sizeof(buf));
	state->len_seq = seq;
	state->len_valid = 1;

	TRACE2(("leave dropbear_chachapoly_getlength"))
	return CRYPT_OK;
}

/* Compute part of the keystream for packet seq ahead of time, one ChaCha20
 * block per call, so the session loop can do it while idle (see
 * packet_idle_work()).  The keystream depends only on the key and the
 * sequence number, never on the data.  Returns 1 if it did a block, 0 if
 * everything for seq is already there.  dropbear_chachapoly_crypt() and
 * _getlength() use it when the sequence number matches and compute it on
 * the spot otherwise. */
int dropbear_chachapoly_precompute(dropbear_chachapoly_state *state, unsigned int seq) {
	unsigned char seqbuf[8];

	if (state->pre_seq != seq) {
		state->pre_seq = seq;
		state->pre_have = 0;
	}
	if (state->pre_have == 7) {
		return 0;
	}
	STORE64H((uint64_t)seq, seqbuf);
	if (!(state->pre_have & 1)) {
		chacha_ivctr64(&state->chacha, seqbuf, sizeof(seqbuf), 0);
		chacha_keystream(&state->chacha, state->pre_polykey, sizeof(state->pre_polykey));
		state->pre_have |= 1;
	} else if (!(state->pre_have & 2)) {
		chacha_ivctr64(&state->header, seqbuf, sizeof(seqbuf), 0);
		chacha_keystream(&state->header, state->pre_len, sizeof(state->pre_len));
		state->pre_have |= 2;
	} else {
		chacha_ivctr64(&state->chacha, seqbuf, sizeof(seqbuf), 1);
		chacha_keystream(&state->chacha, state->pre_payload, sizeof(state->pre_payload));
		state->pre_have |= 4;
	}
	return 1;
}

static int dropbear_chachapoly_mode_start(int cipher, const unsigned char *iv,
		const unsigned char *key, int keylen, int num_rounds, void *cipher_state) {
	return dropbear_chachapoly_start(cipher, iv, key, keylen, num_rounds, cipher_state);
}

static int dropbear_chachapoly_mode_crypt(unsigned int seq,
		const unsigned char *in, unsigned char *out, unsigned long len,
		unsigned long taglen, void *cipher_state, int direction) {
	return dropbear_chachapoly_crypt(seq, in, out, len, taglen, cipher_state, direction);
}

static int dropbear_chachapoly_mode_getlength(unsigned int seq,
		const unsigned char *in, uint32_t *outlen, unsigned long len,
		void *cipher_state) {
	return dropbear_chachapoly_getlength(seq, in, outlen, len, cipher_state);
}

const struct dropbear_cipher_mode dropbear_mode_chachapoly =
	{dropbear_chachapoly_mode_start, NULL, NULL,
	 dropbear_chachapoly_mode_crypt,
	 dropbear_chachapoly_mode_getlength, &dropbear_chachapoly_mac};

#endif /* DROPBEAR_CHACHA20POLY1305 */
