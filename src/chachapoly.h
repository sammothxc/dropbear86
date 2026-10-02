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

#ifndef DROPBEAR_DROPBEAR_CHACHAPOLY_H_
#define DROPBEAR_DROPBEAR_CHACHAPOLY_H_

#include "includes.h"
#include "algo.h"

#if DROPBEAR_CHACHA20POLY1305

typedef struct {
	chacha_state chacha;
	chacha_state header;
	/* Length field decrypted by getlength, reused once by the following
	 * decrypt of the same packet (saves a ChaCha20 block per received
	 * packet; ~26 ms on an 8088). */
	unsigned int len_seq;
	int len_valid;
	unsigned char len_plain[4];
	/* Keystream for packet pre_seq computed ahead of time while idle,
	 * see dropbear_chachapoly_precompute().  pre_have bits: 1 = Poly1305
	 * key, 2 = length field, 4 = first 64 bytes of payload keystream. */
	unsigned int pre_seq;
	unsigned char pre_have;
	unsigned char pre_polykey[32];
	unsigned char pre_len[4];
	unsigned char pre_payload[64];
} dropbear_chachapoly_state;

int dropbear_chachapoly_precompute(dropbear_chachapoly_state *state, unsigned int seq);

extern const struct dropbear_cipher dropbear_chachapoly;
extern const struct dropbear_cipher_mode dropbear_mode_chachapoly;

#endif /* DROPBEAR_CHACHA20POLY1305 */

#endif /* DROPBEAR_DROPBEAR_CHACHAPOLY_H_ */
