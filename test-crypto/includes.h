/* Shadow of src/includes.h for the desktop test harness.
 * Provides just enough stdlib for src/curve25519.c to compile on a host.
 * With DROPBEAR_ED25519=1, libtomcrypt's SHA-512 is stood in for by
 * OpenSSL's (link with -lcrypto). */
#ifndef DROPBEAR_TEST_INCLUDES_H
#define DROPBEAR_TEST_INCLUDES_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#if DROPBEAR_ED25519
#include <openssl/sha.h>
typedef SHA512_CTX hash_state;
static inline int sha512_init(hash_state *hs) { SHA512_Init(hs); return 0; }
static inline int sha512_process(hash_state *hs, const unsigned char *in,
                                 unsigned long len) { SHA512_Update(hs, in, len); return 0; }
static inline int sha512_done(hash_state *hs, unsigned char *out) { SHA512_Final(out, hs); return 0; }
#endif

#endif
