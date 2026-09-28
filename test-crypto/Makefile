# Desktop test harness for src/curve25519.c
#
# Builds and runs against the exact file that ships in the ELKS binary,
# with just enough stubbed headers to compile on a modern host.
#
# curve25519.c and curve25519.h are symlinks to ../src/*, so compilation
# resolves #include "includes.h" against the shadow in THIS directory
# (not the Dropbear one in src/).

CC = gcc
CFLAGS = -O2 -Wall -Wextra -std=c99 \
	 -DDROPBEAR_CURVE25519_DEP=1 -DDROPBEAR_ED25519=0

.PHONY: all test clean

all: test_x25519

test_x25519: test_x25519.c curve25519.c curve25519.h includes.h dbrandom.h
	$(CC) $(CFLAGS) -o $@ test_x25519.c curve25519.c

test: test_x25519
	./test_x25519

clean:
	rm -f test_x25519
