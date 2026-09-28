# dropbear86

An SSH-2 client for **8086** and other 16-bit x86 CPUs running
[ELKS](https://github.com/ghaerr/elks). It is a fork of
[Dropbear](https://github.com/mkj/dropbear), retargeted for `ia16-elf-gcc`,
built with the ELKS libc, and audited for the 16-bit integer widths the SSH
protocol demands.

To the extent anyone has been able to check, this is the first SSH client
for ELKS on 8086.

The main deliverable is one binary: `ssh` (previously `dbclient` upstream).

## Status

- Builds cleanly against `ia16-elf-gcc` 6.3.0 with the `elks-libc` runtime.
- KEX (Curve25519), host-key verify (Ed25519), and cipher (ChaCha20-Poly1305)
  all work.
- Verified end-to-end in QEMU (`hd32-fat.img` from ELKS 0.9.2, `ne2k_isa`).
- Verified end-to-end on real hardware: **Compaq Portable Plus + 3Com 3C509
  ISA NIC**. Reaches password prompt, authenticates, opens an interactive
  session.
- KEX takes several minutes on a 4.77 MHz 8086. See "Performance" below.

## Building

Prerequisites: `ia16-elf-gcc` (from
[tkchia's PPA](https://launchpad.net/~tkchia/+archive/ubuntu/build-ia16/) or
built from source with
[`tkchia/build-ia16`](https://github.com/tkchia/build-ia16)) plus `elks-libc`.

```
make -f Makefile.elks
```

Produces `./ssh` — a Linux-8086 a.out executable, ~117 KB.
Heap is provisioned at 40 KB and stack at 4 KB (see the linker line in
`Makefile.elks`); both fit comfortably in ELKS's 64 KB per-process data
segment.

Local build knobs (algorithms enabled, feature toggles, buffer sizes) live in
`localoptions.h` at the tree root. The default set is tuned for 8086: only
Curve25519 / Ed25519 / ChaCha20-Poly1305 are enabled, RSA / DSS / ECDSA and
all forwarding features are compiled out.

## Deploying to ELKS

Copy `ssh` into `/bin/` on an ELKS filesystem (loop-mount the disk image,
`cp`, `chmod 755`) or transfer it over FTP from a running system:

```
# on the ELKS host, after net start:
ftp <your dev machine>
> binary
> get ssh /bin/ssh
> quit
chmod 755 /bin/ssh
```

Then:

```
ssh -y user@host
```

`-y` skips known-hosts prompting, which is what you want on ELKS —
persistent known-hosts is more filesystem trouble than it's worth for a
device with no meaningful trust anchor.

## Performance

Very slow on real 8086 hardware. Curve25519 scalar multiplication in
portable C on a 4.77 MHz CPU is roughly 3–8 minutes; a full KEX plus host-key
verify is 15–40 minutes for the first connection. Interactive traffic after
KEX is symmetric-only (ChaCha20-Poly1305) and much faster — usable at
keystroke latency.

Speeding this up is on the roadmap. In rough order of increasing effort:

1. Compiler flags — already at `-O2`. Bigger binary, faster arithmetic.
2. Replace the reference `curve25519.c` (10 limbs × 25.5-bit packed in
   `long`) with a 16-bit-limb variant native to the 8086 register file.
   Expected: 3–5× speedup, portable C.
3. Hand-write `fe_mul` / `fe_sq` / `fe_reduce` in `ia16-elf-as`. Expected:
   another 3–5× on top of (2).
4. Precomputed base-point tables for the initial `secret × G` step of KEX
   and for Ed25519 verify. Expected: another ~2×.

Also worth noting: `ia16-elf-gcc` is a GCC 6.3 fork, which precedes several
optimization passes present in modern GCC. Some of the "portable" speedup
above may come from just tracking upstream when tkchia's fork does.

## Known limitations

- **Entropy is weak.** ELKS has no `/dev/urandom`; `dbrandom.c` falls back
  to hashing `getpid() + gettimeofday() + clock() + /bootopts` and a couple
  of similar sources. Total effective entropy is probably 30–40 bits, which
  is not cryptographically sufficient. Do not use this to reach anything
  that actually matters. A persistent-seed patch and/or an ELKS-side
  `/dev/urandom` are follow-ups.
- **8-bit ISA constraints.** The Compaq Portable Plus (and other XT-class
  machines) only wires IRQ 0–7 to its slots. Real NICs must be jumperless-
  configurable to those IRQs — the 3C509 is with `3C5X9CFG.EXE`. The
  picoMEM's NE2000 emulation was found to have an ELKS-specific
  interrupt-delivery incompatibility (same hardware works fine under a DOS
  packet driver); if you're using picoMEM for storage but need networking,
  a real ISA NIC is the reliable path.
- **Password auth only in practice.** Public-key auth is compiled in and
  should work, but no one has tested storing a private key on an ELKS
  filesystem yet.

## Provenance

Forked from a fork of [`mkj/dropbear`](https://github.com/mkj/dropbear) —
the ELKS retargeting work was started by the previous maintainer, who is
looking to hand it off. The full upstream Dropbear source tree is retained
in this repo because the QEMU test harness also builds a host-side Dropbear
server fixture from the same base.

Files not in the ELKS build path (server-side code, agent forwarding, TCP
forwarding, keyimport, RSA/DSS/ECDSA implementations, libtommath) are still
present but unbuilt; the ia16 type audit only touched the client-side files
actually compiled into `ssh`. If you want to build the host-side tools too,
see `INSTALL.md` and `DEVELOPING.md` inherited from upstream.

## License

MIT-style, matching upstream Dropbear. See `LICENSE`.
