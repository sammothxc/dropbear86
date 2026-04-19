# ssh-daemon-project

`ssh-daemon-project` is the standalone Dropbear source tree adapted for ELKS on
16-bit IA16 systems.

## Platform

- ELKS on 8086, 8088, 80186, 80188, 80286 and compatible CPUs
- QEMU ELKS images and real XT/AT class hardware
- `ia16-elf-gcc` extapp builds

## What This Repository Contains

- the Dropbear source tree
- `Makefile.elks` and ELKS-specific configuration
- ELKS networking compatibility fixes for the client path
- the `dbclient` SSH client build used by ELKS images and smoke tests

The main ELKS deliverable from this repository is `dbclient`.
The full source tree is kept because the QEMU test harness also builds a host
Dropbear server fixture from the same source base.

## Relationship To ELKS Enhanced

This repository is separate from `elks-enhanced`.
The main ELKS tree keeps the menuconfig and install hooks for the Dropbear
extapp, but the source is fetched into `extapps%