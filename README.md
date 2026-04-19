I do not wish to maintain this for regular stock elks if one of the elks maintainers could fork this that be really fantastic


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
