#!/bin/sh
# elks_place.sh near|far file.o
#
# Choose which 64 KB code segment an object's code goes in, for ELKS
# medium-model programs.
#
# ia16-elf-gcc names each object's code section .fartext.f.<file>.<N>$
# (with matching ...! and ...& segment-marker sections), where N is a
# number derived from the source.  ELKS's stock elks-medium.ld sends
# sections whose N ends in 0, 2, 4 or 6 to the near segment (0x10000)
# and everything else to the far segment (0x20000) -- an arbitrary
# half/half split that can overfill one segment.  This rewrites the last
# digit of N in all three sections so the stock script places the object
# where we want: 0 for near, 1 for far.  Symbols and relocations refer to
# sections by index, so renaming them is safe.

set -e
case "$1" in
	near) digit=0 ;;
	far) digit=1 ;;
	*) echo "usage: $0 near|far file.o" >&2; exit 2 ;;
esac
obj="$2"
args=""
for sec in $(ia16-elf-objdump -h "$obj" | awk '$2 ~ /^\.fartext\./ { print $2 }'); do
	suffix=${sec#"${sec%?}"}          # trailing $, ! or &
	stem=${sec%??}                    # name without last digit and suffix
	args="$args --rename-section $sec=$stem$digit$suffix"
done
if [ -n "$args" ]; then
	ia16-elf-objcopy $args "$obj"
fi
