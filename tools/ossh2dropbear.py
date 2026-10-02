#!/usr/bin/env python3
"""
Convert an OpenSSH Ed25519 private key into Dropbear's key format, for
use as an ELKS sshd host key.

ELKS has no good entropy source, so generate the key on a modern machine:

    ssh-keygen -t ed25519 -N "" -C elks-host -f elks_host_key
    python3 tools/ossh2dropbear.py elks_host_key dropbear_ed25519_host_key

then copy dropbear_ed25519_host_key to /etc/dropbear/ on the ELKS system
(FTP in binary mode).  elks_host_key.pub is the matching public key for
clients' known_hosts.  The private key must be unencrypted (-N "").

Dropbear's format: string "ssh-ed25519", then a 64-byte string holding the
32-byte private seed followed by the 32-byte public key.  OpenSSH stores
the same 64 bytes, so this is a repackaging, not a key derivation.
"""

import base64
import struct
import sys


def read_string(data, pos):
    (n,) = struct.unpack_from(">I", data, pos)
    pos += 4
    return data[pos:pos + n], pos + n


def ssh_string(b):
    return struct.pack(">I", len(b)) + b


def main():
    if len(sys.argv) != 3:
        sys.exit("usage: ossh2dropbear.py <openssh_private_key> <dropbear_output>")
    text = open(sys.argv[1]).read()
    begin = "-----BEGIN OPENSSH PRIVATE KEY-----"
    end = "-----END OPENSSH PRIVATE KEY-----"
    if begin not in text:
        sys.exit("not an OpenSSH private key")
    body = text.split(begin)[1].split(end)[0]
    data = base64.b64decode("".join(body.split()))

    magic = b"openssh-key-v1\0"
    if not data.startswith(magic):
        sys.exit("bad key magic")
    pos = len(magic)
    cipher, pos = read_string(data, pos)
    kdf, pos = read_string(data, pos)
    _kdfopts, pos = read_string(data, pos)
    if cipher != b"none" or kdf != b"none":
        sys.exit("key is encrypted; regenerate with ssh-keygen -N \"\"")
    (nkeys,) = struct.unpack_from(">I", data, pos)
    pos += 4
    if nkeys != 1:
        sys.exit("expected exactly one key")
    _pubblob, pos = read_string(data, pos)
    priv, pos = read_string(data, pos)

    p = 0
    check1, check2 = struct.unpack_from(">II", priv, p)
    p += 8
    if check1 != check2:
        sys.exit("corrupt private key (check bytes differ)")
    keytype, p = read_string(priv, p)
    if keytype != b"ssh-ed25519":
        sys.exit("not an Ed25519 key: %r" % keytype)
    pub, p = read_string(priv, p)
    seed_and_pub, p = read_string(priv, p)
    if len(pub) != 32 or len(seed_and_pub) != 64 or seed_and_pub[32:] != pub:
        sys.exit("unexpected Ed25519 key layout")

    out = ssh_string(b"ssh-ed25519") + ssh_string(seed_and_pub)
    with open(sys.argv[2], "wb") as f:
        f.write(out)
    print("wrote %s (%d bytes)" % (sys.argv[2], len(out)))


if __name__ == "__main__":
    main()
