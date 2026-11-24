#!/usr/bin/env python3
"""Quick DNS smoke test against a running ad-blocker.

  python tools/test_dns.py 192.168.1.50
  python tools/test_dns.py s3adblock.local --blocked doubleclick.net --allowed github.com

Sends raw UDP DNS queries (no dnspython needed) and prints the A record answer.
A blocked domain must come back as 0.0.0.0.
"""
import argparse
import random
import socket
import struct
import sys


def build_query(domain, txid):
    q = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    for label in domain.strip(".").split("."):
        q += bytes([len(label)]) + label.encode()
    return q + b"\x00" + struct.pack(">HH", 1, 1)


def parse_a(resp):
    txid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", resp[:12])
    if an == 0:
        return None
    i = 12
    while resp[i] != 0:            # skip question name
        i += resp[i] + 1
    i += 5                          # null + qtype + qclass
    for _ in range(an):
        if resp[i] & 0xC0 == 0xC0:
            i += 2
        else:
            while resp[i] != 0:
                i += resp[i] + 1
            i += 1
        rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", resp[i:i + 10])
        i += 10
        if rtype == 1 and rdlen == 4:
            return ".".join(str(b) for b in resp[i:i + 4])
        i += rdlen
    return None


def ask(server, domain, timeout=3.0):
    txid = random.getrandbits(16)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(build_query(domain, txid), (server, 53))
        data, _ = s.recvfrom(2048)
        return parse_a(data)
    except socket.timeout:
        return "TIMEOUT"
    finally:
        s.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("server")
    ap.add_argument("--blocked", action="append", default=["doubleclick.net"])
    ap.add_argument("--allowed", action="append", default=["github.com"])
    a = ap.parse_args()
    try:
        server = socket.gethostbyname(a.server)
    except OSError as e:
        print(f"[!] cannot resolve {a.server}: {e}")
        return 2
    print(f"server: {a.server} ({server})")
    ok = True
    for d in a.blocked:
        r = ask(server, d)
        good = r == "0.0.0.0"
        ok &= good
        print(f"  {'PASS' if good else 'FAIL'}  blocked  {d:32s} -> {r}")
    for d in a.allowed:
        r = ask(server, d)
        good = r not in (None, "0.0.0.0", "TIMEOUT")
        ok &= good
        print(f"  {'PASS' if good else 'FAIL'}  allowed  {d:32s} -> {r}")
    print("\nRESULT:", "all good" if ok else "see FAILs above")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
