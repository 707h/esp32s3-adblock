#!/usr/bin/env python3
"""Host-side verification that the firmware's two-level flash index can find
every hash in a blocklist.bin, for a given INDEX_ENTRIES / MAX_RANGE pair.

This mirrors inFlash() in src/main.cpp exactly:
  * build the sample index the same way buildFlashIndex() does
  * for each hash, binary-search the index, take the segment, clamp the scan
    window to MAX_RANGE, and confirm the hash is inside that window

A "miss" means the device would silently fail to block that domain.
"""
import sys

HASH_BYTES = 5

def unpack(b, i):
    v = 0
    for k in range(HASH_BYTES):
        v |= b[i + k] << (8 * k)
    return v

def in_flash(index, hashes, h, max_range):
    n = len(hashes)
    if n == 0:
        return False
    if h < index[0] or h > index[-1]:
        return False
    lo, hi, seg = 0, len(index) - 2, 0
    while lo <= hi:
        mid = (lo + hi) >> 1
        if index[mid] < h:
            seg = mid
            lo = mid + 1
        elif index[mid] > h:
            hi = mid - 1
        else:
            return True
    last = len(index) - 1
    start = seg * (n - 1) // (last)
    end = (seg + 1) * (n - 1) // (last)
    if end >= n:
        end = n - 1
    count = min(end - start + 1, max_range)
    for i in range(start, start + count):
        if hashes[i] == h:
            return True
        if hashes[i] > h:
            break
    return False

def main():
    path = sys.argv[1]
    entries = int(sys.argv[2]) if len(sys.argv) > 2 else 8192
    max_range = int(sys.argv[3]) if len(sys.argv) > 3 else 256
    data = open(path, 'rb').read()
    n = len(data) // HASH_BYTES
    hashes = [unpack(data, i * HASH_BYTES) for i in range(n)]
    assert hashes == sorted(hashes), "blocklist.bin is not sorted"
    index = [hashes[i * (n - 1) // (entries - 1)] for i in range(entries)]

    misses = sum(0 if in_flash(index, hashes, h, max_range) else 1 for h in hashes)
    # widest bucket actually needed
    widths = []
    for i in range(entries - 1):
        s = i * (n - 1) // (entries - 1)
        e = (i + 1) * (n - 1) // (entries - 1)
        widths.append(e - s + 1)
    print(f"entries={n:,} index={entries} max_range={max_range}")
    print(f"widest bucket    : {max(widths)} hashes (MAX_RANGE must be >= this)")
    print(f"misses           : {misses}")
    print(f"index RAM        : {entries * HASH_BYTES / 1024:.0f} KB")
    sys.exit(0 if misses == 0 else 1)

if __name__ == '__main__':
    main()
