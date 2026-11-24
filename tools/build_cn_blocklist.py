#!/usr/bin/env python3
"""Build blocklist.bin for esp32s3-adblock, using China-reachable sources.

Wraps the upstream build_blocklist.py (same 40-bit FNV-1a format, unchanged) and
selects sources that actually download from a mainland-China network:

  anti-ad.net        - Chinese ad/tracker list, reachable directly
  ghproxy.net/...    - mirror prefix for raw.githubusercontent.com
  raw.githubusercontent.com - direct (unreachable in CN; kept for other regions)

Usage:
  python tools/build_cn_blocklist.py                     # CN daily driver
  python tools/build_cn_blocklist.py --aggressive        # + big Hagezi list
  python tools/build_cn_blocklist.py --out data/x.bin https://host/list.txt

Then flash it with `pio run -e s3_16mb -t uploadfs`, or upload it from the
dashboard (Blocklist -> Upload) with no USB cable.
"""
import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

RAW = "https://raw.githubusercontent.com"
PROXY = "https://ghproxy.net/" + RAW

BASE = [
    "https://anti-ad.net/adguard.txt",
    "https://anti-ad.net/easylist.txt",
]
CN_EXTRA = [
    PROXY + "/hagezi/dns-blocklists/main/wildcard/pro-onlydomains.txt",
]
GLOBAL_EXTRA = [
    PROXY + "/StevenBlack/hosts/master/hosts",
    PROXY + "/hagezi/dns-blocklists/main/wildcard/light-onlydomains.txt",
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join("data", "blocklist.bin"))
    ap.add_argument("--aggressive", action="store_true",
                    help="add the large Hagezi Pro list (also blocks some social/messaging)")
    ap.add_argument("--global", dest="glob", action="store_true",
                    help="use international lists (StevenBlack + Hagezi Light) instead of CN lists")
    ap.add_argument("--allow-missing", action="store_true", default=True)
    ap.add_argument("sources", nargs="*", help="extra URLs / local files")
    a = ap.parse_args()

    # Explicit sources replace the defaults entirely, so `--out x.bin file.txt`
    # builds from just that file (handy for offline / testing runs).
    if a.sources:
        sources = list(a.sources)
    else:
        sources = (GLOBAL_EXTRA if a.glob else BASE)
        if a.aggressive:
            sources += CN_EXTRA

    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    from build_blocklist import main as build  # upstream logic, unchanged
    argv = ["build_blocklist.py", a.out, "--allow-missing"] + sources
    old = sys.argv
    sys.argv = argv
    try:
        build()
    finally:
        sys.argv = old

    # Sanity-check the index against the firmware's ceiling for this env.
    verify = os.path.join(HERE, "verify_index.py")
    if os.path.exists(verify) and os.path.exists(a.out):
        import subprocess
        print("\n[verify] checking INDEX_ENTRIES=8192 / MAX_RANGE=256 ...")
        subprocess.run([sys.executable, verify, a.out, "8192", "256"], check=False)


if __name__ == "__main__":
    main()
