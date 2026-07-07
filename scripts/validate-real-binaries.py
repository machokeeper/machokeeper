#!/usr/bin/env python3
"""Validate the machokeeper binary against real broken Mach-O files from
cache.nixos.org.

The `ak2k/nix-507531-scope` scanner publishes, per darwin channel, a
direct-failing.csv naming every store file whose page hashes are stale,
with a signature_class:

  L, C2, B7-empty   -> ad-hoc, repairable
  B7-real           -> Developer-ID (CMS), must be refused

For a sample of each class this harness fetches the file's store path
from cache.nixos.org, extracts the one file, and drives the *shipped*
machokeeper binary end to end:

  - `machokeeper check <file>`      must exit 2 (stale) before repair
  - `machokeeper doctor --fix`      repairs a repairable file
  - `machokeeper check <file>`      must exit 0 after repair
  - a Developer-ID file is left byte-for-byte unchanged (still exit 2)

It never executes the binaries, so it runs on Linux too — the same
independent, real-world check the engine's C++ ancestor passed 10/10.

Individually evicted cache paths are skipped (not failed); the run fails
only when a file that *was* fetched does not behave as its class says.

Usage: validate-real-binaries.py <path-to-machokeeper> [--channel darwin] [--n 4]
"""

import csv
import io
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request

SCOPE = "https://raw.githubusercontent.com/ak2k/nix-507531-scope/main"
CACHE = "https://cache.nixos.org"


def fetch_csv(channel):
    url = f"{SCOPE}/{channel}/direct-failing.csv"
    with urllib.request.urlopen(url, timeout=60) as r:
        return list(csv.DictReader(io.StringIO(r.read().decode())))


# Only fetch store paths whose compressed download is under this many
# bytes, so a giant closure (swift, libtorch) never stalls the run. The
# smallest broken paths are a few MB.
MAX_DOWNLOAD = 60 * 1024 * 1024


def download_size(store_path):
    """Compressed NAR size of `store_path` from its narinfo, or None."""
    h = store_path.split("/")[-1].split("-")[0]
    try:
        with urllib.request.urlopen(f"{CACHE}/{h}.narinfo", timeout=20) as r:
            for line in r.read().decode().splitlines():
                if line.startswith("FileSize:"):
                    return int(line.split()[1])
    except Exception:
        return None
    return None


def pick(rows, n):
    # One row per store path (smallest download first), so we test
    # distinct real binaries without refetching the same closure.
    seen = set()
    repairable, devid = [], []
    for r in rows:
        if r["store_path"] in seen:
            continue
        seen.add(r["store_path"])
        if r["signature_class"] in ("L", "C2", "B7-empty"):
            repairable.append(r)
        elif r["signature_class"] == "B7-real":
            devid.append(r)
    repairable.sort(key=lambda r: download_size(r["store_path"]) or 1 << 62)
    devid.sort(key=lambda r: download_size(r["store_path"]) or 1 << 62)
    return repairable[:n], devid[:2]


def extract(store_path, rel, workdir):
    """Fetch just this path's NAR from the cache (not its closure) and
    read out the one file. Returns its local path, or None if the path
    is too big, evicted, or unavailable."""
    sz = download_size(store_path)
    if sz is None or sz > MAX_DOWNLOAD:
        return None
    out = os.path.join(workdir, "file.bin")
    try:
        with open(out, "wb") as f:
            # `nix store cat` against the remote cache fetches only this
            # path's NAR, not the closure.
            subprocess.run(
                ["nix", "store", "cat", "--store", CACHE, f"{store_path}/{rel}"],
                check=True,
                stdout=f,
                timeout=300,
            )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return None
    return out if os.path.getsize(out) > 0 else None


def check(mk, path):
    return subprocess.run([mk, "check", path], capture_output=True).returncode


def main():
    mk = os.path.abspath(sys.argv[1])
    channel = "darwin"
    n = 4
    args = sys.argv[2:]
    for i, a in enumerate(args):
        if a == "--channel":
            channel = args[i + 1]
        if a == "--n":
            n = int(args[i + 1])

    rows = fetch_csv(channel)
    repairable, devid = pick(rows, n)
    print(
        f"{channel}: {len(rows)} broken slices; testing {len(repairable)} repairable + {len(devid)} Developer-ID"
    )

    checked = 0
    for r in repairable:
        with tempfile.TemporaryDirectory() as wd:
            f = extract(r["store_path"], r["path"], wd)
            if not f:
                print(f"SKIP (unavailable)  {r['store_path']}/{r['path']}")
                continue
            name = os.path.basename(r["path"])
            if check(mk, f) != 2:
                sys.exit(f"FAIL {name}: check did not report stale (expected exit 2)")
            os.chdir(wd)
            subprocess.run([mk, "doctor", "--fix", f], check=True, capture_output=True)
            if check(mk, f) != 0:
                sys.exit(f"FAIL {name}: still stale after repair")
            print(f"PASS repair  {r['signature_class']:8} {name}")
            checked += 1

    for r in devid:
        with tempfile.TemporaryDirectory() as wd:
            f = extract(r["store_path"], r["path"], wd)
            if not f:
                print(f"SKIP (unavailable)  {r['store_path']}/{r['path']}")
                continue
            before = open(f, "rb").read()
            os.chdir(wd)
            subprocess.run([mk, "doctor", "--fix", f], capture_output=True)
            if open(f, "rb").read() != before:
                sys.exit(
                    f"FAIL {os.path.basename(r['path'])}: Developer-ID file was modified"
                )
            print(f"PASS refuse  B7-real  {os.path.basename(r['path'])}")
            checked += 1

    if checked == 0:
        print("no cache files were available to test (all evicted); nothing validated")
        # Not a failure: the cache moved on. CI treats this as a soft pass.
    else:
        print(f"validated {checked} real broken binaries")


if __name__ == "__main__":
    if shutil.which("nix") is None:
        sys.exit("nix not on PATH")
    main()
