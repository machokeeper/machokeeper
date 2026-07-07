#!/usr/bin/env bash
# Darwin functional test: repair a real broken signed Mach-O and let
# Apple's own codesign be the oracle. Runs only on macOS (needs
# codesign) and needs nix on PATH.
#
# Fetches the smallest broken ad-hoc-signed path named by
# ak2k/nix-507531-scope, extracts the binary, confirms codesign rejects
# it, repairs it with the shipped machokeeper, and confirms codesign
# then accepts it — an independent validation the engine's own check
# cannot give.
set -euo pipefail

MK="${1:?usage: darwin-functional.sh <path-to-machokeeper>}"
MK="$(cd "$(dirname "$MK")" && pwd)/$(basename "$MK")"

command -v codesign >/dev/null || {
  echo "no codesign; not macOS"
  exit 0
}
command -v nix >/dev/null || {
  echo "nix not on PATH"
  exit 1
}

# Ask the harness's own picker for the smallest repairable path+file.
read -r STORE_PATH REL < <(
  python3 - <<'PY'
import csv, io, urllib.request
CACHE="https://cache.nixos.org"
rows=list(csv.DictReader(io.StringIO(urllib.request.urlopen(
  "https://raw.githubusercontent.com/ak2k/nix-507531-scope/main/darwin/direct-failing.csv",timeout=60).read().decode())))
def size(sp):
    h=sp.split("/")[-1].split("-")[0]
    try:
        for l in urllib.request.urlopen(f"{CACHE}/{h}.narinfo",timeout=20).read().decode().splitlines():
            if l.startswith("FileSize:"): return int(l.split()[1])
    except Exception: return 1<<62
    return 1<<62
cand=[r for r in rows if r["signature_class"] in ("L","C2","B7-empty")]
cand.sort(key=lambda r: size(r["store_path"]))
print(cand[0]["store_path"], cand[0]["path"])
PY
)

WD="$(mktemp -d)"
trap 'rm -rf "$WD"' EXIT
FILE="$WD/binary"
echo "fetching $STORE_PATH/$REL"
nix store cat --store https://cache.nixos.org "$STORE_PATH/$REL" >"$FILE"

echo "== codesign before (must reject):"
if codesign --verify "$FILE" 2>/dev/null; then
  echo "FAIL: codesign accepted a supposedly-broken binary"
  exit 1
fi
echo "  rejected, as expected"

cd "$WD"
"$MK" doctor --fix "$FILE"

echo "== codesign after repair (must accept):"
codesign --verify "$FILE"
echo "PASS: repaired binary passes Apple's codesign --verify"
