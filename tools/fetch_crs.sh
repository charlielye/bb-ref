#!/usr/bin/env bash
# Fetch Aztec's BN254 SRS (its first 2^k points) and the Grumpkin SRS into $CRS_PATH (default
# ~/.bb-crs), in the layout bb and bb-ref read: what a machine without bb (CI) needs.
#
#   tools/fetch_crs.sh [k]   (default 20; the default suite's largest circuit)
set -euo pipefail
dir=${CRS_PATH:-$HOME/.bb-crs}
n=$((1 << ${1:-20}))
mkdir -p "$dir"
curl -fsSL -r 0-$((n * 64 - 1)) -o "$dir/bn254_g1.dat" https://crs.aztec-cdn.foundation/g1.dat
curl -fsSL -o "$dir/grumpkin_g1_v2.flat.dat" https://crs.aztec-cdn.foundation/grumpkin_g1_v2.dat
echo "fetch_crs: $n BN254 points and the Grumpkin SRS in $dir"
