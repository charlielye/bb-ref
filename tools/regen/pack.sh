#!/usr/bin/env bash
# Pack fixture directories into their committed archives, tests/data/<pin7>/<dir>/<name>.tar.zst for
# the instance dumps (instance/) and the vendored pin build outputs (inputs/), which
# tests/common/mod.rs unpacks on first use. The regens that write them run it last.
#
#   tools/regen/pack.sh [<dir>/<name> ...]   (default: every instance/ and inputs/ directory)
#
# Deterministic (sorted, no timestamps or owners), so an unchanged directory repacks to the same
# bytes and leaves the archive alone. Test outputs (rust*/) and the UltraInstance dumper's
# mega_app/, which nothing reads, stay out.
set -euo pipefail
F=$(cd "$(dirname "$0")" && pwd)
source "$F/env.sh"
cd "$DATA"
[ $# -gt 0 ] || set -- instance/*/ inputs/*/
for p in "$@"; do
  p=${p%/}
  dir=$(dirname "$p") d=$(basename "$p")
  tar -C "$dir" --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner \
    --exclude=mega_app --exclude='rust*' --exclude=.unpacked -cf - "$d" | zstd -19 --long=31 -T0 -q -c > "$dir/.$d.tar.zst"
  if cmp -s "$dir/.$d.tar.zst" "$dir/$d.tar.zst"; then
    rm "$dir/.$d.tar.zst"
  else
    mv "$dir/.$d.tar.zst" "$dir/$d.tar.zst"
    echo "packed $p ($(du -h "$dir/$d.tar.zst" | cut -f1))"
  fi
  touch "$p/.unpacked"
done
