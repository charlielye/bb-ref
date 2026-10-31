#!/usr/bin/env bash
# Pack instance dumps into the committed archives, tests/data/<pin7>/instance/<name>.tar.zst, which
# tests/common/mod.rs unpacks on first use. The regens that write instance/ run it last.
#
#   tools/regen/pack.sh [name ...]   (default: every dump directory)
#
# Deterministic (sorted, no timestamps or owners), so an unchanged dump repacks to the same bytes
# and leaves the archive alone. Test outputs (rust*/) and the UltraInstance dumper's mega_app/,
# which nothing reads, stay out.
set -euo pipefail
F=$(cd "$(dirname "$0")" && pwd)
source "$F/env.sh"
cd "$DATA/instance"
[ $# -gt 0 ] || set -- */
for d in "$@"; do
  d=${d%/}
  tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner \
    --exclude=mega_app --exclude='rust*' --exclude=.unpacked -cf - "$d" | zstd -19 --long=31 -T0 -q -c > ".$d.tar.zst"
  if cmp -s ".$d.tar.zst" "$d.tar.zst"; then
    rm ".$d.tar.zst"
  else
    mv ".$d.tar.zst" "$d.tar.zst"
    echo "packed $d ($(du -h "$d.tar.zst" | cut -f1))"
  fi
  touch "$d/.unpacked"
done
