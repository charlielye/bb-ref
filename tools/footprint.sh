#!/usr/bin/env bash
# A command's memory footprint as a phone counts it, natively on Linux.
#
#   tools/footprint.sh <label> -- <command ...>
#
# Runs the command uncapped, polling /proc/<pid>/status every 10 ms, and prints the wall, the peak
# RssAnon (private memory: what iOS's footprint and its per-process limits count; file-backed pages,
# such as low memory mode's polynomial files and the mapped CRS, are not in it) and the peak VmRSS
# (everything resident, file pages included). A 10 ms poll can miss a shorter spike.
label=$1; shift 2
s=$(date +%s%N)
"$@" > /dev/null 2>&1 & pid=$!
pa=0; pr=0
while [ -r /proc/$pid/status ]; do
  read -r a r < <(awk '/^RssAnon:/{a=$2}/^VmRSS:/{r=$2}END{print a+0, r+0}' /proc/$pid/status 2>/dev/null)
  [ "${a:-0}" -gt $pa ] && pa=$a; [ "${r:-0}" -gt $pr ] && pr=$r
  sleep 0.01
done
wait $pid; rc=$?
printf '%-22s exit %d  wall %6.2f s  peak anon %6.1f MiB  peak rss %6.1f MiB\n' "$label" $rc "$(awk -v n=$(( $(date +%s%N) - s )) 'BEGIN{print n/1e9}')" "$(awk -v k=$pa 'BEGIN{print k/1024}')" "$(awk -v k=$pr 'BEGIN{print k/1024}')"
