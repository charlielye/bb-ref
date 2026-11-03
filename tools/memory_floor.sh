#!/usr/bin/env bash
# The memory floor of a command: the smallest cgroup memory cap (swap off) it completes under within
# 4x its uncapped wall (bb's definition, aztec-packages#25732), by binary search to 8 MiB. It is the
# number that matters for a prover on a memory-limited device; peak RSS is not, in a file-backed low
# memory mode, since it counts file pages the kernel could drop but has no reason to while memory is
# free.
#
#   tools/memory_floor.sh [--hi <MiB>] [--lo <MiB>] [--step <MiB>] [--factor <n>] -- <command ...>
#
# --factor 4 is the default; a large one (say 1000) finds the absolute floor, where the command
# still completes at all.
#
# Near the floor a capped run can pass once and fail the next time (the kernel's reclaim races the
# writeback of dirty file pages), so the floor found is confirmed by a second run, stepping up until
# one passes. Prints the uncapped wall, then each probe, then `floor <MiB> MiB, <s> s at the floor`
# (the confirming run's wall).
#
# The cap is a systemd scope (cgroup v2). It must have the io controller as well as the memory one:
# the kernel bounds a cgroup's dirty pages only when it has both, and without that a file-backed
# prover fills its cap with dirty pages the flusher has no reason to write yet, and is killed
# (systemd delegates only cpu, memory and pids to user scopes). So the scope is a system one, made
# with passwordless sudo and run as the caller. The command's TMPDIR should be a real disk, not
# tmpfs: tmpfs pages are memory. Run on a bench box, not a workstation.
set -euo pipefail
HI=4096
LO=0
STEP=8
FACTOR=4
while [ $# -gt 0 ]; do
  case $1 in
    --hi) HI=$2; shift 2 ;;
    --lo) LO=$2; shift 2 ;;
    --step) STEP=$2; shift 2 ;;
    --factor) FACTOR=$2; shift 2 ;;
    --) shift; break ;;
    *) break ;;
  esac
done
[ $# -gt 0 ] || { echo "usage: memory_floor.sh [--hi MiB] [--step MiB] -- <command ...>" >&2; exit 2; }
sudo -n true 2> /dev/null || { echo "memory_floor: needs passwordless sudo (a system scope; see above)" >&2; exit 1; }

# run <cap MiB or 0> <timeout s>: prints the wall in ms; fails if the command failed or timed out.
run() {
  local cap=$1 limit=$2 s e
  shift 2
  s=$(date +%s%N)
  if [ "$cap" = 0 ]; then
    "$@" > /dev/null 2>&1 || return 1
  else
    timeout "$limit" sudo -n systemd-run --scope -q -p MemoryMax="${cap}M" -p MemorySwapMax=0 -p IOAccounting=yes \
      --uid="$(id -u)" --gid="$(id -g)" --same-dir -E HOME="$HOME" "$@" > /dev/null 2>&1 || return 1
  fi
  e=$(date +%s%N)
  echo $(( (e - s) / 1000000 ))
}

base=$(run 0 0 "$@") || { echo "the command fails uncapped" >&2; exit 1; }
limit=$(( base * FACTOR / 1000 + 1 ))
echo "uncapped $(awk -v m="$base" 'BEGIN { printf "%.2f", m / 1000 }') s; a capped run passes within ${limit} s"
lo=$LO hi=$HI
run "$hi" "$limit" "$@" > /dev/null || { echo "fails at ${hi} MiB: raise --hi" >&2; exit 1; }
while [ $(( hi - lo )) -gt "$STEP" ]; do
  mid=$(( (lo + hi) / 2 / STEP * STEP ))
  [ "$mid" -gt "$lo" ] || mid=$(( lo + STEP ))
  if ms=$(run "$mid" "$limit" "$@"); then
    echo "  ${mid} MiB: $(awk -v m="$ms" 'BEGIN { printf "%.2f", m / 1000 }') s"
    hi=$mid
  else
    echo "  ${mid} MiB: fails"
    lo=$mid
  fi
done
until ms=$(run "$hi" "$limit" "$@"); do
  echo "  ${hi} MiB: fails on a second run"
  hi=$(( hi + STEP ))
done
echo "floor ${hi} MiB, $(awk -v m="$ms" 'BEGIN { printf "%.2f", m / 1000 }') s at the floor"
