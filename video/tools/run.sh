#!/bin/bash
# usage: run.sh <out_dir> [durations.json]
set -e
OUT=$1; DUR=$2
pkill -f "demo_backend.py 8781" 2>/dev/null || true; sleep 0.5
rm -rf /tmp/claude-0/vd; mkdir -p "$OUT"
(SENTINEL_DATA=/tmp/claude-0/vd setsid python3 /home/claude/sentinel-video/demo_backend.py 8781 > "$OUT/backend.log" 2>&1 &)
sleep 2
python3 /home/claude/sentinel-video/director.py "$OUT" $DUR 2> "$OUT/director.log" || { tail -20 "$OUT/director.log"; exit 1; }
pkill -f "demo_backend.py 8781" || true
cat "$OUT/director.log" | grep -v "^$" | tail -20
