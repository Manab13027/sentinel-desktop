"""Cut the raw take at the sync point and lay every narration clip at the moment its scene began."""
import json
import re
import subprocess
import sys

TAKE, VOICE, OUT = sys.argv[1], sys.argv[2], sys.argv[3]
t = json.load(open(f"{TAKE}/timeline.json"))

# find the white sync flash
subprocess.run(["ffmpeg", "-v", "error", "-t", "15", "-i", f"{TAKE}/raw.mp4", "-vf",
                f"signalstats,metadata=print:key=lavfi.signalstats.YAVG:file={TAKE}/yavg.txt", "-f", "null", "-"], check=True)
flash = None
for blk in open(f"{TAKE}/yavg.txt").read().split("frame:")[1:]:
    if float(re.search(r"YAVG=([\d.]+)", blk).group(1)) > 150:
        flash = float(re.search(r"pts_time:([\d.]+)", blk).group(1))
        break
assert flash is not None, "sync flash not found"
t0 = flash + t["flash_to_t0"]
length = t["end"] + 2.4
print(f"flash={flash:.2f}s  t0={t0:.2f}s  length={length:.1f}s")

inputs, filters = [], []
for i, (lid, m) in enumerate(t["marks"].items()):
    inputs += ["-i", f"{VOICE}/{lid}.aiff"]
    ms = int(round(m * 1000))
    filters.append(f"[{i + 1}:a]aresample=48000,pan=stereo|c0=c0|c1=c0,adelay={ms}|{ms}[a{i}]")
n = len(t["marks"])
mix = "".join(f"[a{i}]" for i in range(n)) + f"amix=inputs={n}:normalize=0:dropout_transition=0,apad,atrim=0:{length:.2f}," \
      "highpass=f=70,acompressor=threshold=-20dB:ratio=3:attack=5:release=120,loudnorm=I=-16:TP=-1.5:LRA=11[aout]"
fc = ";".join(filters) + ";" + mix

cmd = ["ffmpeg", "-y", "-v", "error", "-ss", f"{t0:.3f}", "-t", f"{length:.2f}", "-i", f"{TAKE}/raw.mp4", *inputs,
       "-filter_complex", fc, "-map", "0:v", "-map", "[aout]",
       "-c:v", "libx264", "-preset", "slow", "-crf", "18", "-pix_fmt", "yuv420p", "-r", "25",
       "-c:a", "aac", "-b:a", "192k", "-movflags", "+faststart", OUT]
subprocess.run(cmd, check=True)

# YouTube chapter timestamps for the description
parts = {"intro": "Intro", "dashboard": "The dashboard", "ports": "Open ports & closing them", "network": "Network monitor",
         "vulns": "Vulnerabilities & patches", "advisor": "AI advisor", "settings": "Settings", "outro": "Wrap-up"}
lines = json.load(open("/home/claude/sentinel-video/narration.json"))
seen, chap = set(), []
for l in lines:
    if l["part"] not in seen:
        seen.add(l["part"])
        s = 0 if not chap else int(t["marks"][l["id"]])
        chap.append(f"{s // 60}:{s % 60:02d} {parts[l['part']]}")
open(OUT.rsplit(".", 1)[0] + "_chapters.txt", "w").write("\n".join(chap) + "\n")
print("\n".join(chap))
