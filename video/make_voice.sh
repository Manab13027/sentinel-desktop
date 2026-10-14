#!/bin/bash
# Records the Sentinel video narration with a built-in macOS male voice.
# Run:  bash ~/Documents/Projects_Folder/sentinel-desktop/video/make_voice.sh
set -e
cd "$(dirname "$0")"
mkdir -p voice
VOICES=$(say -v "?")
VOICE=""
for v in "Evan (Premium)" "Evan (Enhanced)" "Nathan (Premium)" "Nathan (Enhanced)" "Tom (Enhanced)" "Aaron (Enhanced)" "Daniel (Premium)" "Daniel (Enhanced)" "Rishi (Enhanced)" "Daniel" "Aaron" "Rishi" "Tom" "Alex" "Fred"; do
  if echo "$VOICES" | grep -q "^$v  "; then VOICE="$v"; break; fi
done
[ -z "$VOICE" ] && { echo "No male English voice found. Install one in System Settings > Accessibility > Spoken Content > System voice > Manage Voices."; exit 1; }
echo "Using voice: $VOICE"; echo "$VOICE" > voice/voice.txt
RATE=${RATE:-172}
echo "  l01"; say -v "$VOICE" -r "$RATE" -o "voice/l01.aiff" "This is Sentinel. An A I powered security app for Windows and Mac, that works completely offline."
echo "  l02"; say -v "$VOICE" -r "$RATE" -o "voice/l02.aiff" "In the next few minutes, I'll show you how it finds open ports, spots apps talking to servers they shouldn't, and fixes vulnerabilities with a single click."
echo "  l03"; say -v "$VOICE" -r "$RATE" -o "voice/l03.aiff" "Everything starts on the dashboard. One scan checks your open ports, your network connections, and your system's security settings."
echo "  l04"; say -v "$VOICE" -r "$RATE" -o "voice/l04.aiff" "On the left are the most exposed ports, ranked by risk, along with the application that opened each one."
echo "  l05"; say -v "$VOICE" -r "$RATE" -o "voice/l05.aiff" "In the middle is your overall security score. This machine scores poorly, with four critical issues."
echo "  l06"; say -v "$VOICE" -r "$RATE" -o "voice/l06.aiff" "On the right, the vulnerability board counts open issues by severity, including two that attackers are actively exploiting right now."
echo "  l07"; say -v "$VOICE" -r "$RATE" -o "voice/l07.aiff" "Below that, you can see how exposed your ports are, what Sentinel recommends doing about them, and the state of every outbound connection."
echo "  l08"; say -v "$VOICE" -r "$RATE" -o "voice/l08.aiff" "Let's look at the open ports. Each row shows the port, the service, and the exact program behind it. Its name, process I D, user, and file location."
echo "  l09"; say -v "$VOICE" -r "$RATE" -o "voice/l09.aiff" "Click any row, and Sentinel's A I explains the risk in plain English."
echo "  l10"; say -v "$VOICE" -r "$RATE" -o "voice/l10.aiff" "This one is a red flag. Port forty-four forty-four, the default port for Metasploit reverse shells, opened by a program running from a temporary folder."
echo "  l11"; say -v "$VOICE" -r "$RATE" -o "voice/l11.aiff" "To close it, click Close port. Sentinel offers to block it in the firewall, and it can also stop the program behind it."
echo "  l12"; say -v "$VOICE" -r "$RATE" -o "voice/l12.aiff" "I'll choose, Yes, close port. Windows asks for administrator permission, and the port is blocked instantly."
echo "  l13"; say -v "$VOICE" -r "$RATE" -o "voice/l13.aiff" "Blocked ports are marked with a lock, and you can undo any block with one click."
echo "  l14"; say -v "$VOICE" -r "$RATE" -o "voice/l14.aiff" "Next, the network monitor. Every fifteen seconds, Sentinel checks which applications are connecting out, and exactly where to."
echo "  l15"; say -v "$VOICE" -r "$RATE" -o "voice/l15.aiff" "Here, it caught a program called update dot exe, sending traffic to a cryptocurrency mining pool. That's a classic sign of crypto jacking."
echo "  l16"; say -v "$VOICE" -r "$RATE" -o "voice/l16.aiff" "And this file, opened from the Downloads folder, is talking to a raw I P address, on a port used by remote access trojans."
echo "  l17"; say -v "$VOICE" -r "$RATE" -o "voice/l17.aiff" "Sentinel also learns what's normal for each app. After the first day, any brand new destination is flagged as an anomaly."
echo "  l18"; say -v "$VOICE" -r "$RATE" -o "voice/l18.aiff" "For strict control, switch to Allowlist mode. Then, any destination you haven't approved is flagged as unauthorised."
echo "  l19"; say -v "$VOICE" -r "$RATE" -o "voice/l19.aiff" "One click blocks the address in the firewall. And if you don't recognise the program, Sentinel can stop it too."
echo "  l20"; say -v "$VOICE" -r "$RATE" -o "voice/l20.aiff" "Now, vulnerabilities. Sentinel audits your operating system, and checks your installed apps against a built in database of known exploits."
echo "  l21"; say -v "$VOICE" -r "$RATE" -o "voice/l21.aiff" "Findings are grouped by category, and sorted by severity. Anything being exploited in the wild is clearly marked."
echo "  l22"; say -v "$VOICE" -r "$RATE" -o "voice/l22.aiff" "Click, How to fix, and you get a full playbook. Why it matters, the manual steps, and the exact commands Sentinel will run."
echo "  l23"; say -v "$VOICE" -r "$RATE" -o "voice/l23.aiff" "Click, Apply fix automatically. Sentinel applies the fix, then re-checks the system, to confirm it's really fixed."
echo "  l24"; say -v "$VOICE" -r "$RATE" -o "voice/l24.aiff" "For missing patches, run a deep scan, and Sentinel lists every update that Windows or mac O S hasn't installed yet."
echo "  l25"; say -v "$VOICE" -r "$RATE" -o "voice/l25.aiff" "All of this feeds the A I advisor. You can ask it anything about your system."
echo "  l26"; say -v "$VOICE" -r "$RATE" -o "voice/l26.aiff" "It answers using your live scan results and its built in security knowledge. No internet, and no cloud model required."
echo "  l27"; say -v "$VOICE" -r "$RATE" -o "voice/l27.aiff" "On the right is your action plan, ordered by impact versus effort, so you always know what to fix first."
echo "  l28"; say -v "$VOICE" -r "$RATE" -o "voice/l28.aiff" "After fixing things, press Refresh, and anything that's resolved drops off the plan."
echo "  l29"; say -v "$VOICE" -r "$RATE" -o "voice/l29.aiff" "If you have a local A I model installed with Ollama, Sentinel can use it for more conversational answers. But everything works without it."
echo "  l30"; say -v "$VOICE" -r "$RATE" -o "voice/l30.aiff" "Finally, settings. Here you manage your allowed and blocked domains, and import extra threat intelligence feeds whenever you're online."
echo "  l31"; say -v "$VOICE" -r "$RATE" -o "voice/l31.aiff" "Every firewall rule Sentinel creates is listed here, so you can undo it at any time. And the activity log records every action."
echo "  l32"; say -v "$VOICE" -r "$RATE" -o "voice/l32.aiff" "And that's Sentinel. Your ports, your network, and your patches, all in one place, and completely offline."
echo "  l33"; say -v "$VOICE" -r "$RATE" -o "voice/l33.aiff" "If you found this video useful, please like, subscribe, and share it with someone who cares about security."
echo "  l34"; say -v "$VOICE" -r "$RATE" -o "voice/l34.aiff" "And if you'd like a copy of Sentinel for yourself, just send me a message here on YouTube. Thanks for watching."
echo "Done - $(ls voice/*.aiff | wc -l | tr -d " ") clips recorded in $(pwd)/voice"
