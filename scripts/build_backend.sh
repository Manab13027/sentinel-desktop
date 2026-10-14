#!/usr/bin/env bash
# Build the Python scanning engine into a single self-contained binary (macOS / Linux).
# Output: backend-dist/sentinel-backend  (bundled into the app by electron-builder)
set -euo pipefail
cd "$(dirname "$0")/.."

python3 -m venv .venv-build
source .venv-build/bin/activate
# --isolated ignores global pip config (e.g. extra/unreachable package indexes).
# PyInstaller >= 6.16 is required for Python 3.14.
pip install --isolated -r backend/requirements.txt "pyinstaller>=6.16"

rm -rf backend-dist build-py
pyinstaller backend/server.py \
  --name sentinel-backend \
  --onefile --noconfirm --clean \
  --distpath backend-dist --workpath build-py --specpath build-py \
  --paths backend \
  --add-data "$(pwd)/backend/sentinel/knowledge:sentinel/knowledge" \
  --hidden-import sentinel.advisor --hidden-import sentinel.network --hidden-import sentinel.vulns

echo "Built: backend-dist/sentinel-backend"
