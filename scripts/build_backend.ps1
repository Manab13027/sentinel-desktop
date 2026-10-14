# Build the Python scanning engine into a single self-contained .exe (Windows).
# Output: backend-dist\sentinel-backend.exe  (bundled into the installer by electron-builder)
$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')

python -m venv .venv-build
.\.venv-build\Scripts\python.exe -m pip install --isolated -r backend\requirements.txt "pyinstaller>=6.16"

Remove-Item -Recurse -Force backend-dist, build-py -ErrorAction SilentlyContinue
$knowledge = Join-Path (Get-Location) 'backend\sentinel\knowledge'
.\.venv-build\Scripts\pyinstaller.exe backend\server.py `
  --name sentinel-backend `
  --onefile --noconfirm --clean --noconsole `
  --distpath backend-dist --workpath build-py --specpath build-py `
  --paths backend `
  --add-data "$knowledge;sentinel\knowledge" `
  --hidden-import sentinel.advisor --hidden-import sentinel.network --hidden-import sentinel.vulns

Write-Host "Built: backend-dist\sentinel-backend.exe"
