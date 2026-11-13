# Сборка агента на Windows: нужен Python 3.12 x64.
# Результат: dist\FamilyTime-<версия>.zip — папка FamilyTime + install.ps1 + uninstall.ps1
param([string]$Python = "python")
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$ver = (Select-String -Path familytime_agent\__init__.py -Pattern 'VERSION = "(.+)"').Matches[0].Groups[1].Value
if (-not (Test-Path .venv)) { & $Python -m venv .venv }
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
# обёртки comtypes для UI Automation — заранее, чтобы они попали в exe
.\.venv\Scripts\python.exe -c "import comtypes.client as cc; cc.GetModule('UIAutomationCore.dll'); import comtypes.gen.UIAutomationClient, comtypes.gen.stdole; print('comtypes gen OK')"
if ($LASTEXITCODE -ne 0) { throw "не удалось сгенерировать обёртки comtypes" }
.\.venv\Scripts\pyinstaller.exe --noconfirm --clean familytime.spec

$out = "dist\package"
Remove-Item $out -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory $out | Out-Null
Copy-Item dist\FamilyTime "$out\FamilyTime" -Recurse
Set-Content "$out\FamilyTime\version.txt" $ver -Encoding ascii
Copy-Item install.ps1, uninstall.ps1, familytime.example.json $out
Compress-Archive -Path "$out\*" -DestinationPath "dist\FamilyTime-$ver.zip" -Force
Write-Host "Готово: dist\FamilyTime-$ver.zip"
