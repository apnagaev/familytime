<#
.SYNOPSIS
  Установка и обновление агента FamilyTime. Запускается от SYSTEM (сценарий автозагрузки
  компьютера в GPO) или вручную от администратора.

.EXAMPLE
  # из общей папки, рядом лежат папка FamilyTime и familytime.json
  powershell -ExecutionPolicy Bypass -File \\server\familytime$\install.ps1

.EXAMPLE
  .\install.ps1 -ServerUrl https://kids.example.com -EnrollSecret ... -Mode track
#>
param(
    [string]$Source = $PSScriptRoot,
    [string]$ServerUrl,
    [string]$EnrollSecret,
    [ValidateSet("control", "track")][string]$Mode,
    [switch]$Force
)
$ErrorActionPreference = "Stop"
$Name = "FamilyTime"
$Dest = Join-Path $env:ProgramFiles $Name
$Data = Join-Path $env:ProgramData $Name
$Log = Join-Path $env:ProgramData "$Name-install.log"

function Log($m) { "$(Get-Date -Format s) $m" | Tee-Object -FilePath $Log -Append | Out-Host }

try {
    # ---- настройки: параметры важнее familytime.json рядом со сценарием
    $cfg = @{ mode = "control" }
    $jsonPath = Join-Path $Source "familytime.json"
    if (Test-Path $jsonPath) {
        (Get-Content $jsonPath -Raw -Encoding UTF8 | ConvertFrom-Json).PSObject.Properties |
            ForEach-Object { $cfg[$_.Name] = $_.Value }
    }
    if ($ServerUrl) { $cfg.server_url = $ServerUrl }
    if ($EnrollSecret) { $cfg.enroll_secret = $EnrollSecret }
    if ($Mode) { $cfg.mode = $Mode }
    if (-not $cfg.server_url -or -not $cfg.enroll_secret) { throw "Нужны server_url и enroll_secret (familytime.json рядом с install.ps1: $jsonPath)" }
    if ($cfg.server_url -match 'example\.(com|org|net)' -or $cfg.enroll_secret -match '^тот-же') {
        throw "В familytime.json значения из примера: укажите адрес портала и ENROLL_SECRET сервера"
    }

    # версия: version.txt из сборки, иначе — из свойств familytime-agent.exe
    $verFile = Join-Path $Source "$Name\version.txt"
    $exeFile = Join-Path $Source "$Name\familytime-agent.exe"
    if (Test-Path $verFile) { $newVer = (Get-Content $verFile).Trim() }
    elseif (Test-Path $exeFile) { $newVer = (Get-Item $exeFile).VersionInfo.ProductVersion }
    else { throw "Не найдена папка $Name с familytime-agent.exe рядом с install.ps1 ($Source)" }
    $curVer = if (Test-Path "$Dest\version.txt") { (Get-Content "$Dest\version.txt").Trim() } else { "" }
    $svc = Get-Service $Name -ErrorAction SilentlyContinue

    # ---- данные: config.json доступен только SYSTEM и администраторам
    New-Item -ItemType Directory -Force $Data | Out-Null
    & icacls $Data /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" | Out-Null
    $cfgPath = Join-Path $Data "config.json"
    $cfgJson = ([ordered]@{ server_url = $cfg.server_url; enroll_secret = $cfg.enroll_secret; mode = $cfg.mode } |
        ConvertTo-Json)
    $cfgChanged = -not (Test-Path $cfgPath) -or ((Get-Content $cfgPath -Raw) -ne $cfgJson)

    if (-not $Force -and $svc -and $curVer -eq $newVer -and -not $cfgChanged) {
        if ($svc.Status -ne "Running") { Start-Service $Name }
        exit 0
    }
    Log "установка $newVer (было: '$curVer'), запуск от $([Security.Principal.WindowsIdentity]::GetCurrent().Name), источник $Source"

    if ($svc) {
        Stop-Service $Name -Force -ErrorAction SilentlyContinue
        (Get-Service $Name).WaitForStatus("Stopped", "00:00:30")
    }
    Get-Process familytime-helper -ErrorAction SilentlyContinue | Stop-Process -Force

    # ---- файлы
    $srcMb = [int]((Get-ChildItem (Join-Path $Source $Name) -Recurse -File | Measure-Object Length -Sum).Sum / 1MB)
    Log "копирование файлов: $srcMb МБ"
    & robocopy (Join-Path $Source $Name) $Dest /MIR /R:2 /W:2 /NFL /NDL /NJH /NJS /NP | Out-Null
    if ($LASTEXITCODE -ge 8) { throw "robocopy: код $LASTEXITCODE" }
    Log "файлы скопированы (robocopy $LASTEXITCODE)"
    Set-Content "$Dest\version.txt" $newVer -Encoding ascii
    # прежний токен выдан для другого сервера или секрета — регистрация заново
    if ($cfgChanged) { Remove-Item (Join-Path $Data "state.json") -Force -ErrorAction SilentlyContinue }
    [IO.File]::WriteAllText($cfgPath, $cfgJson, (New-Object Text.UTF8Encoding $false))

    # ---- местоположение: без него Windows 11 24H2 не отдаёт список Wi-Fi
    $loc = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location"
    New-Item -Path $loc -Force | Out-Null
    Set-ItemProperty -Path $loc -Name Value -Value "Allow"
    New-Item -Path "$loc\NonPackaged" -Force | Out-Null
    Set-ItemProperty -Path "$loc\NonPackaged" -Name Value -Value "Allow"
    Set-Service lfsvc -StartupType Manual -ErrorAction SilentlyContinue

    # ---- служба
    Log "служба: создание и запуск"
    if (-not $svc) {
        New-Service -Name $Name -BinaryPathName "`"$Dest\familytime-agent.exe`"" -DisplayName $Name `
            -Description "Учёт и ограничение времени за компьютером, локация компьютера." `
            -StartupType Automatic | Out-Null
    }
    & sc.exe failure $Name reset= 86400 actions= restart/5000/restart/10000/restart/30000 | Out-Null
    & sc.exe failureflag $Name 1 | Out-Null
    Start-Service $Name
    Log "готово"
}
catch {
    Log "ОШИБКА: $_"
    exit 1
}
