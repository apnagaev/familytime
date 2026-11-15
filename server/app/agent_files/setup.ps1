# FamilyTime: установка и обновление агента на компьютере вне домена.
# Запускается из FamilyTime-setup.cmd (скачивается на портале, страница «Компьютеры»),
# уже с правами администратора. Адрес портала, код установки и режим — в переменных
# окружения FT_URL, FT_CODE, FT_MODE.
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

function Say($text, $color = "Gray") { Write-Host $text -ForegroundColor $color }
function Fail($text) {
    Say ""
    Say "НЕ ПОЛУЧИЛОСЬ: $text" Red
    Say "Журнал установки: $env:ProgramData\FamilyTime-install.log" DarkGray
}

function Install-FamilyTime {
    $url = ($env:FT_URL).TrimEnd("/")
    $code = $env:FT_CODE
    $mode = if ($env:FT_MODE -eq "track") { "track" } else { "control" }
    Say ""
    Say "  FamilyTime — установка и обновление" Cyan
    Say "  Портал: $url"
    Say ""

    $me = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        return Fail "нужны права администратора. Запустите файл ещё раз и ответьте «Да» на запрос Windows."
    }
    if ([Environment]::OSVersion.Version.Major -lt 10 -or -not [Environment]::Is64BitOperatingSystem) {
        return Fail "нужна 64-разрядная Windows 10 или 11."
    }

    # уже установлен? — прежние настройки, если тот же портал
    $data = Join-Path $env:ProgramData "FamilyTime"
    $old = $null
    try { $old = Get-Content (Join-Path $data "config.json") -Raw -Encoding UTF8 | ConvertFrom-Json } catch { }
    $sameServer = $old -and $old.server_url -and ("$($old.server_url)".TrimEnd("/") -eq $url)

    Say "Проверяю портал..."
    $wc = New-Object Net.WebClient
    $wc.Encoding = [Text.Encoding]::UTF8          # Invoke-RestMethod в PowerShell 5.1 читает JSON как Latin-1
    try {
        $info = $wc.DownloadString("$url/agent/latest?code=$([uri]::EscapeDataString($code))") | ConvertFrom-Json
    } catch {
        return Fail "портал $url недоступен: $($_.Exception.Message). Проверьте интернет и попробуйте ещё раз."
    }
    if (-not $info.version) { return Fail "на портале нет программы для установки — напишите администратору." }

    if ($info.code_ok) {
        $secret = $code
        $mode = $info.mode
        $who = if ($info.family) { " (семья «$($info.family)»)" } else { "" }
        Say ("Код установки действует" + $who + ". Режим: " + $(if ($mode -eq "track") { "только локация" } else { "время и локация" })) Green
    } elseif ($sameServer) {
        $secret = $old.enroll_secret
        $mode = $old.mode
        Say "Программа уже установлена — обновляю, настройки не меняю." Green
    } else {
        return Fail "код установки в этом файле устарел или отозван. Скачайте новый установщик на портале (страница «Компьютеры»)."
    }
    if ($sameServer -and $info.code_ok -and $old.enroll_secret -ne $code) {
        # тот же портал, новый код: оставляем прежнюю регистрацию, если она есть
        $state = Join-Path $data "state.json"
        $hasToken = $false
        try { $hasToken = [bool]((Get-Content $state -Raw -Encoding UTF8 | ConvertFrom-Json).token) } catch { }
        if ($hasToken) {
            $secret = $old.enroll_secret
            $mode = $old.mode
            Say "Компьютер уже зарегистрирован — регистрацию и режим оставляю прежними." DarkGray
        }
    }

    # не %TEMP%: у учётной записи с русским именем он бывает в коротком виде (C:\Users\0737~1\...),
    # и такой путь не находится; папка в ProgramData — всегда латиницей и длинным именем
    $tmp = Join-Path $env:ProgramData ("FamilyTime-setup-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
    New-Item -ItemType Directory -Force $tmp | Out-Null
    $tmp = (Get-Item -LiteralPath $tmp).FullName
    try {
        $zip = Join-Path $tmp "FamilyTime.zip"
        Say ("Скачиваю FamilyTime {0} ({1:N0} МБ)..." -f $info.version, ($info.size / 1MB))
        $wc.DownloadFile("$url/agent/package.zip", $zip)
        $sha = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
        if ($sha -ne $info.sha256) { return Fail "файл скачался с ошибкой (контрольная сумма не совпала). Попробуйте ещё раз." }
        Say "Распаковываю..."
        $pkg = Join-Path $tmp "pkg"
        Expand-Archive -LiteralPath $zip -DestinationPath $pkg -Force
        if (-not (Test-Path -LiteralPath (Join-Path $pkg "install.ps1"))) { return Fail "в скачанном пакете нет install.ps1." }
        Say "Устанавливаю службу..."
        # вывод установщика — на экран; его сообщения в stderr не должны обрывать этот сценарий
        $ErrorActionPreference = "Continue"
        & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $pkg "install.ps1") `
            -Source $pkg -ServerUrl $url -EnrollSecret $secret -Mode $mode 2>&1 | ForEach-Object { Say "  $_" DarkGray }
        $rc = $LASTEXITCODE
        $ErrorActionPreference = "Stop"
        if ($rc -ne 0) { return Fail "установка завершилась с ошибкой (код $rc)." }
    } finally {
        Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }

    $svc = Get-Service FamilyTime -ErrorAction SilentlyContinue
    if (-not $svc -or $svc.Status -ne "Running") { return Fail "служба FamilyTime не запустилась." }

    Say "Жду регистрации на портале..."
    $ok = $false
    for ($i = 0; $i -lt 45; $i++) {
        try {
            if ((Get-Content (Join-Path $data "state.json") -Raw -Encoding UTF8 | ConvertFrom-Json).token) { $ok = $true; break }
        } catch { }
        Start-Sleep -Seconds 2
    }
    Say ""
    if ($ok) {
        Say "ГОТОВО. FamilyTime $($info.version) работает, компьютер появится на портале в течение минуты." Green
        Say "Обновления будут приходить сами. Окно можно закрыть."
    } else {
        Say "Программа установлена, но регистрация пока не прошла." Yellow
        Say "Если компьютер не появится на портале за 5 минут — проверьте интернет и запустите файл ещё раз."
        Say "Журнал агента: $data\logs\agent.log" DarkGray
    }
}

try { Install-FamilyTime } catch { Fail $_.Exception.Message }
