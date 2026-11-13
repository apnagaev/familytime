<#
.SYNOPSIS
  Удаление агента FamilyTime: служба, файлы, и политики браузеров, которые агент мог оставить
  в разделах реестра пользователей (иначе браузер ребёнка останется в режиме «только учёба»).
#>
$ErrorActionPreference = "Continue"
$Name = "FamilyTime"

Stop-Service $Name -Force -ErrorAction SilentlyContinue
& sc.exe delete $Name | Out-Null
Get-Process familytime-helper, familytime-agent -ErrorAction SilentlyContinue | Stop-Process -Force

$keys = "Software\Policies\Google\Chrome", "Software\Policies\Microsoft\Edge", "Software\Policies\YandexBrowser"
$lists = "URLBlocklist", "URLAllowlist", "URLBlacklist", "URLWhitelist"

function Clean([string]$root) {
    foreach ($k in $keys) {
        foreach ($l in $lists) { & reg.exe delete "$root\$k\$l" /f 2>$null | Out-Null }
        foreach ($v in "IncognitoModeAvailability", "InPrivateModeAvailability", "BrowserGuestModeEnabled") {
            & reg.exe delete "$root\$k" /v $v /f 2>$null | Out-Null
        }
    }
}

$profiles = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" |
    Where-Object { $_.PSChildName -match '^S-1-5-21-' }
foreach ($p in $profiles) {
    $sid = $p.PSChildName
    if (Test-Path "Registry::HKEY_USERS\$sid") {
        Clean "HKU\$sid"
    } else {
        $hive = Join-Path (Get-ItemProperty $p.PSPath).ProfileImagePath "NTUSER.DAT"
        if (Test-Path $hive) {
            & reg.exe load "HKU\FT_$sid" $hive 2>$null | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Clean "HKU\FT_$sid"
                [gc]::Collect()
                & reg.exe unload "HKU\FT_$sid" | Out-Null
            }
        }
    }
}

Remove-Item (Join-Path $env:ProgramFiles $Name) -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item (Join-Path $env:ProgramData $Name) -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "FamilyTime удалён"
