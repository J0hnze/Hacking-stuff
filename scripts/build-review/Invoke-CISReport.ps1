# Invoke-CISReport.ps1 - self-contained Windows CIS-style audit report
#
# Drop this single file onto a test machine, then run:
#   powershell -ExecutionPolicy Bypass -File .\Invoke-CISReport.ps1
#
# Default output:
#   %USERPROFILE%\audit-temp\COMPUTERNAME_YYYY-MM-DD_HH-MM-SS.html
#
# Optional:
#   powershell -ExecutionPolicy Bypass -File .\Invoke-CISReport.ps1 -OutDir D:\reports

param(
    [string]$OutDir = (Join-Path $env:USERPROFILE "audit-temp")
)

$ErrorActionPreference = "Continue"

$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$reportDate = Get-Date -Format "dd MMM yyyy HH:mm:ss"
$hostname = $env:COMPUTERNAME
$outFile = Join-Path $OutDir "${hostname}_${timestamp}.html"
$results = New-Object System.Collections.Generic.List[object]

function Add-CISResult {
    param(
        [string]$CIS,
        [string]$Section,
        [ValidateSet("PASS", "FAIL", "WARN", "INFO")]
        [string]$Status,
        [string]$Message,
        [string]$Fix = ""
    )

    $results.Add([pscustomobject]@{
        CIS = $CIS
        Section = $Section
        Status = $Status
        Message = $Message
        Fix = $Fix
    })

    $colour = switch ($Status) {
        "PASS" { "Green" }
        "FAIL" { "Red" }
        "WARN" { "Yellow" }
        default { "Cyan" }
    }
    Write-Host ("  [{0}] CIS {1} - {2}" -f $Status, $CIS, $Message) -ForegroundColor $colour
}

function HtmlEncode {
    param([object]$Value)
    if ($null -eq $Value) { return "" }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-NetAccountsNumber {
    param([string]$Label)

    $line = net accounts 2>$null | Select-String -Pattern $Label | Select-Object -First 1
    if (-not $line) { return $null }

    if ([string]$line -match "Never") { return 0 }

    $digits = ([string]$line -replace '[^\d]', '').Trim()
    if ($digits -eq "") { return $null }
    return [int]$digits
}

function Get-AuditSetting {
    param([string]$Subcategory)

    $result = auditpol /get /subcategory:"$Subcategory" 2>$null | Select-String -Pattern $Subcategory | Select-Object -First 1
    if (-not $result) { return "Not Found" }
    return (([string]$result) -split '\s{2,}')[-1].Trim()
}

function Get-RegistryValue {
    param(
        [string]$Path,
        [string]$Name
    )

    $props = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
    if (-not $props) { return $null }
    return $props.$Name
}

function Test-MinPasswordAge {
    $value = Get-NetAccountsNumber -Label "Minimum password age"
    if ($null -eq $value) {
        Add-CISResult "1.2" "Account Policy" "WARN" "Minimum password age could not be read." "Check local or domain password policy manually."
        return
    }
    $status = if ($value -ge 1) { "PASS" } else { "FAIL" }
    Add-CISResult "1.2" "Account Policy" $status "Minimum password age: $value day(s). Expected: >= 1." "Set minimum password age to at least 1 day."
}

function Test-LockoutDuration {
    $value = Get-NetAccountsNumber -Label "Lockout duration"
    if ($null -eq $value) {
        Add-CISResult "1.7" "Account Policy" "WARN" "Lockout duration could not be read." "Check local or domain account lockout policy manually."
        return
    }
    $status = if ($value -eq 0 -or $value -ge 15) { "PASS" } else { "FAIL" }
    Add-CISResult "1.7" "Account Policy" $status "Lockout duration: $value minute(s). Expected: >= 15, or 0 until administrator unlocks." "Set account lockout duration to 15 minutes or more."
}

function Test-LockoutThreshold {
    $value = Get-NetAccountsNumber -Label "Lockout threshold"
    if ($null -eq $value) {
        Add-CISResult "1.8" "Account Policy" "WARN" "Lockout threshold could not be read." "Check local or domain account lockout policy manually."
        return
    }
    $status = if ($value -ge 1 -and $value -le 5) { "PASS" } else { "FAIL" }
    Add-CISResult "1.8" "Account Policy" $status "Lockout threshold: $value attempt(s). Expected: 1-5." "Set account lockout threshold between 1 and 5 invalid attempts."
}

function Test-LockoutObservationWindow {
    $value = Get-NetAccountsNumber -Label "Lockout observation window"
    if ($null -eq $value) {
        Add-CISResult "1.9" "Account Policy" "WARN" "Lockout observation window could not be read." "Check local or domain account lockout policy manually."
        return
    }
    $status = if ($value -ge 15) { "PASS" } else { "FAIL" }
    Add-CISResult "1.9" "Account Policy" $status "Reset lockout counter after: $value minute(s). Expected: >= 15." "Set reset lockout counter after to at least 15 minutes."
}

function Test-AdminAccountRename {
    $admin = Get-LocalUser -ErrorAction SilentlyContinue | Where-Object { $_.SID -like "*-500" } | Select-Object -First 1
    if (-not $admin) {
        Add-CISResult "2.1" "Local Policy" "WARN" "Built-in Administrator account could not be found." "Verify the local SID ending in -500 manually."
        return
    }
    $status = if ($admin.Name -ne "Administrator") { "PASS" } else { "FAIL" }
    Add-CISResult "2.1" "Local Policy" $status "Built-in Administrator account name: '$($admin.Name)'. Expected: not 'Administrator'." "Rename the built-in Administrator account."
}

function Test-GuestAccountStatus {
    $guest = Get-LocalUser -ErrorAction SilentlyContinue | Where-Object { $_.SID -like "*-501" -or $_.Name -eq "Guest" } | Select-Object -First 1
    if (-not $guest) {
        Add-CISResult "2.2" "Local Policy" "PASS" "Guest account not found." ""
        return
    }
    $status = if (-not $guest.Enabled) { "PASS" } else { "FAIL" }
    Add-CISResult "2.2" "Local Policy" $status "Guest account enabled: $($guest.Enabled). Expected: False." "Disable the Guest account."
}

function Test-LimitBlankPasswordUse {
    $value = Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "LimitBlankPasswordUse"
    $status = if ($value -eq 1) { "PASS" } else { "FAIL" }
    Add-CISResult "2.3/6.3" "Local Policy" $status "LimitBlankPasswordUse: $value. Expected: 1." "Set HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse to 1."
}

function Test-UACSettings {
    $key = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $checks = @(
        @{ CIS = "6.5"; Name = "EnableLUA"; Expected = 1; Desc = "UAC enabled" },
        @{ CIS = "6.6"; Name = "ConsentPromptBehaviorAdmin"; Expected = 2; Desc = "Admin prompt for consent" },
        @{ CIS = "6.7"; Name = "EnableInstallerDetection"; Expected = 1; Desc = "Detect application installs and prompt" },
        @{ CIS = "6.8"; Name = "PromptOnSecureDesktop"; Expected = 1; Desc = "Prompt on secure desktop" }
    )

    foreach ($check in $checks) {
        $value = Get-RegistryValue $key $check.Name
        $status = if ($value -eq $check.Expected) { "PASS" } else { "FAIL" }
        Add-CISResult $check.CIS "Local Policy" $status "$($check.Desc) ($($check.Name)): $value. Expected: $($check.Expected)." "Set $($check.Name) to $($check.Expected)."
    }
}

function Test-AuditAccountLogon {
    $categories = @("Logon", "Logoff", "Account Lockout", "Credential Validation")
    foreach ($category in $categories) {
        $setting = Get-AuditSetting $category
        $status = if ($setting -match "Success and Failure") { "PASS" } else { "FAIL" }
        Add-CISResult "2.5" "Audit Policy" $status "Audit '$category': $setting. Expected: Success and Failure." "Configure advanced audit policy for '$category' to Success and Failure."
    }
}

function Test-AuditPrivilegeUse {
    $setting = Get-AuditSetting "Privilege Use"
    $status = if ($setting -match "Success and Failure") { "PASS" } else { "FAIL" }
    Add-CISResult "2.6" "Audit Policy" $status "Audit Privilege Use: $setting. Expected: Success and Failure." "Configure Audit Privilege Use to Success and Failure."
}

function Test-AuditPolicyStatus {
    $subcategories = @(
        "Logon",
        "Logoff",
        "Account Lockout",
        "Credential Validation",
        "Security Group Management",
        "User Account Management",
        "Process Creation",
        "Policy Change",
        "Privilege Use",
        "System Integrity"
    )

    foreach ($subcategory in $subcategories) {
        $setting = Get-AuditSetting $subcategory
        $status = if ($setting -ne "No Auditing" -and $setting -ne "Not Found" -and $setting -ne "Not configured") { "PASS" } else { "FAIL" }
        Add-CISResult "2.7" "Audit Policy" $status "Audit '$subcategory': $setting. Expected: configured." "Configure advanced audit policy for '$subcategory'."
    }
}

function Test-EventLogRetention {
    $logs = @("Security", "System", "Application")
    foreach ($log in $logs) {
        $line = wevtutil gl $log 2>$null | Select-String "retention:" | Select-Object -First 1
        $retention = if ($line) { (([string]$line) -replace '.*:\s*', '').Trim() } else { "Unknown" }
        $status = if ($retention -eq "true") { "PASS" } else { "FAIL" }
        Add-CISResult "3.1" "Event Log" $status "$log log retention: $retention. Expected: true." "Configure $log event log retention to retain or archive logs rather than overwrite as needed."
    }
}

function Test-SecurityLogSize {
    $logs = @("Security", "System", "Application")
    foreach ($log in $logs) {
        $line = wevtutil gl $log 2>$null | Select-String "maxSize:" | Select-Object -First 1
        $maxSize = if ($line) { [long](([string]$line) -replace '\D', '') } else { 0 }
        $maxKB = [math]::Round($maxSize / 1KB)
        $status = if ($maxKB -ge 196608) { "PASS" } else { "FAIL" }
        Add-CISResult "3.2" "Event Log" $status "$log log max size: $maxKB KB. Expected: >= 196608 KB." "Set $log event log maximum size to at least 196608 KB."
    }
}

function Test-PowerShellLanguageMode {
    $currentMode = $ExecutionContext.SessionState.LanguageMode
    $status = if ($currentMode -eq "ConstrainedLanguage") { "PASS" } else { "WARN" }
    Add-CISResult "5.1" "PowerShell" $status "Current PowerShell language mode: $currentMode. Expected in hardened estates: ConstrainedLanguage." "Use WDAC or AppLocker policy where Constrained Language Mode is required."

    $sbValue = Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" "EnableScriptBlockLogging"
    $sbStatus = if ($sbValue -eq 1) { "PASS" } else { "FAIL" }
    Add-CISResult "5.2" "PowerShell" $sbStatus "Script Block Logging: $sbValue. Expected: 1." "Enable PowerShell Script Block Logging by policy."

    $mlValue = Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" "EnableModuleLogging"
    $mlStatus = if ($mlValue -eq 1) { "PASS" } else { "FAIL" }
    Add-CISResult "5.3" "PowerShell" $mlStatus "Module Logging: $mlValue. Expected: 1." "Enable PowerShell Module Logging by policy."
}

function Test-LAPSInstalled {
    $legacyLAPS = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions\*" -ErrorAction SilentlyContinue |
        Where-Object { $_.DllName -like "*AdmPwd*" } |
        Select-Object -First 1
    $windowsLAPS = Get-Command "Get-LapsAADPassword" -ErrorAction SilentlyContinue

    if ($legacyLAPS -or $windowsLAPS) {
        $source = if ($windowsLAPS) { "Windows LAPS cmdlets detected" } else { "Legacy LAPS AdmPwd extension detected" }
        Add-CISResult "16.1" "LAPS" "PASS" "LAPS installed: $source." ""
    }
    else {
        Add-CISResult "16.1" "LAPS" "FAIL" "LAPS not detected." "Install Microsoft LAPS or enable Windows LAPS via policy."
    }

    $legacyPolicy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd" -ErrorAction SilentlyContinue
    $windowsPolicy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Policies\LAPS" -ErrorAction SilentlyContinue
    if ($legacyPolicy -or $windowsPolicy) {
        Add-CISResult "16.2" "LAPS" "INFO" "LAPS policy key found. Verify password age, complexity, backup target, and permissions against the estate standard." ""
    }
    else {
        Add-CISResult "16.2" "LAPS" "WARN" "LAPS policy key not found." "Verify LAPS configuration in GPMC/Intune."
    }
}

function Test-BitLockerMode {
    if (-not (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)) {
        Add-CISResult "13.1" "BitLocker" "WARN" "Get-BitLockerVolume is unavailable on this system." "Check BitLocker status manually with manage-bde -status."
        return
    }

    $drives = Get-Volume -ErrorAction SilentlyContinue |
        Where-Object { $_.DriveType -eq "Fixed" -and $_.DriveLetter } |
        Select-Object -ExpandProperty DriveLetter |
        ForEach-Object { "$_`:" }

    if (-not $drives) {
        Add-CISResult "13.1" "BitLocker" "WARN" "No fixed drives with drive letters were found." "Check encryption status manually."
        return
    }

    foreach ($drive in $drives) {
        $bitLockerVolume = Get-BitLockerVolume -MountPoint $drive -ErrorAction SilentlyContinue
        if (-not $bitLockerVolume) {
            Add-CISResult "13.1" "BitLocker" "WARN" "$drive BitLocker status could not be read." "Check $drive manually with manage-bde -status."
            continue
        }

        $status = $bitLockerVolume.VolumeStatus
        $protectors = ($bitLockerVolume.KeyProtector | ForEach-Object { $_.KeyProtectorType }) -join ", "

        if ($status -notmatch "FullyEncrypted|EncryptionInProgress") {
            Add-CISResult "13.1" "BitLocker" "FAIL" "$drive is not encrypted ($status)." "Enable BitLocker on $drive."
        }
        elseif ($protectors -match "Tpm$" -and $protectors -notmatch "TpmPin|TpmStartupKey|TpmNetworkKey|RecoveryPassword") {
            Add-CISResult "13.1" "BitLocker" "FAIL" "$drive uses TPM-only protection ($protectors)." "Enable a pre-boot PIN or startup key where physical attack resistance is required."
        }
        elseif ($protectors -match "TpmPin|TpmStartupKey|TpmNetworkKey") {
            Add-CISResult "13.1" "BitLocker" "PASS" "$drive encrypted with stronger TPM protector configuration ($protectors)." ""
        }
        elseif ($protectors -match "Password|RecoveryPassword" -and $protectors -notmatch "Tpm") {
            Add-CISResult "13.1" "BitLocker" "WARN" "$drive encrypted but appears to use password/recovery-only protection ($protectors)." "Verify protector design against the build standard."
        }
        else {
            Add-CISResult "13.1" "BitLocker" "WARN" "$drive encrypted but protector configuration is unclear ($protectors)." "Verify protector design against the build standard."
        }
    }
}

if (-not (Test-Path $OutDir)) {
    New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
}

$isAdmin = Test-IsAdmin
$os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
if (-not $os) { $os = Get-WmiObject Win32_OperatingSystem -ErrorAction SilentlyContinue }
$computer = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
if (-not $computer) { $computer = Get-WmiObject Win32_ComputerSystem -ErrorAction SilentlyContinue }

$osName = if ($os) { $os.Caption } else { "Unknown" }
$osBuild = if ($os) { $os.BuildNumber } else { "Unknown" }
$domain = if ($computer) { $computer.Domain } else { "Unknown" }
$user = "$env:USERDOMAIN\$env:USERNAME"
$lastBoot = $null
if ($os -and $os.LastBootUpTime) {
    if ($os.LastBootUpTime -is [datetime]) {
        $lastBoot = $os.LastBootUpTime
    }
    elseif ($os.PSObject.Methods.Name -contains "ConvertToDateTime") {
        $lastBoot = $os.ConvertToDateTime($os.LastBootUpTime)
    }
}
$uptime = if ($lastBoot) { (Get-Date) - $lastBoot } else { $null }
$uptimeText = if ($uptime) { "{0}h {1}m" -f [int]$uptime.TotalHours, $uptime.Minutes } else { "Unknown" }

Write-Host ""
Write-Host "CIS Benchmark Report - $hostname" -ForegroundColor Cyan
Write-Host "Output: $outFile" -ForegroundColor Cyan
if (-not $isAdmin) {
    Write-Host "Warning: not running as Administrator. Some checks may return WARN or incomplete results." -ForegroundColor Yellow
}
Write-Host ""

Test-MinPasswordAge
Test-LockoutDuration
Test-LockoutThreshold
Test-LockoutObservationWindow
Test-AdminAccountRename
Test-GuestAccountStatus
Test-LimitBlankPasswordUse
Test-UACSettings
Test-AuditAccountLogon
Test-AuditPrivilegeUse
Test-AuditPolicyStatus
Test-EventLogRetention
Test-SecurityLogSize
Test-PowerShellLanguageMode
Test-LAPSInstalled
Test-BitLockerMode

$totalPass = @($results | Where-Object { $_.Status -eq "PASS" }).Count
$totalFail = @($results | Where-Object { $_.Status -eq "FAIL" }).Count
$totalWarn = @($results | Where-Object { $_.Status -eq "WARN" }).Count
$totalInfo = @($results | Where-Object { $_.Status -eq "INFO" }).Count
$totalChecks = $totalPass + $totalFail + $totalWarn
$passPct = if ($totalChecks -gt 0) { [math]::Round($totalPass / $totalChecks * 100) } else { 0 }

$tableRows = foreach ($result in $results) {
    $statusClass = $result.Status.ToLowerInvariant()
    $fixHtml = ""
    if ($result.Fix) {
        $fixHtml = "<div class='fix'><strong>Fix:</strong> $(HtmlEncode $result.Fix)</div>"
    }

    "<tr class='$statusClass'>
      <td class='badge-cell'><span class='badge $statusClass'>$($result.Status)</span></td>
      <td class='cis'>$(HtmlEncode $result.CIS)</td>
      <td class='section'>$(HtmlEncode $result.Section)</td>
      <td>$(HtmlEncode $result.Message)$fixHtml</td>
    </tr>"
}

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CIS Benchmark Report - $(HtmlEncode $hostname)</title>
<style>
  :root {
    --pass: #1a7f4b; --pass-bg: #e8f5ee; --pass-border: #a3d9b8;
    --fail: #c0392b; --fail-bg: #fdf0ee; --fail-border: #f0a8a1;
    --warn: #b7770d; --warn-bg: #fef9ec; --warn-border: #f5d98a;
    --info: #2471a3; --info-bg: #eaf4fb; --info-border: #aed6f1;
    --bg: #f4f5f7; --surface: #ffffff; --text: #1a1a2e; --muted: #6b7280;
    --radius: 6px; --font: 'Segoe UI', system-ui, sans-serif;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); font-family: var(--font); color: var(--text); font-size: 14px; }
  header { background: #1a1a2e; color: #fff; padding: 24px 32px; }
  header h1 { font-size: 1.4em; font-weight: 600; margin-bottom: 4px; }
  header .meta { opacity: .7; font-size: .82em; display: flex; gap: 24px; flex-wrap: wrap; margin-top: 8px; }
  .container { max-width: 1120px; margin: 0 auto; padding: 24px 32px; }
  .summary { display: grid; grid-template-columns: repeat(5, 1fr); gap: 16px; margin-bottom: 28px; }
  .card { background: var(--surface); border-radius: var(--radius); padding: 16px 20px; border-top: 4px solid #6c757d; box-shadow: 0 1px 3px rgba(0,0,0,.08); }
  .card.pass { border-color: var(--pass); }
  .card.fail { border-color: var(--fail); }
  .card.warn { border-color: var(--warn); }
  .card.info { border-color: var(--info); }
  .card .num { font-size: 2.2em; font-weight: 700; line-height: 1; }
  .card .lbl { font-size: .72em; text-transform: uppercase; letter-spacing: .08em; color: var(--muted); margin-top: 4px; }
  .card.pass .num { color: var(--pass); }
  .card.fail .num { color: var(--fail); }
  .card.warn .num { color: var(--warn); }
  .card.info .num { color: var(--info); }
  .progress-wrap, .host-info { background: var(--surface); border-radius: var(--radius); padding: 16px 20px; margin-bottom: 28px; box-shadow: 0 1px 3px rgba(0,0,0,.08); }
  .progress-wrap .label { font-size: .78em; color: var(--muted); margin-bottom: 8px; }
  .bar-bg { background: #e5e7eb; border-radius: 99px; height: 12px; overflow: hidden; }
  .bar-fill { height: 100%; border-radius: 99px; background: linear-gradient(90deg, var(--pass), #27ae60); }
  .host-info { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; }
  .host-info .k { font-size: .72em; text-transform: uppercase; letter-spacing: .08em; color: var(--muted); }
  .host-info .v { font-weight: 600; margin-top: 2px; }
  table { width: 100%; border-collapse: collapse; background: var(--surface); border-radius: var(--radius); overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,.08); }
  thead { background: #1a1a2e; color: #fff; }
  thead th { padding: 10px 14px; text-align: left; font-size: .75em; font-weight: 600; text-transform: uppercase; letter-spacing: .06em; }
  tbody tr { border-bottom: 1px solid #f0f0f0; }
  tbody tr:last-child { border-bottom: none; }
  tbody tr:hover { background: #fafafa; }
  td { padding: 9px 14px; vertical-align: top; }
  .badge-cell { width: 72px; }
  .cis { width: 70px; font-family: Consolas, monospace; font-size: .85em; color: var(--muted); }
  .section { width: 150px; font-size: .82em; color: var(--muted); }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 99px; font-size: .72em; font-weight: 700; letter-spacing: .05em; text-transform: uppercase; }
  .badge.pass { background: var(--pass-bg); color: var(--pass); border: 1px solid var(--pass-border); }
  .badge.fail { background: var(--fail-bg); color: var(--fail); border: 1px solid var(--fail-border); }
  .badge.warn { background: var(--warn-bg); color: var(--warn); border: 1px solid var(--warn-border); }
  .badge.info { background: var(--info-bg); color: var(--info); border: 1px solid var(--info-border); }
  tr.fail td { background: #fff8f7; }
  .fix { margin-top: 5px; color: #374151; font-size: .92em; }
  footer { text-align: center; padding: 24px; font-size: .75em; color: var(--muted); }
  @media (max-width: 820px) {
    .summary { grid-template-columns: repeat(2, 1fr); }
    .host-info { grid-template-columns: 1fr; }
    .container { padding: 18px; }
  }
</style>
</head>
<body>
<header>
  <h1>CIS Benchmark Report - $(HtmlEncode $hostname)</h1>
  <div class="meta">
    <span>Generated: $(HtmlEncode $reportDate)</span>
    <span>Operator: $(HtmlEncode $user)</span>
    <span>Domain: $(HtmlEncode $domain)</span>
    <span>Admin: $isAdmin</span>
  </div>
</header>
<div class="container">
  <div class="summary">
    <div class="card pass"><div class="num">$totalPass</div><div class="lbl">Pass</div></div>
    <div class="card fail"><div class="num">$totalFail</div><div class="lbl">Fail</div></div>
    <div class="card warn"><div class="num">$totalWarn</div><div class="lbl">Warn</div></div>
    <div class="card info"><div class="num">$totalInfo</div><div class="lbl">Info</div></div>
    <div class="card"><div class="num">$totalChecks</div><div class="lbl">Scored Checks</div></div>
  </div>
  <div class="progress-wrap">
    <div class="label">Pass rate - $passPct%</div>
    <div class="bar-bg"><div class="bar-fill" style="width:${passPct}%"></div></div>
  </div>
  <div class="host-info">
    <div><div class="k">Hostname</div><div class="v">$(HtmlEncode $hostname)</div></div>
    <div><div class="k">OS</div><div class="v">$(HtmlEncode $osName)</div></div>
    <div><div class="k">Build</div><div class="v">$(HtmlEncode $osBuild)</div></div>
    <div><div class="k">Uptime</div><div class="v">$(HtmlEncode $uptimeText)</div></div>
    <div><div class="k">Domain</div><div class="v">$(HtmlEncode $domain)</div></div>
    <div><div class="k">Run as</div><div class="v">$(HtmlEncode $user)</div></div>
  </div>
  <table>
    <thead>
      <tr>
        <th>Result</th>
        <th>CIS</th>
        <th>Section</th>
        <th>Detail</th>
      </tr>
    </thead>
    <tbody>
      $($tableRows -join "`n      ")
    </tbody>
  </table>
</div>
<footer>CIS Benchmark Audit - $(HtmlEncode $hostname) - $(HtmlEncode $reportDate)</footer>
</body>
</html>
"@

$html | Out-File -FilePath $outFile -Encoding UTF8

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ("PASS: {0}  FAIL: {1}  WARN: {2}  INFO: {3}" -f $totalPass, $totalFail, $totalWarn, $totalInfo) -ForegroundColor $(if ($totalFail -eq 0) { "Green" } else { "Yellow" })
Write-Host "Pass rate: $passPct%"
Write-Host "Report: $outFile" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
