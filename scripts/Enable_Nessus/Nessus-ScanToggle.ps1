<#
.SYNOPSIS
    Toggles a Windows endpoint into and out of "Nessus scan ready" mode.

.DESCRIPTION
    Provides a simple CLI-style interface:

    -m, -Mode       Enable | Disable
    -s, -ScannerIPs Comma-separated list of scanner IPs (optional)
    -v, -Verbose    Verbose output
    -h, -Help       Show help/usage and exit

    ENABLE mode:
        * Enables firewall rules commonly required for authenticated Nessus scans:
          - File and Printer Sharing
          - Windows Management Instrumentation (WMI)
          - Remote Event Log Management
          - Remote Service Management (where present)
        * Enables and starts the RemoteRegistry service.
        * Sets LocalAccountTokenFilterPolicy = 1 to allow local admin over the network.
        * If ScannerIPs are supplied, creates temporary inbound rules for those IPs
          under the firewall group "Nessus Scanner Access".

    DISABLE mode:
        * Disables the above firewall groups again.
        * Stops and disables the RemoteRegistry service.
        * Removes LocalAccountTokenFilterPolicy override.
        * If ScannerIPs (or any were previously created), removes rules in the
          "Nessus Scanner Access" firewall group.

.EXAMPLE
    .\Nessus-ScanToggle.ps1 -m Enable

.EXAMPLE
    .\Nessus-ScanToggle.ps1 -m Enable -s 10.0.0.10,10.0.0.11 -v

.EXAMPLE
    .\Nessus-ScanToggle.ps1 -m Disable -s 10.0.0.10,10.0.0.11
#>

[CmdletBinding()]
param(
    [Alias("m")]
    [ValidateSet("Enable", "Disable")]
    [string]$Mode,

    [Alias("s")]
    [string[]]$ScannerIPs,

    [Alias("v")]
    [switch]$Verbose,

    [Alias("h")]
    [switch]$Help
)

# -----------------------------
# Usage / Help
# -----------------------------
function Show-Usage {
    Write-Host "Nessus-ScanToggle.ps1" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Usage:" -ForegroundColor Yellow
    Write-Host "  .\Nessus-ScanToggle.ps1 -m <Enable|Disable> [-s <ip1,ip2,...>] [-v] [-h]"
    Write-Host ""
    Write-Host "Options:"
    Write-Host "  -m, -Mode        Mode of operation: Enable or Disable"
    Write-Host "  -s, -ScannerIPs  Comma-separated list of Nessus scanner IPs (optional)"
    Write-Host "  -v, -Verbose     Enable verbose output"
    Write-Host "  -h, -Help        Show this help message and exit"
    Write-Host ""
    Write-Host "Examples:"
    Write-Host "  .\Nessus-ScanToggle.ps1 -m Enable"
    Write-Host "  .\Nessus-ScanToggle.ps1 -m Enable -s 10.0.0.10,10.0.0.11 -v"
    Write-Host "  .\Nessus-ScanToggle.ps1 -m Disable -s 10.0.0.10,10.0.0.11"
}

if ($Help -or -not $Mode) {
    Show-Usage
    if (-not $Help -and -not $Mode) {
        # Missing mode but no -h: show usage then exit with non-zero
        exit 1
    }
    exit 0
}

# Enable Write-Verbose output if -v specified
if ($Verbose) {
    $VerbosePreference = "Continue"
}

function Test-IsAdmin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal   = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

if (-not (Test-IsAdmin)) {
    Write-Error "This script must be run as Administrator. Please re-run in an elevated PowerShell session."
    exit 1
}

Write-Host "=== Nessus Scan Toggle ===" -ForegroundColor Cyan
Write-Host "Mode: $Mode" -ForegroundColor Cyan
if ($ScannerIPs) {
    Write-Host "Scanner IPs: $($ScannerIPs -join ', ')" -ForegroundColor Cyan
}
Write-Host ""

# -----------------------------
# Helper: Firewall group toggle
# -----------------------------
function Set-FirewallGroupState {
    param(
        [Parameter(Mandatory = $true)][string]$DisplayGroup,
        [Parameter(Mandatory = $true)][bool]$Enable
    )

    try {
        $rules = Get-NetFirewallRule -DisplayGroup $DisplayGroup -ErrorAction Stop
    } catch {
        Write-Verbose "Firewall display group '$DisplayGroup' not found. Skipping."
        Write-Host "[!] Firewall display group '$DisplayGroup' not found on this system. Skipping." -ForegroundColor Yellow
        return
    }

    if ($rules) {
        $state = if ($Enable) { "Enabled" } else { "Disabled" }
        Write-Verbose "Setting firewall group '$DisplayGroup' -> $state"
        Write-Host "[+] Setting firewall group '$DisplayGroup' -> $state"
        $enabledValue = if ($Enable) { "True" } else { "False" }
        $rules | Set-NetFirewallRule -Enabled $enabledValue -ErrorAction SilentlyContinue
    }
}

# -----------------------------
# 1. Firewall configuration
# -----------------------------
$enableFirewall = ($Mode -eq "Enable")

$firewallGroups = @(
    "File and Printer Sharing",
    "Windows Management Instrumentation (WMI)",
    "Remote Event Log Management",
    "Remote Service Management"
)

Write-Host "=== Firewall Rules (Built-in Groups) ===" -ForegroundColor Cyan
foreach ($group in $firewallGroups) {
    Set-FirewallGroupState -DisplayGroup $group -Enable $enableFirewall
}
Write-Host ""

# -----------------------------
# 1b. Scanner IP specific rules
# -----------------------------
$scannerRuleGroupName = "Nessus Scanner Access"

Write-Host "=== Scanner IP Firewall Rules ===" -ForegroundColor Cyan

if ($Mode -eq "Enable" -and $ScannerIPs) {
    $ports = "135,139,445,5985,5986"
    foreach ($ip in $ScannerIPs) {
        Write-Host "[+] Creating inbound allow rule for scanner $ip on ports $ports"
        Write-Verbose "New-NetFirewallRule for $ip ports $ports in group '$scannerRuleGroupName'"

        try {
            New-NetFirewallRule `
                -DisplayName "Nessus Scanner ($ip)" `
                -Group $scannerRuleGroupName `
                -Direction Inbound `
                -Action Allow `
                -RemoteAddress $ip `
                -Protocol TCP `
                -LocalPort $ports `
                -Profile Any `
                -ErrorAction SilentlyContinue | Out-Null
        } catch {
            Write-Host "[!] Failed to create firewall rule for scanner $ip: $_" -ForegroundColor Yellow
        }
    }
}
elseif ($Mode -eq "Disable") {
    Write-Host "[+] Removing any firewall rules in group '$scannerRuleGroupName' (if present)."
    try {
        $existingRules = Get-NetFirewallRule -Group $scannerRuleGroupName -ErrorAction SilentlyContinue
        if ($existingRules) {
            $existingRules | Remove-NetFirewallRule -ErrorAction SilentlyContinue
        } else {
            Write-Verbose "No rules found in group '$scannerRuleGroupName'."
        }
    } catch {
        Write-Host "[!] Error removing scanner firewall rules: $_" -ForegroundColor Yellow
    }
}
Write-Host ""

# -----------------------------
# 2. RemoteRegistry service
# -----------------------------
Write-Host "=== RemoteRegistry Service ===" -ForegroundColor Cyan
try {
    $svc = Get-Service -Name "RemoteRegistry" -ErrorAction Stop
} catch {
    Write-Host "[!] RemoteRegistry service not found on this system. Skipping." -ForegroundColor Yellow
    $svc = $null
}

if ($svc) {
    if ($Mode -eq "Enable") {
        Write-Host "[+] Setting RemoteRegistry startup type to 'Automatic' and starting service."
        Write-Verbose "Set-Service RemoteRegistry -StartupType Automatic; Start-Service RemoteRegistry"
        Set-Service -Name "RemoteRegistry" -StartupType Automatic -ErrorAction SilentlyContinue
        if ($svc.Status -ne "Running") {
            Start-Service -Name "RemoteRegistry" -ErrorAction SilentlyContinue
        }
    }
    elseif ($Mode -eq "Disable") {
        Write-Host "[+] Stopping RemoteRegistry and setting startup type to 'Disabled'."
        Write-Verbose "Stop-Service RemoteRegistry -Force; Set-Service -StartupType Disabled"
        if ($svc.Status -eq "Running") {
            Stop-Service -Name "RemoteRegistry" -Force -ErrorAction SilentlyContinue
        }
        Set-Service -Name "RemoteRegistry" -StartupType Disabled -ErrorAction SilentlyContinue
    }
}
Write-Host ""

# -----------------------------
# 3. LocalAccountTokenFilterPolicy
# -----------------------------
Write-Host "=== LocalAccountTokenFilterPolicy ===" -ForegroundColor Cyan
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$regName = "LocalAccountTokenFilterPolicy"

if ($Mode -eq "Enable") {
    Write-Host "[+] Setting $regName = 1 (enable local admin over network for UAC)."
    Write-Verbose "New-Item $regPath; New-ItemProperty $regName=1"
    New-Item -Path $regPath -Force | Out-Null
    New-ItemProperty -Path $regPath -Name $regName -Value 1 -PropertyType DWord -Force | Out-Null
} else {
    Write-Host "[+] Removing $regName override (if present)."
    Write-Verbose "Remove-ItemProperty $regName"
    Remove-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue
}
Write-Host ""

Write-Host "=== Completed Nessus-ScanToggle in '$Mode' mode. ===" -ForegroundColor Green
