<#
.SYNOPSIS
    Keeps a laptop awake by briefly toggling NumLock on and off.

.DESCRIPTION
    Uses SendKeys to toggle NumLock twice (on then off, or vice versa)
    every N seconds so that:
      - Windows sees keyboard activity
      - NumLock ends each cycle in its original state

.PARAMETER IntervalSeconds
    How often to perform the wiggle (default: 120 seconds).

.EXAMPLE
    .\Keep-Awake.ps1

.EXAMPLE
    .\Keep-Awake.ps1 -IntervalSeconds 120
#>

[CmdletBinding()]
param(
    [int]$IntervalSeconds = 120
)

Add-Type -AssemblyName System.Windows.Forms

$initialNumLock = [console]::NumberLock
Write-Host "=== Keep-Awake (NumLock) ===" -ForegroundColor Cyan
Write-Host "Initial NumLock state: $initialNumLock" -ForegroundColor Cyan
Write-Host "Interval: $IntervalSeconds seconds" -ForegroundColor Cyan
Write-Host "Press Ctrl + C to stop." -ForegroundColor Yellow
Write-Host ""

try {
    while ($true) {
        # Quick toggle ON/OFF (or OFF/ON) so NumLock ends in the same state
        [System.Windows.Forms.SendKeys]::SendWait('{NUMLOCK}')
        Start-Sleep -Milliseconds 500
        [System.Windows.Forms.SendKeys]::SendWait('{NUMLOCK}')

        Start-Sleep -Seconds $IntervalSeconds
    }
}
finally {
    # Try to restore original NumLock state, just in case
    if ([console]::NumberLock -ne $initialNumLock) {
        [System.Windows.Forms.SendKeys]::SendWait('{NUMLOCK}')
    }
    Write-Host "`n[+] Keep-Awake stopped. NumLock restored." -ForegroundColor Green
}