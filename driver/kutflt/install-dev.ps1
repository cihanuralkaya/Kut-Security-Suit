# install-dev.ps1 - Install/uninstall the test-signed kutflt driver.
# Run ELEVATED on a dedicated TEST machine/VM with testsigning ON.
# See README.md for BSOD risk and safe-mode recovery. NEVER run on production.
param([ValidateSet('install','uninstall')][string]$Action = 'install')
$ErrorActionPreference = 'Stop'
$sys = Join-Path $PSScriptRoot 'x64\Release\kutflt.sys'
$dst = Join-Path $env:SystemRoot 'System32\drivers\kutflt.sys'

if ($Action -eq 'install') {
    Copy-Item $sys $dst -Force
    # Minifilter service: type=filesys, FltMgr dependency + altitude.
    sc.exe create kutflt type= filesys start= demand binPath= $dst `
        group= "FSFilter Activity Monitor" depend= FltMgr
    $key = "HKLM\SYSTEM\CurrentControlSet\Services\kutflt\Instances"
    reg add $key /v DefaultInstance /t REG_SZ /d "KutFlt Instance" /f
    reg add "$key\KutFlt Instance" /v Altitude /t REG_SZ /d "385200" /f
    reg add "$key\KutFlt Instance" /v Flags /t REG_DWORD /d 0 /f
    fltmc load kutflt
    Write-Host "Loaded. Verify with: fltmc filters"
    Write-Host "The Go agent's tamperprotect.KernelDriverProbe() now returns (true,'kutflt')."
} else {
    fltmc unload kutflt 2>$null
    sc.exe delete kutflt
    Remove-Item $dst -Force -ErrorAction SilentlyContinue
    Write-Host "Uninstalled."
}
