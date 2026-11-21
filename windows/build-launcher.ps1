# Rebuild windows\SDU VPN.exe from launcher.cs.
# Uses the C# compiler that ships with .NET Framework (present on Windows 10/11).
$ErrorActionPreference = "Stop"

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$csc = Join-Path $env:WINDIR "Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if (-not (Test-Path $csc)) {
    throw "csc.exe not found: $csc"
}

& $csc /nologo /target:winexe `
    "/out:$here\SDU VPN.exe" `
    "/win32icon:$here\sdu-vpn.ico" `
    "/reference:System.Windows.Forms.dll" `
    "$here\launcher.cs"

if ($LASTEXITCODE -ne 0) { throw "csc.exe failed with exit code $LASTEXITCODE" }
Write-Host "Built: $here\SDU VPN.exe"
