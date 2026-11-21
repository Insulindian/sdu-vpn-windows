# Install SDU VPN for the current Windows user:
#   * the zju-connect data plane (upstream release, not kept in this repo)
#   * Python dependencies (requests / playwright / pywebview)
#   * the Chromium build that Playwright drives for the CAS login page
#   * a Start Menu entry and a desktop shortcut for windows\SDU VPN.exe
#
# Run from anywhere:  powershell -ExecutionPolicy Bypass -File windows\install.ps1
$ErrorActionPreference = "Stop"

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Split-Path -Parent $here
$exe = Join-Path $here "SDU VPN.exe"

Write-Host "SDU VPN install: $root"

# 1. Python -----------------------------------------------------------------
$python = (Get-Command python -ErrorAction SilentlyContinue)
if (-not $python) {
    throw "Python 3.11+ is required and 'python' is not on PATH."
}
$version = & python -c "import sys; print('%d.%d' % sys.version_info[:2])"
if ([version]::Parse($version) -lt [version]"3.11") {
    throw "Python 3.11+ is required, found $version."
}
Write-Host "Python $version"

# 2. Data plane --------------------------------------------------------------
# zju-connect is AGPL-3.0 and is not redistributed in this repository; take the
# upstream release and verify it before it is ever started.
$bin = Join-Path $root "client\bin"
$plane = Join-Path $bin "zju-connect.exe"
if (-not (Test-Path $plane)) {
    $url = "https://github.com/Mythologyli/zju-connect/releases/download/v1.3.1/zju-connect-windows-amd64.zip"
    $sha = "AEE7D8DBBF4DB98FBFF2B36D657094D95F3F6209DC3168914C62AEA01A8732BE"
    $zip = Join-Path $env:TEMP "zju-connect-windows-amd64.zip"

    Write-Host "Downloading zju-connect v1.3.1 (upstream release)..."
    New-Item -ItemType Directory -Force -Path $bin | Out-Null
    Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing
    Expand-Archive -Path $zip -DestinationPath $bin -Force
    Remove-Item $zip -Force

    $actual = (Get-FileHash $plane -Algorithm SHA256).Hash
    if ($actual -ne $sha) {
        Remove-Item $plane -Force
        throw "zju-connect.exe checksum mismatch: $actual"
    }
    Write-Host "zju-connect: $plane"
}
else {
    Write-Host "zju-connect: $plane (already present)"
}

# 3. Dependencies -----------------------------------------------------------
& python -m pip install --upgrade -r (Join-Path $here "requirements.txt")
if ($LASTEXITCODE -ne 0) { throw "pip install failed" }

& python -m playwright install chromium
if ($LASTEXITCODE -ne 0) { throw "playwright install failed" }

# 4. Shortcuts --------------------------------------------------------------
$shell = New-Object -ComObject WScript.Shell
$startMenu = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\SDU VPN"
New-Item -ItemType Directory -Force -Path $startMenu | Out-Null

foreach ($target in @(
    (Join-Path $startMenu "SDU VPN.lnk"),
    (Join-Path ([Environment]::GetFolderPath("Desktop")) "SDU VPN.lnk")
)) {
    $shortcut = $shell.CreateShortcut($target)
    $shortcut.TargetPath = $exe
    $shortcut.WorkingDirectory = $here
    $shortcut.IconLocation = "$exe,0"
    $shortcut.Description = "SDU VPN"
    $shortcut.Save()
    Write-Host "Shortcut: $target"
}

Write-Host ""
Write-Host "Done. Start it from the Start Menu (SDU VPN) or run windows\start.bat."
Write-Host "The first proxy connection opens the university CAS page in Chromium."
