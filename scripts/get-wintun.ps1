$ErrorActionPreference = 'Stop'

# Downloads official signed Wintun DLL (wintun.net) for Windows L3 VPN (amd64 + arm64) into dist/
$wintunVer = '0.14.1'
$zipUrl = "https://www.wintun.net/builds/wintun-$wintunVer.zip"
$tmpDir = Join-Path $env:TEMP "wintun-$wintunVer"
$zipPath = Join-Path $env:TEMP "wintun-$wintunVer.zip"
$distDir = Join-Path $PSScriptRoot '..\dist'

New-Item -ItemType Directory -Force -Path $distDir | Out-Null
Write-Host "Downloading official Wintun $wintunVer from $zipUrl ..."
Invoke-WebRequest -Uri $zipUrl -OutFile $zipPath -UseBasicParsing

if (Test-Path $tmpDir) { Remove-Item -Recurse -Force $tmpDir }
Expand-Archive -Path $zipPath -DestinationPath $tmpDir -Force

Copy-Item (Join-Path $tmpDir 'wintun\bin\amd64\wintun.dll') (Join-Path $distDir 'wintun.dll') -Force
Copy-Item (Join-Path $tmpDir 'wintun\bin\arm64\wintun.dll') (Join-Path $distDir 'wintun-arm64.dll') -Force

Remove-Item -Recurse -Force $tmpDir, $zipPath
Write-Host "Installed wintun.dll (amd64) and wintun-arm64.dll into $distDir!"
Write-Host "Run RelayVPN as Administrator and toggle 'Built-in L3 VPN' on the Dashboard."
