param(
    [string]$BaseDownloadURL = "",
    [string]$ReleaseNotes = "APN automatic update release"
)

$ErrorActionPreference = 'Stop'

$verFile = Join-Path $PSScriptRoot '..\internal\version\version.go'
$verMatch = Select-String -Path $verFile -Pattern 'Version\s*=\s*"([^"]+)"'
$ver = if ($verMatch) { $verMatch.Matches[0].Groups[1].Value } else { throw 'Could not read version' }

if ($BaseDownloadURL -eq "") {
    $BaseDownloadURL = "https://github.com/MYSitthichat/APN/releases/download/v$ver"
}

$distDir = Join-Path $PSScriptRoot '..\dist'
$base = $BaseDownloadURL.TrimEnd('/')

$map = [ordered]@{
    'windows-amd64' = "APN-v$ver-windows-amd64.exe"
    'windows-arm64' = "APN-v$ver-windows-arm64.exe"
    'linux-amd64'   = "APN-v$ver-linux-amd64"
    'linux-arm64'   = "APN-v$ver-linux-arm64"
    'linux-armv7'   = "APN-v$ver-linux-armv7"
    'darwin-arm64'  = "APN-v$ver-macos-arm64"
    'darwin-amd64'  = "APN-v$ver-macos-amd64"
}

$assets = [ordered]@{}
foreach ($k in $map.Keys) {
    $file = Join-Path $distDir $map[$k]
    if (Test-Path $file) {
        $hash = (Get-FileHash -Path $file -Algorithm SHA256).Hash.ToLowerInvariant()
        $assets[$k] = [ordered]@{
            url    = "$base/$($map[$k])"
            sha256 = $hash
        }
    }
}

$manifest = [ordered]@{
    version       = $ver
    release_notes = $ReleaseNotes
    assets        = $assets
}

$outPath = Join-Path $distDir 'latest.json'
$manifest | ConvertTo-Json -Depth 5 | Set-Content -Path $outPath -Encoding UTF8
Write-Host "Generated $outPath for APN v$ver ($($assets.Count) platform assets)."
Write-Host "Upload the binaries in dist/ to $base/ and save latest.json into Cloudflare KV key 'release:latest' (Namespace RELAYVPN_PEERS)!"
