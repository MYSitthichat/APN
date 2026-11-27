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
$jsonText = $manifest | ConvertTo-Json -Depth 5
[System.IO.File]::WriteAllText($outPath, $jsonText, (New-Object System.Text.UTF8Encoding($false)))
Write-Host "Generated $outPath for APN v$ver ($($assets.Count) platform assets)."
Write-Host "Upload the binaries in dist/ and latest.json to $base/ (the GitHub release). The rendezvous server reads latest.json from the latest release itself, so nothing else needs uploading."

# Sign every platform asset with the offline release key (Ed25519) and verify against the key
# compiled into APN. Clients v1.3.14+ refuse unsigned or wrongly signed updates.
# Key: $env:APN_UPDATE_KEY or %USERPROFILE%\.apn-release\update-signing.key (never commit it).
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
Push-Location $repoRoot
try {
    go run ./scripts/signupdate -sign $outPath
    if ($LASTEXITCODE -ne 0) { throw 'Signing latest.json failed (release key missing?)' }
    go run ./scripts/signupdate -verify $outPath
    if ($LASTEXITCODE -ne 0) { throw 'latest.json signature verification failed' }
} finally {
    Pop-Location
}
