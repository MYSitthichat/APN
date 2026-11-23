param(
    [Parameter(Mandatory = $true)]
    [string]$Version,
    [Parameter(Mandatory = $true)]
    [string]$Notes
)

$ErrorActionPreference = 'Stop'
$ver = $Version.TrimStart('v')
$tag = "v$ver"

# 1. Update internal/version/version.go
$verFile = Join-Path $PSScriptRoot '..\internal\version\version.go'
$content = Get-Content -Path $verFile -Raw
$updated = $content -replace 'const Version = "[^"]+"', "const Version = `"$ver`""
Set-Content -Path $verFile -Value $updated -NoNewline -Encoding UTF8

# 2. Verify code & run tests
go vet ./...
if ($LASTEXITCODE -ne 0) { throw 'go vet failed' }
go test -v ./...
if ($LASTEXITCODE -ne 0) { throw 'go test failed' }

# 3. Rebuild local dist binaries
& (Join-Path $PSScriptRoot 'build-all.ps1') -RendezvousURL 'https://rdv.psms-center.com'

# 4. Commit, tag with release notes, and push to GitHub (triggers GitHub Actions Release + Auto-Update!)
git add -A
git commit -m "Release $tag" -m $Notes
git tag -a $tag -m $Notes
git push origin main --tags

Write-Host "`nPublished $tag to GitHub! GitHub Actions is building all 7 binaries and updating APN Auto-Updater."
