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

# 3. Rebuild local dist binaries + latest.json + SHA256SUMS.txt
& (Join-Path $PSScriptRoot 'build-all.ps1') -RendezvousURL 'https://rdv.psms-center.com'
& (Join-Path $PSScriptRoot 'publish-update.ps1') -ReleaseNotes $Notes
$dist = Resolve-Path (Join-Path $PSScriptRoot '..\dist')
$sums = Get-ChildItem $dist -File -Filter "APN-v$ver-*" | ForEach-Object { "$((Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant())  $($_.Name)" }
$sums | Set-Content -Path (Join-Path $dist 'SHA256SUMS.txt') -Encoding ASCII

# 4. Commit, tag with release notes, and push to GitHub + publish Release immediately via gh!
git add -A
git commit -m "Release $tag" -m $Notes
git tag -a $tag -m $Notes
git push origin main --tags

if (Get-Command gh -ErrorAction SilentlyContinue) {
    $files = @(Get-ChildItem $dist -File -Filter "APN-v$ver-*" | ForEach-Object { $_.FullName }) + (Join-Path $dist 'SHA256SUMS.txt') + (Join-Path $dist 'latest.json')
    gh release create $tag --title "APN $tag" --notes-from-tag @files
}

Write-Host "`nPublished $tag to GitHub! Every APN client can now 1-click auto-update."
