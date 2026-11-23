param(
    [string]$RendezvousURL = ""
)

$ErrorActionPreference = 'Stop'

# Extract semantic version from internal/version/version.go
$verFile = Join-Path $PSScriptRoot '..\internal\version\version.go'
$verMatch = Select-String -Path $verFile -Pattern 'Version\s*=\s*"([^"]+)"'
$ver = if ($verMatch) { $verMatch.Matches[0].Groups[1].Value } else { '0.9.1' }

$ldflags = "-s -w"
if ($RendezvousURL -ne "") {
    $ldflags += " -X relayvpn/internal/config.DefaultRendezvousURL=$RendezvousURL"
    Write-Host "Embedding default Rendezvous URL: $RendezvousURL"
}

$targets = @(
    @{ Label = "APN-v$ver-windows-amd64.exe"; GOOS = 'windows'; GOARCH = 'amd64'; GOARM = ''  },
    @{ Label = "APN-v$ver-windows-arm64.exe"; GOOS = 'windows'; GOARCH = 'arm64'; GOARM = ''  },
    @{ Label = "APN-v$ver-linux-amd64";       GOOS = 'linux';   GOARCH = 'amd64'; GOARM = ''  },
    @{ Label = "APN-v$ver-linux-arm64";       GOOS = 'linux';   GOARCH = 'arm64'; GOARM = ''  },
    @{ Label = "APN-v$ver-linux-armv7";       GOOS = 'linux';   GOARCH = 'arm';   GOARM = '7' },
    @{ Label = "APN-v$ver-macos-arm64";       GOOS = 'darwin';  GOARCH = 'arm64'; GOARM = ''  },
    @{ Label = "APN-v$ver-macos-amd64";       GOOS = 'darwin';  GOARCH = 'amd64'; GOARM = ''  }
)

$outDir = Join-Path $PSScriptRoot '..\dist'
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

# Remove older unnamed/previous-version binaries from dist/ (skip any currently-running exe cleanly)
Get-ChildItem -Path $outDir -File -Filter 'relayvpn-*' -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
Get-ChildItem -Path $outDir -File -Filter 'RelayVPN-v*' -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
Get-ChildItem -Path $outDir -File -Filter 'APN-v*' -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue

foreach ($t in $targets) {
    $env:CGO_ENABLED = '0'
    $env:GOOS = $t.GOOS
    $env:GOARCH = $t.GOARCH
    if ($t.GOARM -ne '') {
        $env:GOARM = $t.GOARM
    } else {
        Remove-Item Env:GOARM -ErrorAction SilentlyContinue
    }
    $targetFlags = $ldflags
    if ($t.GOOS -eq 'windows') {
        # Pure Windows GUI subsystem: zero CMD / Windows Terminal window on Windows 10 & 11!
        $targetFlags = "-H=windowsgui " + $targetFlags
    }
    $dest = Join-Path $outDir $t.Label
    Write-Host "Building $($t.Label) ..."
    go build -trimpath -ldflags="$targetFlags" -o $dest ./cmd/relayvpn
    if ($LASTEXITCODE -ne 0) { throw "Build failed for $($t.Label)" }
}

Remove-Item Env:GOOS, Env:GOARCH, Env:GOARM, Env:CGO_ENABLED -ErrorAction SilentlyContinue

# Also generate double-clickable Ubuntu/Debian .deb installer packages (amd64, arm64, armhf)
$iconPng = Join-Path $PSScriptRoot '..\internal\webui\static\logo.png'
$debTargets = @(
    @{ Bin = "APN-v$ver-linux-amd64"; Arch = 'amd64'; Out = "APN-v$ver-linux-amd64.deb" },
    @{ Bin = "APN-v$ver-linux-arm64"; Arch = 'arm64'; Out = "APN-v$ver-linux-arm64.deb" },
    @{ Bin = "APN-v$ver-linux-armv7"; Arch = 'armhf'; Out = "APN-v$ver-linux-armv7.deb" }
)
foreach ($d in $debTargets) {
    $binFull = Join-Path $outDir $d.Bin
    $debFull = Join-Path $outDir $d.Out
    if (Test-Path $binFull) {
        go run ./scripts/mkdeb -bin $binFull -icon $iconPng -version $ver -arch $d.Arch -out $debFull
        if ($LASTEXITCODE -ne 0) { throw "DEB build failed for $($d.Out)" }
    }
}

Write-Host "`nAll 7 cross-platform binaries + 3 Ubuntu/Debian .deb installers built successfully in $outDir!"
Write-Host "Note: For iOS & Android native VPN bindings (.xcframework / .aar), see scripts/build-mobile.sh"
Write-Host "      or open the built-in PWA on iPhone/iPad/Android via Safari/Chrome -> Add to Home Screen."
