#!/usr/bin/env bash
set -euo pipefail

# Builds native iOS (.xcframework) and Android (.aar) libraries from pkg/mobile using gomobile.
# Requirements:
#   go install golang.org/x/mobile/cmd/gomobile@latest
#   gomobile init
#   - iOS build requires macOS with Xcode installed
#   - Android build requires Android NDK installed

VER=$(grep -E 'Version\s*=' internal/version/version.go | sed -E 's/.*"([^"]+)".*/\1/')
mkdir -p dist

if [[ "$(uname -s)" == "Darwin" ]]; then
  echo "Building iOS XCFramework (RelayVPNCore-v${VER}-ios.xcframework)..."
  gomobile bind -target=ios -o "dist/RelayVPNCore-v${VER}-ios.xcframework" ./pkg/mobile
else
  echo "Skipping iOS .xcframework build (requires macOS + Xcode)."
fi

if [[ -n "${ANDROID_NDK_HOME:-}" || -n "${ANDROID_HOME:-}" ]]; then
  echo "Building Android AAR (RelayVPNCore-v${VER}-android.aar)..."
  gomobile bind -target=android -androidapi 24 -o "dist/RelayVPNCore-v${VER}-android.aar" ./pkg/mobile
else
  echo "Skipping Android .aar build (set ANDROID_HOME / ANDROID_NDK_HOME to enable)."
fi
