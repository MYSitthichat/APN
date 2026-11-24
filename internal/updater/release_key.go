package updater

// releasePublicKey is the APN release-signing public key (Ed25519, base64). Its private half is
// kept offline by the maintainer (default %USERPROFILE%\.apn-release\update-signing.key) and is
// used by scripts/publish-update.ps1 through scripts/signupdate.
const releasePublicKey = "0bT6/PTssEGPlL5tGlTWwG67557unG+JlUu06it4Csk="
