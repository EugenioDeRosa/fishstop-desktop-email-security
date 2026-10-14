# Production desktop updates

Only `main` publishes production installers. A manual workflow invocation on any
other branch is skipped. Development changes stay on `dev` until release approval.

The release workflow requires the same stable numeric version in `package.json`,
both root entries in `package-lock.json`, `src-tauri/Cargo.toml`, and
`src-tauri/tauri.conf.json`. After the first public release, the version must be
strictly greater than the latest published updater manifest. Increase these
versions together before releasing; publishing changed code with the same version
does not deliver an update to existing installations.

Configure the repository secret `TAURI_SIGNING_PRIVATE_KEY` with the **contents**
of the existing private updater key, not a path on the developer's computer.
Set `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` if the key has a password. Keep the private
key and a secure backup outside Git. Do not regenerate it for each release:
installed apps trust the public key bundled in their configuration.

The workflow builds Windows x64, macOS Intel, and macOS Apple Silicon in a draft.
Before publication it checks the updater manifest version, all three platform
entries, release-specific GitHub asset URLs, and the actual Minisign signatures
of all downloaded update packages against the app's public key. Missing assets,
different keys, corrupted packages, or build failures leave the release unpublished.
Only the completed release becomes `latest`; the client reads its `latest.json`.
The production action must therefore have permission to upload release assets.

The app checks automatically while idle and allows a manual check in Settings.
Installation requires the user's confirmation and is blocked during active work.
Tauri verifies the package signature again on the user's device. An installation
failure does not trigger a restart. App data and downloaded models must survive
the installer upgrade; test this on real packaged apps before public distribution.

## Final packaged-app test

1. Confirm the repository signing secret is configured with the existing key.
2. Build and install a signed baseline on Windows, Intel Mac, and Apple Silicon
   Mac. Save a guest analysis, settings, and an installed model.
3. Publish a higher-version release through `main` when publication is authorized.
4. In the baseline installation, check updates, postpone once, then install.
   Verify progress, restart, the new version, preserved guest history/settings,
   and reuse of the previously downloaded model.
5. Check offline behaviour and repeat a manual check after recovery.

Local frontend simulations and cryptographic fixture verification do not replace
this installer test. Updater signatures also do not replace Windows Authenticode
or macOS code signing/notarization.

Reference: https://v2.tauri.app/plugin/updater/
