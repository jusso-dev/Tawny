# Code signing

Status: prepared, not active. No certificate has been bought and no signing
key exists. Justin needs to choose the options below. This page lists them,
what each needs, and how the release workflow uses them.

Code signing and the update manifest do different jobs:

- **Authenticode and Apple notarisation** tell Windows SmartScreen and macOS
  Gatekeeper who published the binary, so people installing Tawny by hand see
  no warning. They cost money and need a vendor's identity checks.
- **The minisign release key** is the trust root for self-update (target-edr
  §10). Agents install only a binary named by a manifest signed with that
  key. It is free, and it stays the trust root whatever is chosen below.

## What the release workflow does

`.github/workflows/release.yml` has three signing jobs. Each one checks for
its secrets through a job-level env flag (secrets can't be used directly in
`if:`) and skips with a log line when they are missing, so a tagged release
still publishes unsigned binaries, `.sha256` sidecars and attestations.

| Job | Runs when these secrets are set | What it does |
| --- | --- | --- |
| `sign-windows` | `WINDOWS_PFX_BASE64`, `WINDOWS_PFX_PASSWORD` (optional variable `WINDOWS_TIMESTAMP_URL`) | `signtool sign /fd sha256 /tr <timestamp> /td sha256`, then `signtool verify /pa`, rewrites the `.sha256` sidecar, replaces the artifact |
| `notarize-macos` | `APPLE_DEVELOPER_ID_P12_BASE64`, `APPLE_DEVELOPER_ID_P12_PASSWORD`, `APPLE_DEVELOPER_ID_IDENTITY`; notarising also needs `APPLE_NOTARY_APPLE_ID`, `APPLE_NOTARY_TEAM_ID`, `APPLE_NOTARY_PASSWORD` | `codesign --options runtime --timestamp` into a throwaway keychain, `xcrun notarytool submit --wait`, rewrites the `.sha256` sidecars |
| `release-manifests` | `MINISIGN_SECRET_KEY` (and `MINISIGN_PASSWORD` if the key has one) in the protected `release-signing` environment | Writes `{version, platform, sha256, size, min_from_version, ring, rollback}` per binary and signs it with `minisign -S` |

The `release` job then attests and publishes everything, including the
signed binaries' final hashes.

The `sign-windows` job takes a PFX file. That fits a certificate whose key
can be exported, which public CAs no longer issue for code signing (see
below). With a hardware token or a cloud signing service the step changes to
that vendor's tool or GitHub Action; the gating stays the same. Change it
once the option is chosen.

A bare Mach-O binary can't be stapled, so macOS checks the notarisation
ticket online on first run. That is normal for command-line tools.

## Windows options

Check current pricing and eligibility on each vendor's own pages before
choosing. Prices and rules change, and none are quoted here.

1. **OV code-signing certificate from a public CA** (for example DigiCert,
   Sectigo, GlobalSign, SSL.com). Since the CA/Browser Forum code-signing
   rules changed in 2023, the private key must be generated and kept on a
   hardware token or in a cloud HSM, so it can't sit in a GitHub secret as a
   PFX. Options are a USB token (signing then needs a machine with the token
   attached, or a self-hosted runner), or the CA's cloud signing service
   (for example DigiCert KeyLocker, SSL.com eSigner), which has a CLI or
   GitHub Action. SmartScreen reputation builds up over time with OV.
   Pages to check: each CA's "code signing certificate" pricing page and its
   cloud signing product page.
2. **EV code-signing certificate.** Same key rules as OV, more identity
   checks, historically faster SmartScreen reputation. Check whether that
   still holds; Microsoft has changed how EV is treated. Pages to check: the
   same CA pages, EV variant.
3. **Microsoft Azure Artifact Signing** (formerly Trusted Signing). A monthly
   subscription where Microsoft holds the key and signs through an Azure
   account; there is an official GitHub Action. It has eligibility rules for
   organisations and individuals, and its availability by country has changed
   since launch. Check that an Australian business (or individual) can enrol
   today. Pages to check: "Artifact Signing" (or "Trusted Signing") on
   learn.microsoft.com, its pricing page on azure.microsoft.com, and the
   Azure account needed for it. Using it creates an Azure resource, which is
   Justin's call.

Things to weigh: whether signing must run on GitHub-hosted runners (rules out
a USB token unless there is a self-hosted runner), who verifies the
business identity, and renewal.

## macOS option

**Apple Developer Program** membership gives a Developer ID Application
certificate and access to the notary service. Membership is a yearly fee in
local currency. Check the current Australian price on Apple's "Apple
Developer Program" enrolment page and "Membership details" page. Enrolling
as an organisation needs a D-U-N-S number; enrolling as an individual puts
Justin's name on the signature.

After enrolment:

1. Create a Developer ID Application certificate, export it as `.p12`, and
   store it base64-encoded in `APPLE_DEVELOPER_ID_P12_BASE64` with its
   password in `APPLE_DEVELOPER_ID_P12_PASSWORD`.
2. Set `APPLE_DEVELOPER_ID_IDENTITY` to the certificate name, for example
   `Developer ID Application: <name> (<team id>)`.
3. Create an app-specific password for the Apple ID and set
   `APPLE_NOTARY_APPLE_ID`, `APPLE_NOTARY_TEAM_ID` and
   `APPLE_NOTARY_PASSWORD`. A notary API key is an alternative; the step
   would change to `--key`, `--key-id`, `--issuer`.

A signed agent also stops the installers' upgrade path from having to export
Keychain items first, because a Developer ID build keeps the same code
identity across versions.

## Release minisign key (free, needed for self-update)

Self-update is off until this exists. The agent compiles in a placeholder
public key and refuses every update while it is there.

1. On a machine you trust, offline if possible: `minisign -G -p tawny-release.pub -s tawny-release.key`.
   Use a password. Keep the secret key and its password out of the
   repository, chat and shared drives.
2. Put the second line of `tawny-release.pub` into `agent/src/update_key.zig`
   as `public_key`, replacing the placeholder, and update the test there.
3. Create the GitHub environment `release-signing` with required reviewers
   (Settings, Environments). Add `MINISIGN_SECRET_KEY` (the whole secret key
   file) and `MINISIGN_PASSWORD` there, not as repository secrets.
4. Tag a release. The manifests are published beside the binaries and new
   releases start in the `canary` ring.

If the secret key leaks: create a new key, ship a release whose
`update_key.zig` holds the new public key through the installers (not
self-update), and remove the old secret from the environment.
