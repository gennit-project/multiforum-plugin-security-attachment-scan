# Security: Attachment Scan Plugin

The **Security: Attachment Scan** plugin protects downloadable uploads by
talking to the [VirusTotal API](https://www.virustotal.com/). When enabled at
the server scope it inspects zip files (and any other downloadable attachments)
as soon as they are uploaded and again right before a visitor downloads the
bundle.

## How It Works

1. A creator uploads a downloadable file to a channel.
2. Multiforum emits either `downloadableFile.created` or
   `downloadableFile.updated`.
3. The plugin posts the file URL to VirusTotal and stores the scan result by
   calling `ctx.storeFlag()`.
4. The pipeline UI surfaces a pass/fail badge for moderators and creators.
5. The public sees a confirmation that the virus scan ran before the download
   link is released.

The plugin also re-runs the scan when someone requests the download to guard
against newly-detected threats.

## Required Secrets

| Key                    | Scope  | Description                                                 |
| ---------------------- | ------ | ----------------------------------------------------------- |
| `VIRUS_TOTAL_API_KEY`  | Server | API key used to authenticate with the VirusTotal REST API.  |

The manifest ships UI metadata so administrators can save the key directly
inside Multiforum.

## Settings Form

The manifest exports a config schema with two sections:

- A **Secrets** section that renders a password input for the VirusTotal API
  key with validation hints.
- A **Settings** section where administrators can tweak the scan timeout and
  control whether downloads should be quarantined automatically if VirusTotal
  flags a threat.

See `plugin.json` for the full schema and default values.


## Standalone Plugin Package

This repository is the source of truth for `security-attachment-scan`. Plugin releases are versioned with Git tags in the form `v<plugin.json version>`.

### Development

```bash
npm install
npm run ci
```

`npm run ci` validates `plugin.json`, runs Vitest, builds TypeScript, and creates a release bundle under `out/`.

### Release

1. Update `plugin.json` and `package.json` to the same version.
2. Commit the change.
3. Tag the commit with `v<version>`.
4. Push the tag.

The `Publish Release` workflow builds `security-attachment-scan-<version>.tgz`, writes a SHA-256 checksum, and uploads both artifacts to the GitHub Release.

### Registry Metadata

Use this source URL in the Multiforum plugin registry:

```json
{
  "sourceRepoUrl": "https://github.com/gennit-project/multiforum-plugin-security-attachment-scan",
  "releaseNotesUrl": "https://github.com/gennit-project/multiforum-plugin-security-attachment-scan/releases/tag/v0.2.1"
}
```
