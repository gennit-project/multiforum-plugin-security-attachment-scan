# Security: Attachment Scan Plugin

The **Security: Attachment Scan** plugin protects downloadable uploads. When
enabled at the server scope it inspects attachments as soon as they are uploaded
(and again right before a visitor downloads the bundle) by calling the
[Multiforum security-scan service](https://github.com/gennit-project/multiforum-plugin-security-scan-service) —
a standalone Python/FastAPI microservice.

> **Why a separate service?** Multiforum plugins run in-process inside the Node
> backend, so heavy or risky file handling (downloading untrusted uploads,
> unpacking ZIPs) is better kept out of that process. The service runs the
> VirusTotal reputation lookup **and** static ZIP analysis (dangerous file
> types, zip-bomb ratio, path-traversal entries, README/LICENSE checks) and
> returns a single verdict. The VirusTotal API key lives on the service, not in
> the forum backend.

## How It Works

1. A creator uploads a downloadable file to a channel.
2. Multiforum emits `downloadableFile.created` / `.updated` / `.downloaded`.
3. For each attachment URL, the plugin `POST`s to the service's `/scan` endpoint
   with the `X-API-Key` header.
4. The service returns a verdict — `clean`, `suspicious`, `malicious`, or
   `error`.
5. The upload is blocked if any attachment is a **blocking** result:
   - a finding at or above the `blockOn` threshold (`suspicious` or
     `malicious`), or
   - a scan `error`, when `onError` is `block` (the default — see below).
   Blocking makes the plugin return `success: false`, which fails the pipeline
   step. Any non-clean verdict is also recorded via `ctx.storeFlag()` so
   moderators see it.

> **On scan errors (fail closed vs open).** A scan `error` — a service failure,
> an unreachable service, or an unreadable file — is an operational state, *not*
> a point on the malice scale, so it is governed by its own `onError` toggle
> rather than by `blockOn`. The default is `block` (fail closed): if we can't
> determine a file is safe, we don't let it through — which also means an
> attacker can't bypass the scan by deliberately making it error. Set
> `onError: allow` only if availability matters more than safety for your server.

## Configuration

### Secret

| Key                    | Scope  | Description                                                            |
| ---------------------- | ------ | ---------------------------------------------------------------------- |
| `SCAN_SERVICE_API_KEY` | Server | Shared secret sent as `X-API-Key`; must match the service's `SCAN_API_KEY`. |

### Settings

| Key                      | Scope   | Default      | Description                                                        |
| ------------------------ | ------- | ------------ | ----------------------------------------------------------------- |
| `serviceUrl`             | Server  | —            | Base URL of the deployed Cloud Run scan service.                  |
| `blockOn`                | Server  | `malicious`  | Malice threshold that blocks the upload: `suspicious` or `malicious`. |
| `onError`                | Server  | `block`      | What to do when the scan can't complete: `block` (fail closed) or `allow` (fail open). |
| `policy.require_readme`  | Channel | `false`      | Require a `README` at the ZIP root.                               |
| `policy.require_license` | Channel | `false`      | Require a `LICENSE` at the ZIP root.                              |

The manifest ships UI metadata so administrators can configure all of this
directly inside Multiforum. See `plugin.json` for the full schema.

## Standalone Plugin Package

This repository is the source of truth for `security-attachment-scan`. Plugin
releases are versioned with Git tags in the form `v<plugin.json version>`.

### Development

```bash
npm install
npm run ci
```

`npm run ci` validates `plugin.json`, runs Vitest, builds TypeScript, and
creates a release bundle under `out/`.

### Release

1. Update `plugin.json` and `package.json` to the same version.
2. Commit the change.
3. Tag the commit with `v<version>`.
4. Push the tag.

The `Publish Release` workflow builds `security-attachment-scan-<version>.tgz`,
writes a SHA-256 checksum, and uploads both artifacts (plus `plugin.json`) to the
GitHub Release.

### Registry Metadata

Use this source URL in the Multiforum plugin registry:

```json
{
  "sourceRepoUrl": "https://github.com/gennit-project/multiforum-plugin-security-attachment-scan",
  "releaseNotesUrl": "https://github.com/gennit-project/multiforum-plugin-security-attachment-scan/releases/tag/v0.4.0"
}
```
