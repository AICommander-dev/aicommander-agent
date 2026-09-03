# AI Commander — agent source

Source for the [`@aicommander/agent`](https://www.npmjs.com/package/@aicommander/agent)
npm package, published from this repository with
[npm provenance attestations](https://docs.npmjs.com/generating-provenance-statements).

## Dual-use disclosure — read this first

**AI Commander's agent is a remote-administration tool.** It is not a library, and it
is not a background utility. Concretely, and by design:

- It opens an **outbound WebSocket** to a relay and **executes shell commands it
  receives over that connection** on the machine it runs on.
- **It can only ever talk to one relay, and that is deliberate.** The agent is
  **host-locked** to `https://aicommander.dev`. An `AICOMMANDER_SERVER` (or
  `--server`) pointing anywhere else is ignored, loudly, and the agent falls back
  to the canonical relay — because it runs as root, so a stray or injected
  environment variable must not be able to re-home it to someone else's server.
  The exceptions are loopback and an explicit `AICOMMANDER_DEV=1`, both for local
  development; see `packages/agent/src/relay-url.ts`, which documents the rule and
  the reasoning. There is no self-hosted relay deployment today.
- **The session code is a credential for command execution as the agent's uid** — root
  or LocalSystem under the documented service install. Anyone who holds the code can run
  commands on the machine. Treat it exactly like an SSH private key.
- **Nothing in the package runs on install.** Its manifest defines no
  `preinstall`, `install`, `postinstall` or `prepare` script — the four hooks npm
  can run without being asked — so `npm install @aicommander/agent` executes no
  code from this package: it opens no socket, spawns no process and contacts no
  host. That is a claim about this package and nothing else: npm still fetches
  the tarball from the registry, and any dependency remains free to run its own
  install scripts (`npm install --ignore-scripts` settles both). The agent starts
  only when you explicitly run `npx @aicommander/agent`, or deliberately install
  it as a service.
- **The published bundle is unminified**, with the originating source path left
  as a comment above each inlined section, and the one prebuilt binary in the
  tarball is the Windows launcher described under
  [Verifying the Windows launcher](#verifying-the-windows-launcher). Everything
  else it contains is text.

If that capability is not what you want on a machine, do not run this software on it.

## What this repository is

A **one-way mirror**. Development happens in a private monorepo; every release
overwrites this repository's `main` with a squashed snapshot of the agent's source and
tags it. **Pull requests here cannot be merged** — changes have to be made upstream.

It contains only what is needed to build and publish the npm package:

| Path | What it is |
|---|---|
| `packages/agent` | The agent itself — the published package |
| `packages/protocol` | Relay wire protocol, inlined into the agent bundle by esbuild |
| `packages/priv-helper` | Privileged helper, built before the agent's `prepublishOnly` |
| `packages/agent/dist-native/` | Windows UTF-8 exec launcher, built and signed in the private repo (signing secrets never reach this repository) and carried here as a committed artifact with its `.sha256` and a detached `.sig` — see [Verifying the Windows launcher](#verifying-the-windows-launcher) |

## Verifying the Windows launcher

`packages/agent/dist-native/aicommander-win-exec-x64.exe` is the only binary in
this repository. It is built and Authenticode-signed in the private release
pipeline, then committed here — this repository holds no signing key, so it
cannot produce that binary, only check the one it is handed.

Before every publish, `.github/workflows/publish.yml` runs
`packages/agent/scripts/verify-win-exec.mjs --require-authenticode --require-signature`,
in public, where you can read the result in the run log. That check either
passes or the publish stops. Exactly what it establishes:

- **Origin — the detached `.sig`.** A raw Ed25519 signature over the file's
  bytes, verified against the release public key pinned in
  `packages/agent/scripts/release-key.mjs` (SPKI SHA-256
  `2d76d381fc8ed38e7dfb53882e14b2980ee105e0b49ff31cf55403e19e648407`, also
  served at <https://aicommander.dev/install.pub>, and the same key that signs
  the agent binaries and the `install` script). The private half never enters
  this repository, so a substituted launcher cannot be re-signed to pass.
  Verify it yourself:

  ```bash
  cd packages/agent/dist-native
  curl -fsS https://aicommander.dev/install.pub -o release.pub
  openssl pkey -pubin -in release.pub -outform DER | openssl dgst -sha256   # must print the fingerprint above
  openssl pkeyutl -verify -pubin -inkey release.pub -rawin \
    -in aicommander-win-exec-x64.exe -sigfile aicommander-win-exec-x64.exe.sig
  ```

- **Shape — the PE image.** A strict parse of the PE headers and section
  layout, a required `Machine` of `0x8664` (x64), and a required, well-formed
  Authenticode certificate table (PKCS#7 `WIN_CERTIFICATE` records ending
  exactly at EOF, with no opaque overlay appended).

And what it does **not** establish, so that nothing here reads as more than it
is: the script does not itself validate the Authenticode PKCS#7 signature or
build a certificate chain. That signature is validated by Windows when the file
runs, and by `Get-AuthenticodeSignature` in the private build — which also pins
the signer subject and requires an RFC-3161 timestamp. The co-committed
`.sha256` is transport integrity only; it lives next to the file it describes,
so on its own it proves nothing about where that file came from.

## Issues

Please file issues and security reports at
<https://github.com/AICommander-dev/aicommander/issues> — this mirror's tracker is not
monitored.

## Building

```bash
pnpm install --frozen-lockfile
pnpm build
pnpm test
```

## License

[Elastic License 2.0](LICENSE.txt) (SPDX: `Elastic-2.0`) — use, copy, modify and
redistribute freely; do not offer this software to third parties as a hosted or
managed service.

**1.0.56 and earlier are MIT; 1.1.0 and later are Elastic License 2.0.** The relicense lands
on the 1.1.0 release, so the boundary is a version number, not a date: every
`@aicommander/agent` release up to and including 1.0.56 stays under the MIT
license it shipped with, and that grant is irrevocable.

`packages/priv-helper` is ELv2 as well, on the same 1.1.0 boundary: it is a
private workspace package, but its code is bundled into the `@aicommander/agent`
tarball, so it has been distributed — under MIT — in every agent release up to
and including 1.0.56, and that grant is irrevocable for those releases.

`packages/protocol` stays **MIT**. Its code is bundled verbatim into
`@aicommander/mcp`, which is MIT and stays MIT, so relicensing it would put the
same source under two licenses in two published tarballs. It is also inlined by
esbuild into the agent's published `dist/index.js` and `dist/bin/agent.js`, so
the MIT notice travels inside the npm tarball as `THIRD-PARTY-NOTICES.txt`
(`packages/agent/THIRD-PARTY-NOTICES.txt` here), which names every inlined
component and reproduces the MIT text in full.

Between releases the agent manifest declares `Elastic-2.0` while its `version`
still reads the last MIT release; `packages/agent/scripts/license-boundary.mjs`
refuses to publish that combination, and this repository's `publish.yml` runs it
on the tagged tree before `npm publish`.
