# @aicommander/agent — remote shell, jobs, and file-transfer agent

> **What this package is, stated plainly.** This is remote-administration
> tooling. It executes shell commands that arrive over a network connection, and
> the session code is a **root-exec credential** for doing that: under the
> documented service install the agent runs as root, so anyone who holds the code
> can run commands as root on the machine. That is the advertised purpose, not a
> side effect, and it is the whole product.
>
> Four things follow, and they are what separate this from the malware the
> capability resembles:
>
> - **Nothing in this package runs on install.** Its manifest defines no
>   `preinstall`, `install`, `postinstall` or `prepare` script — the four hooks
>   npm can run without being asked — so `npm install @aicommander/agent`
>   executes no code from this package: it opens no socket, spawns no process
>   and contacts no host. That is a claim about THIS package and nothing else.
>   npm still fetches the tarball from the registry, and any dependency remains
>   free to run its own install scripts; `npm install --ignore-scripts` settles
>   both. The agent runs only when you run it.
> - **It can only ever talk to one relay, and that is deliberate.** The agent is
>   **host-locked** to `https://aicommander.dev`. An `AICOMMANDER_SERVER` pointing
>   anywhere else is ignored, loudly, and the agent falls back to the canonical
>   relay — because it runs as root, so a stray or injected environment variable
>   must not be able to re-home it to someone else's server. The exceptions are
>   loopback and an explicit `AICOMMANDER_DEV=1`, both for local development. See
>   `src/relay-url.ts`, which documents the rule and the reasoning. There is no
>   self-hosted relay deployment today.
> - **The published bundle is unminified.** `dist/index.js` and
>   `dist/bin/agent.js` are ordinary multi-line JavaScript, and esbuild leaves
>   the originating source path as a comment above each inlined section, so you
>   can read what you install and see where each part came from. The source is
>   public at <https://github.com/AICommander-dev/aicommander-agent>.
> - **One file in the tarball is a prebuilt binary, and it is the only one.**
>   `dist-native/aicommander-win-exec-x64.exe` is a small MSVC-built C++ launcher
>   used only on Windows: it creates a hidden console, switches both console code
>   pages to UTF-8, and starts `cmd.exe /d /s /c` with the command unchanged. Its
>   full source is in the public repository next to everything else
>   (`packages/agent/native/win-exec-launcher/`), but the copy in the tarball is
>   NOT built from the tarball — it is compiled and Authenticode-signed in the
>   release pipeline and injected as a CI artifact. It is verified twice before
>   any publish, once privately and once in the public mirror's `publish.yml` run
>   log, with `scripts/verify-win-exec.mjs --require-authenticode
>   --require-signature`: a detached Ed25519 signature over the file's bytes,
>   checked against the release key pinned in the source and served at
>   <https://aicommander.dev/install.pub>. That `.sig` and its `.sha256` are not
>   inside the npm tarball; they sit beside the identical bytes in the mirror
>   repository, so `sha256sum` on the file you installed is what ties the two
>   together. Everything else the tarball contains is text.
>
> Treat the session code like an SSH private key. The [Security](#security)
> section below is the full threat model, including what to do if it leaks.

The **on-machine agent** for [AI Commander](https://aicommander.dev). Run it on a
server, laptop, container, or CI box and it dials out to the relay and listens for
commands — letting your AI client execute shell/bash commands and detached
long-running background jobs on that machine, and transfer regular files to or
from it, through the
[`@aicommander/mcp`](https://www.npmjs.com/package/@aicommander/mcp) server (or
any MCP/HTTP client pointed at the relay). Long builds, downloads, batch
processing, rendering, and GPU/ML training return a `jobId` immediately and keep
running after the request and conversation end.

File transfer uses the same outbound-only network model and machine identity.
The MCP client can use `remote_pull(code, path)` to collect a file from the
machine and, for signed-in callers, `remote_push(code, blob_id, dest_path)` to
place a previously uploaded blob on it.

It's an **SSH alternative** with no exposed SSH, no open inbound ports, and no
VPN: the agent connects outbound, prints an `AIC-…` session code, and you drive it
from your AI by that code (or a saved alias, with an account API key).

Requires **Node ≥ 20** on the target machine.

> **Install this on the machine you want to manage/control** (the server, VM,
> container, or laptop you want your AI to run commands on) — **NOT** on the
> machine running your AI client. The client side is a different package,
> [`@aicommander/mcp`](https://www.npmjs.com/package/@aicommander/mcp) (the
> MCP server your editor/Claude talks to). Install `@aicommander/agent` on the
> target, `@aicommander/mcp` next to your AI client.

## Quick run (ephemeral, foreground)

```bash
npx @aicommander/agent
```

Runs in the **foreground** and prints the **full session code** (you ran it
yourself in your own terminal, so there's nothing to reveal), then listens until
you press **Ctrl-C**. Nothing is installed and no service is created — ideal for
containers, CI, dev boxes, or a quick one-off connection.

```bash
# Point at a different relay if you self-host:
AICOMMANDER_SERVER=https://relay.example.com npx @aicommander/agent
```

The printed code is what you give to your AI client: *"execute df -h on AIC-…"*.
(`aicommander-agent status --reveal` is only for the systemd **service** below,
where logs/status keep the code masked.)

## Persistent service (Linux, systemd)

Install globally and register a systemd unit that starts on boot and restarts on
failure:

```bash
sudo npm i -g @aicommander/agent
sudo aicommander-agent install
```

`install` writes `/etc/systemd/system/aicommander-agent.service`, enables it,
(re)starts it, and prints the session code. The unit runs `aicommander-agent run`
via the absolute path of the installed CLI and the Node binary that performed the
install (so it doesn't depend on `PATH`).

`install` first verifies that a running systemd manager is reachable. On a Linux
host without systemd (including a minimal container that happens to include the
`systemctl` binary), it fails before creating a directory or user or writing a
unit. `aicommander-agent run` remains available as a foreground alternative, but
it lasts only until its process or terminal closes and does not start after a
reboot. For persistence, configure it with the host's native init/process manager
or platform autostart (for example OpenRC, supervisord, s6, runit, or a container
restart policy). If the host provides none of those facilities, a persistent
installation that returns after reboot is not possible.

```bash
# Bake a relay URL into the unit. Host-lock still applies at RUNTIME: anything
# other than https://aicommander.dev, a loopback address, or a URL paired with
# AICOMMANDER_DEV=1 is ignored with a warning and the agent uses the canonical
# relay anyway. This flag is for local development, not for self-hosting —
# there is no self-hosted relay deployment today.
sudo aicommander-agent install --server http://localhost:8787
```

Manage the service:

| Command | What it does |
|---|---|
| `sudo aicommander-agent status [--reveal]` | Show status, uptime, session code (masked unless `--reveal`) |
| `sudo aicommander-agent enable` | Start+enable the service |
| `sudo aicommander-agent disable` | Stop+disable the service. It also names any `aic-job-*.scope` units still running — they outlive the agent by design, so they keep running **as root** with nothing supervising them and can no longer be cancelled through AI Commander — and prints the `systemctl stop` that ends them. It deliberately does **not** kill them: "do not run the agent" is not consent to end someone's training run. If the scopes cannot even be listed, it says so rather than implying nothing is running. |
| `sudo aicommander-agent change-code` | Mint a new code and revoke all current access |
| `sudo aicommander-agent uninstall --force` | Stop, disable, and remove everything. Leftover `aic-job-*.scope` units — which stopping the service no longer takes down — are stopped first, and one that will not stop within the budget is **SIGKILLed**, which **ends that job**; every escalation is printed as it happens and every killed scope is named in the summary. The teardown is then verified: if any scope could not be torn down, or could not even be enumerated, the job workspaces and logs are deliberately **kept** rather than deleted out from under a root process that may still be writing to them. They are named, together with the `systemctl stop` that ends the scopes and the `rm -rf` that finishes the removal by hand. |
| `aicommander-agent doctor [--json] [--report <path>] [--offline] [-v\|--verbose]` | Diagnose this machine when the app will not start or the machine shows offline: the shipped file list (present, and re-hashed), whether the install directory accepts a write and with what OS error verbatim, a live antivirus-interference probe (writes the real job scripts into a scratch directory, reads them back, removes them), the connection ladder — DNS → HTTPS → **ticket exchange** → WebSocket upgrade, each with its actual status code — the autostart entry's pinned path, the privileged helper (installed / registered / signed / answering / protocol), the identity and session store, the diagnostic log, disk, clock and proxy variables. Needs no root. It changes nothing: no credential is consumed, no code rotated, no file left behind, and a running agent is never disturbed — a check that cannot be done safely reports itself skipped and says why. `--report` writes a **redacted** bundle (no access code, no token, no command text, account names stripped from every path) meant to be attached to a support case or an antivirus-vendor submission. `-v`/`--verbose` adds each check's structured facts (paths, errnos, status codes, counts) under its line — the console view is deliberately unredacted, so a remedy naming a real path stays followable. Exits 1 when a check failed, and also when `--report` could not write the file it was given. |
| `journalctl -u aicommander-agent -f` | Follow service logs |

For the Windows privileged helper, an Authenticode `UnknownError` is a failed
signature verification: the doctor could not confirm the signature, without
claiming the binary is malicious. Explicit file-access failures remain warnings.
On macOS, a conclusive root `launchctl` answer that the helper is not loaded is
a failure even when the plist itself could not be inspected.

Helper file checks report a missing binary or `VERSION` marker as a failure even
when another path cannot be inspected. The report describes that inspection error
separately; an access error alone remains a warning and does not establish absence.

Service logs are payload-free: journald may receive operation start/end, exit
code, duration, and the printable executable basename for secure exec. It never
receives the full shell command, secure-exec argv, cwd, env, input, stdout, or
stderr. The library controller used by the desktop app is silent; an explicit
foreground TTY run uses the same safe summary and does not print command payloads.
Remote stdout/stderr is buffered for the requesting client. The REST SSE form
sends heartbeat comments while the command runs, then one final result event; it
does not stream output progressively.

On x64 Windows, ordinary `remote_exec` keeps `cmd.exe /d /s /c` command
semantics while a signed, unprivileged native launcher creates a hidden console
and verifies both console code pages are 65001 before `cmd.exe` is allowed to
run. This works when the Electron desktop parent has no attached console, keeps
stdout and stderr as separate streaming pipes, and gives cmd built-ins and
console-aware native programs UTF-8 output. Missing/incompatible launcher or a
failed code-page setup refuses the command instead of falling back to legacy
bytes. Python also receives `PYTHONUTF8=1` and `PYTHONIOENCODING=utf-8` unless the
request explicitly overrides them. The agent intentionally does not use a
PowerShell preamble because that would change cmd quoting, expansion, pipelines,
and built-ins. Both the TypeScript resolver and the launcher verify architecture;
the native check detects an ARM64 OS even when Node/Electron itself runs under
x64 emulation. Windows ARM64 execution is currently refused until a native ARM64
launcher has its own release/runtime test lane.

## Detached jobs and GPUs

On Windows, a visible job terminal identifies itself as **AI Commander - running job**.
It shows the job ID, the initiating account's server-masked email when available
(otherwise anonymous/account unavailable), and the start date and time in the
machine's local timezone with its UTC offset. Closing the window may stop the job;
view its output and status in AI Commander. This notice stays out of the job log.
Account lookup is best-effort and delays startup by at most 750 ms. macOS and Linux
jobs do not open a separate terminal window.
Banner account lists, including failed lookups, are cached for five minutes per
device to preserve the device API quota; displayed masked addresses may reflect
that cached data. Manual Linked Accounts and block/unblock actions remain fresh.

The complete MCP inventory is `remote_exec`, `session_status`, `list_machines`,
`remote_screenshot`, `remote_pull`, `remote_push`, and `remote_job_start` /
`_list` / `_status` / `_logs` / `_cancel`. Besides ordinary command execution,
the agent serves the **detached job** tools (and their `/api/v1/jobs` HTTP twin).
A job is a long-running command that outlives the
request that started it: the agent spawns it in its own process group with
stdout+stderr redirected to a file, and a shell wrapper writes the exit code to
disk — so the outcome is recorded even if the agent is not alive when the job
ends. That lifts both of `remote_exec`'s caps: its 1-hour deadline hard-kills the
process tree, while its 1&nbsp;MiB output cap truncates the reply and sends only a
best-effort stop that can lose the race, leaving the process running.

- **State lives on this machine, not the relay.** One directory per job under
  `<jobs root>/<jobId>/` holding `meta.json`, `output.log`, the `exit` marker and
  a default `workspace/`. The jobs root is `<configDir>/jobs` when a config
  directory is set (including `AICOMMANDER_CONFIG_DIR` — so pointing that at
  durable storage moves job data too), `/var/lib/aicommander/jobs` for a root
  service, and a per-user data dir otherwise. It holds logs and workspaces, so
  give it a volume with room.
- **Restart recovery.** At startup the agent reconciles every job it left behind:
  exit file ⇒ `exited`, live pid ⇒ adopted as `running`, otherwise `unknown`
  (never a fabricated success). It also reaps GPU locks left by dead jobs. On
  macOS/Windows a job can remain alive across an agent restart; on Linux a job
  started by an agent that already has this feature is launched through
  `systemd-run --scope` into its own `aic-job-<jobId>.scope`, outside the
  service's control group, so stopping, restarting, or upgrading the service
  leaves it running. When a scoped job reaches a terminal state — it finished on
  its own, or it was cancelled — the agent empties what is left of that scope,
  so a descendant that escaped the job's process group (one that called
  `setsid`) cannot keep running on a GPU whose lock has just been handed to the
  next job. On macOS and Windows such a descendant survives, as it always has.
  That path needs a systemd host and a **root** agent;
  without both (a non-systemd host, a non-root agent) jobs stay in the service's
  control group and a restart still ends them — the agent logs which it got in
  one line at startup, and again only if a later re-probe changes that answer.
  It does not reach backwards either: a job that was already running when the
  agent was upgraded **to** that version is in no scope, and the restart the
  upgrade performs is what ends it, so check `remote_job_list` and finish or
  checkpoint running work before that first upgrade.
  Finished job directories are retained for about 7 days and swept in the
  background at most hourly, driven by job start/list activity.
- **Caps that don't kill.** `output.log` stops growing at 256 MiB with a
  truncation notice; the job itself keeps running. Each log read returns at most
  256 KiB, paged by byte offset.
- **GPU awareness.** The agent probes `nvidia-smi` (no shell, 5 s timeout) at
  registration and every 60 s, reporting each card's index, model, total/used
  VRAM, utilization and driver version. Machines without a card report nothing
  and skip the poll entirely. A job started with a `gpuIndex` takes an exclusive
  lockfile on that card and gets `CUDA_VISIBLE_DEVICES` set for it.
- **No new privilege.** A job runs as the agent's own user, exactly like
  `remote_exec`; there is no elevated job path. Job commands and output are
  payload — never logged, and the command string leaves the machine only when the
  caller explicitly asked for it.

### Job implementation

[`src/job-manager.ts`](src/job-manager.ts) owns lifecycle decisions, cancellation,
restart recovery, retention, and GPU reservations. Its helpers separate
[`job-types.ts`](src/job-types.ts) (records and requests),
[`job-store.ts`](src/job-store.ts) (metadata and shared filesystem helpers),
[`job-output.ts`](src/job-output.ts) (log reads and response formatting), and
[`job-process.ts`](src/job-process.ts) (process launch, environment, and identity).
Existing imports continue to use `job-manager.ts`.

Status is derived from disk and process evidence. An unverifiable PID keeps its
job running and its GPU reserved. A persisted cancellation takes precedence over
an exit marker, including after restart and when the marker appears during a
status check. Start/cancel coordination stays in the manager so extracting an
I/O helper does not change when a reservation can be released.

## File transfer

The agent advertises file-transfer capability and handles the machine side of
`remote_pull` and `remote_push`. It validates that a pull source is a single
regular file, streams bytes over a separate HTTPS request (not the command
WebSocket), and writes a pushed file through a temporary sibling followed by an
atomic rename so an interrupted push does not leave a partial destination.

Each file is limited to 100&nbsp;MiB. Archive a directory into one regular file
before pulling it; larger artifacts should go directly through your own object
storage or artifact registry. Relay blobs stop being readable 24 hours after
creation; an hourly, retrying sweep removes the inaccessible bytes afterward.
Download links expire after 1 hour, and upload/push requires a signed-in account.
See the public [file-transfer reference](https://aicommander.dev/file-transfer/)
for MCP and REST calls, authorization, retention, and request deadlines.

## npm channel vs the signed native installer

| | `npx` / `npm i -g` (this package) | verified native release installer |
|---|---|---|
| Runtime | Your Node ≥ 20 | Self-contained native binary (no Node) |
| Best for | Ephemeral / dev / CI / Node-managed hosts | Linux systemd installs |
| Integrity | npm's tarball integrity + registry-side checksums | **SHA-256 checksum enforced** before install |
| Authenticity | npm registry trust | Installer + binary **Ed25519 signatures**, when the key fingerprint is independently confirmed |
| Update | `npm i -g @aicommander/agent@latest` | Repeat the verified download flow |

## Security

This npm package relies on **npm registry/tarball integrity** for trust. The
native release flow verifies a signed, versioned installer before `sudo`, then
verifies the downloaded binary against the same Ed25519 key and enforces its
SHA-256 checksum. Follow the current steps at
<https://aicommander.dev/howto/#install-agent>; never pipe `/install` directly
into `sudo bash`. The Ed25519 guarantee is meaningful only after confirming the
key fingerprint through a channel independent of the download website.

Prefer this npm package for **ephemeral / dev use** and Node-managed
environments. In all cases: the session code is a **root-exec credential** —
anyone who has it can run commands as root on the machine. Keep it secret, don't
paste it into shared chats/screenshots/tickets, and rotate it with
`aicommander-agent change-code` if it leaks.

The relay connection does not put that code or the reusable `agentToken` in its
WebSocket URL. The agent authenticates a fixed-URL POST with
`Authorization: Bearer`, receives a 30-second single-use opaque connection
ticket, then opens the ticket URL with the same Bearer header. Relay errors and
local reconnect output do not include the Authorization value.

**Local credential files:** the Linux CLI and systemd service persist
`device.json` (device identity) and `session.json` (session code + agent token)
under `/etc/aicommander-agent` with a `~/.config` fallback, and stamp live
metadata in `/var/run/aicommander-agent/state.json`.
Both use atomic writes and owner-only `0700`/`0600` modes; systemd installs set
`AICOMMANDER_SERVICE=1` and fail closed if persistence breaks. The desktop app
keeps the session code in `session.json` but stores the reusable agent token in
OS-protected Electron `safeStorage` (`session.token`); it refuses to start when
that encryption is unavailable.

**`AICOMMANDER_CONFIG_DIR` — storing them somewhere durable:** the default chain
assumes `/etc` survives a reboot. Where it does not (QNAP QTS rebuilds its whole
root filesystem from a ramdisk at every boot; some container images are just as
volatile) the agent would come back with a new device identity, a new session
code, and no linked accounts. Point this variable at durable, writable storage
and both files live there instead:

```bash
sudo AICOMMANDER_CONFIG_DIR=/share/CACHEDEV1_DATA/aicommander/config \
  aicommander-agent run
```

- **Precedence:** an explicit `configDir` (the desktop app's per-user data dir)
  wins; then `AICOMMANDER_CONFIG_DIR`; then `/etc` → `~/.config`. Leaving it
  unset behaves exactly as before.
- **Must be an absolute path that the agent can create and write.** A relative,
  typo'd, or read-only value is a **fatal startup error**, never a silent
  fallback to the volatile default.
- **Migration is automatic:** switching it on for a machine that already
  registered adopts the existing `device.json`/`session.json` from
  `/etc/aicommander-agent` or `~/.config/aicommander-agent` — the identity is
  copied over on the next start, the session code is reused and lands there on
  the next save, both at the same owner-only `0700`/`0600` modes — and both
  adoptions are logged. So the code and every linked account survive. New writes
  only ever go to the override dir; the old locations stay readable and are
  purged on `change-code` and on identity regeneration, so nothing stale can be
  read back.
- **Export it for CLI subcommands too.** The variable is per-process, so
  `sudo -E` (or setting it in the same command) keeps the CLI on the store the
  service uses. `change-code` still rotates without it — the agent also looks for
  the rotate marker in the old locations — but `list-admins` and `block-admin`
  mint a separate identity and address a device the relay has never seen; they
  warn on stderr when that happens.

The separate service-token **secure exec** path is Linux-only and drops every
command to the installer-created `aicommander-exec` account. New accounts have no
supplementary groups and an owner-only (`0700`) home. Before any target process
spawns, the agent rejects known shells/interpreters/argument runners and
privilege/container/orchestration clients even if a hostile relay claims they
are allowlisted. It also parses local `/etc/passwd` and `/etc/group` without a
shell and refuses privileged primary or supplementary membership (`root`,
`wheel`, `sudo`, `docker`, `podman`, `lxd`, `incus`, `disk`, `libvirt`, or gid
`0`). Missing, unreadable, malformed, duplicate, or otherwise ambiguous identity
data fails closed.

The command denylist is intentionally not a complete sandbox policy: ordinary
tools can gain subprocess features over time. The non-root uid/group boundary,
not the basename allowlist or denylist, remains the containment mechanism.

## License

[Elastic License 2.0](LICENSE.txt) (SPDX: `Elastic-2.0`) — you may use, copy,
modify and redistribute this software, but you may not offer it to third parties
as a hosted or managed service.

**1.0.56 and earlier are MIT; 1.1.0 and later are Elastic License 2.0.** The relicense
lands on the 1.1.0 release; every version up to and including 1.0.56 stays under
the MIT license it shipped with, and that grant is irrevocable.

Between releases this tree carries `"license": "Elastic-2.0"` while `version`
still reads the last MIT release, because the release script bumps the number —
so a tarball built straight from a development checkout would carry a manifest
that contradicts the sentence above. It cannot be published:
`scripts/license-boundary.mjs` refuses any version at or below 1.0.56, and any
version below 1.1.0 that declares `Elastic-2.0`. It runs in `scripts/release.mjs`
before the bump is written, and again on the tagged tree in the mirror's public
publish workflow.

**What is under which license.** Everything in this package is Elastic-2.0. The
published `dist/index.js` and `dist/bin/agent.js` additionally have two workspace
packages inlined into them by esbuild: `@aicommander/priv-helper` (Elastic-2.0,
same terms) and `@aicommander/protocol` (**MIT**). The MIT notice therefore
travels in the tarball, in [THIRD-PARTY-NOTICES.txt](THIRD-PARTY-NOTICES.txt),
which names each inlined component and reproduces the MIT text in full. The
runtime dependencies (`chalk`, `commander`, `ora`, `ws`) are not bundled — npm
installs them separately under their own terms.

Source: <https://github.com/AICommander-dev/aicommander-agent> (a one-way mirror of a
private monorepo — issues and pull requests belong at
<https://github.com/AICommander-dev/aicommander/issues>). Releases are published
from that repository with
[npm provenance attestations](https://docs.npmjs.com/generating-provenance-statements).
