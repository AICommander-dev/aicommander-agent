// WHY elevated execution is unavailable on a machine — the diagnostic that rides
// alongside `elevatedExec: false`.
//
// The flag alone was unreadable. `elevatedCapable` is emitted ONLY when true, so
// its absence meant "this machine has no privileged helper", "this agent is too
// old to report one" or "the field was dropped because the machine is offline" —
// three states with three different remedies that no consumer could tell apart,
// so no consumer said anything at all. On the machine that produced the
// 2026-09-02 incident the helper had never been REGISTERED, and nothing anywhere
// said so: every elevated call would have failed on a box that looked healthy.
//
// A REASON IS A DIAGNOSTIC, NEVER A CAPABILITY. Nothing may become permitted
// because this string looks benign: the agent still advertises `elevatedExec`
// only when it has completed a handshake with a helper it reached, and the relay
// still refuses elevated work unless that flag AND a live boot nonce are present.
// This vocabulary exists to explain a refusal, never to soften one.
//
// It also carries NO machine-identifying detail — no paths, ports, hostnames or
// signer subjects. It travels to the relay and into caller-facing text; the
// specifics belong in `aicommander-agent doctor`, which runs ON the machine and
// prints them to the person standing at it.
//
// ── THE SIX CAUSES, AND WHY EXACTLY THESE ────────────────────────────────────
// The vocabulary is the doctor's (agent doctor/checks/priv-helper.ts asks the
// same questions in the same order), so a relay answer and a local report never
// describe one machine in two dialects:
//
//  - platform_unsupported — Linux. There is no helper here BY DESIGN, and the
//    remedy is to stop asking for `elevated`, not to install anything.
//  - not_installed — the helper's files are not on disk. Re-install.
//  - not_registered — the files are there, but the OS was never told to run
//    them: no SYSTEM scheduled task on Windows, no LaunchDaemon plist on macOS.
//    THIS IS THE INCIDENT STATE, and it is invisible from the outside: the
//    Windows installer registers the task only after both installed copies pass
//    an exact-signer Authenticode check and deliberately ignores that failure, so
//    a perfectly healthy-looking install can simply have no helper.
//  - endpoint_unreachable — installed and registered, but nothing answers. The
//    helper is not running (it starts at boot); a reboot is the usual fix.
//  - protocol_mismatch — it answered, speaking an IPC protocol version this
//    agent will not speak. Half of a paired upgrade landed. Fails closed.
//  - endpoint_conflict — two endpoints answered with DIFFERENT boot nonces. A
//    live helper owns every port it could bind, so a second identity means
//    something that is not the helper is answering; the agent refuses to use
//    any of them (a local squatter is downgraded to a denial of service rather
//    than handed a signed capability).
//
// ── WHAT IS DELIBERATELY NOT HERE ────────────────────────────────────────────
// There is no `signature_mismatch`. The agent cannot produce it honestly: the
// Authenticode/codesign verdict costs a PowerShell (or codesign) spawn and the
// reconciler runs every 60 seconds, and — more decisively — a signature the
// installer rejected means the installer never registered the task, so the
// machine reports `not_registered`, which is the true statement about its state.
// The doctor answers the signature question on the machine itself. Reporting a
// distinction the discovery path cannot make would be worse than reporting none.

/** Every reason the agent may put on the wire. Order is diagnostic, not ranked. */
export const ELEVATED_UNAVAILABLE_REASONS = [
  "platform_unsupported",
  "not_installed",
  "not_registered",
  "endpoint_unreachable",
  "protocol_mismatch",
  "endpoint_conflict",
] as const;

export type ElevatedUnavailableReason = (typeof ELEVATED_UNAVAILABLE_REASONS)[number];

/**
 * Narrow an untrusted wire value to a known reason.
 *
 * The relay stores and repeats this string, so an agent (or something posing as
 * one) must not be able to put arbitrary text into a caller-facing message.
 * Anything unrecognised — including a reason a FUTURE agent invents — is dropped
 * and the surfaces fall back to what they said before reasons existed, which is
 * exactly how an agent too old to report one is treated.
 */
export function isElevatedUnavailableReason(
  value: unknown,
): value is ElevatedUnavailableReason {
  return (
    typeof value === "string" &&
    (ELEVATED_UNAVAILABLE_REASONS as readonly string[]).includes(value)
  );
}
