// The last line of defence for every string the helper's `doctor` prints.
//
// WHY THIS EXISTS, HAVING BEEN ARGUED NOT TO. doctor.ts used to carry a header
// claiming that nothing in its output needs redacting "by construction": only
// fixed machine-wide locations, counts and booleans. That claim was false in
// three places at once — the VERSION marker's CONTENT is a file anybody who can
// write beside a COPIED helper controls; the unelevated install scan reports a
// root derived from THIS binary's own location, which is a user path the moment
// somebody runs the helper out of their Downloads folder; and a check that
// throws prints the exception's message, which for an fs error embeds the path
// it failed on. The verb is advertised — in its own footer — as safe to send to
// support or to an antivirus vendor, so "by construction" had to become "by
// rule".
//
// The rules are the agent's (`redactDiagText` in agent/src/diag-log.ts), mirrored
// rather than imported: the agent depends on THIS package, so importing back
// makes the workspace cycle turbo already refuses (see doctor.ts's header). They
// are deliberately the same rules — a support engineer reading a helper report
// beside an agent report should not have to learn two redactions. The rules
// themselves are pinned by the tests beside this file, one per rule; the two
// copies are not diffed automatically, so a change THERE is a change to make
// here as well.
//
// ONE RULE IS NOT MIRRORED BUT SHARED, because it could be. This file used to
// claim parity while blanking all three groups of a session code
// (`AIC-****-****-****`) where the agent keeps the first
// (`AIC-9K3F-***-***`). Correlating a helper report against an agent report is
// the stated reason for the mirroring, and a support engineer cannot correlate
// two codes that have both been erased. The masking lives in
// `@aicommander/protocol` — a leaf package this one already depends on, and NOT
// the agent, so there is no cycle to avoid — so it is CALLED rather than
// re-implemented, and the parity is a fact instead of a promise.
//
// The wrapper adds exactly one thing. `maskSessionCode` returns anything that is
// not a canonical code UNCHANGED (the minting alphabet excludes I, L, O and U),
// which is right where a placeholder like "—" must survive and wrong here: this
// redactor's whole job is that a mistake is harmless, and passing a code-shaped
// string through in full is not harmless. So a match the protocol package
// declines to mask is blanked instead. Every string the two redactors will ever
// be asked to correlate — an actual session code — comes out identical.
//
// IDEMPOTENT: redacting an already-redacted string leaves it alone, so a value
// that passes through twice does not become `/home/<<user>>`.

import os from "node:os";

import { maskSessionCode } from "@aicommander/protocol";

/**
 * A session code, in the agent's own loose spelling — deliberately looser than
 * the canonical alphabet so a mistyped or lower-cased code is still caught.
 */
const SESSION_CODE_RE = /\bAIC-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}\b/gi;
/** What a code becomes when the protocol package will not vouch for it. */
const BLANKED_CODE = "AIC-****-****-****";

/**
 * The agent's mask, called — reveal the prefix and the first group, blank the
 * two that are the credential. Uppercased first because codes are minted
 * uppercase over a case-insensitive alphabet and `redactDiagText` canonicalises
 * the same way; that is what makes the two reports byte-identical for one code.
 * A value the protocol package hands back unchanged was not a real code, and is
 * blanked rather than printed. See the header.
 */
export function maskHelperSessionCode(match: string): string {
  const code = match.toUpperCase();
  const masked = maskSessionCode(code);
  return masked === code ? BLANKED_CODE : masked;
}
/** A JWS/JWT triple — the elevated capability's shape. Matched before the blob rule. */
const JWS_RE = /\b[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g;
/** Any long opaque run: tickets, tokens, device secrets, API keys. */
const OPAQUE_BLOB_RE = /\b[A-Za-z0-9_-]{32,}\b/g;
const CONTROL_CHARS_RE = /[\u0000-\u001f\u007f]/g;
/** `C:\Users\<name>` / `/home/<name>` belonging to ANY account, not just ours. */
const HOME_SEGMENT_RE = /(^|[\s"'=(:,])((?:[A-Za-z]:)?[\\/](?:Users|home)[\\/])([^\\/\s"',)]+)/g;

/** No single line of a report is a payload. */
const MAX_TEXT_CHARS = 600;

function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * This process's own home directory, as a matcher, built ONCE at module load —
 * a redactor must not depend on what the environment looks like at the moment
 * somebody prints something. A one-segment root is ignored: substituting it
 * would rewrite every absolute path on the machine into `~`.
 */
const HOME_DIR_RE: RegExp | null = (() => {
  let home: string;
  try {
    home = os.homedir();
  } catch {
    return null;
  }
  if (!home || home.length < 4) return null;
  const trimmed = home.replace(/[\\/]+$/, "");
  return new RegExp(escapeRegExp(trimmed), process.platform === "win32" ? "gi" : "g");
})();

/** The operator's config-dir override — neither shaped like a home nor inside one. */
const CONFIG_DIR_RE: RegExp | null = (() => {
  const raw = process.env["AICOMMANDER_CONFIG_DIR"]?.trim();
  if (!raw || raw.length < 4) return null;
  const trimmed = raw.replace(/[\\/]+$/, "");
  if (trimmed.length < 4) return null;
  return new RegExp(escapeRegExp(trimmed), process.platform === "win32" ? "gi" : "g");
})();

/**
 * Paths are worth keeping — "where is this installed", "which of our own files
 * was refused" is what the report is FOR. The ACCOUNT NAME inside them is worth
 * nothing to any reader and is the user's identity leaving the machine.
 */
export function redactHelperPaths(text: string): string {
  const withoutConfig = CONFIG_DIR_RE ? text.replace(CONFIG_DIR_RE, "<config-dir>") : text;
  const out = HOME_DIR_RE ? withoutConfig.replace(HOME_DIR_RE, "~") : withoutConfig;
  return out.replace(HOME_SEGMENT_RE, (_m, lead: string, root: string, name: string) =>
    name === "<user>" ? `${lead}${root}${name}` : `${lead}${root}<user>`,
  );
}

/**
 * Every string that reaches the helper's report goes through here. Callers are
 * still expected not to collect secrets; this is what makes a mistake harmless
 * instead of a credential in a vendor's inbox.
 */
export function redactHelperText(text: string): string {
  const redacted = redactHelperPaths(text)
    .replace(SESSION_CODE_RE, maskHelperSessionCode)
    .replace(JWS_RE, "[redacted-jws]")
    .replace(OPAQUE_BLOB_RE, "[redacted]")
    .replace(CONTROL_CHARS_RE, " ");
  return redacted.length > MAX_TEXT_CHARS ? `${redacted.slice(0, MAX_TEXT_CHARS)}…` : redacted;
}
