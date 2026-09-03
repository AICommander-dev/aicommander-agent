import { redactDiagText } from "../diag-log.js";
import { HELP_URL, type CheckResult, type DoctorFacts, type DoctorReport } from "./types.js";
import { renderDoctorReport } from "./render.js";

/**
 * The report bundle — the part of this command that leaves the machine.
 *
 * `--report <path>` writes a file whose whole purpose is to be attached to a
 * support case and, more to the point, EMAILED TO AN ANTIVIRUS VENDOR. That
 * makes redaction a correctness requirement here, not hygiene.
 *
 * ── ONE SET OF REDACTION RULES, NOT TWO ──────────────────────────────────────
 * Everything goes through `redactDiagText` from diag-log.ts, which is the rule
 * set the log already enforces on the same class of file. It masks session codes
 * (a root-exec credential), blanks JWS triples (the elevated capability), blanks
 * any 32+ character opaque run (agent tokens, ws tickets, device secrets, API
 * keys), strips control characters — and it de-identifies paths: this process's
 * home directory becomes `~`, any other account's `…/Users/<name>/…` becomes
 * `<user>`, and the AICOMMANDER_CONFIG_DIR override, which an operator may have
 * named after their company or their customer, becomes `<config-dir>`.
 *
 * Writing a second set of rules here would guarantee they drift, and the drift
 * would only ever be discovered by a credential arriving somewhere it should
 * not. Reusing the log's rules also means a fix to either one fixes both.
 *
 * Note what redaction deliberately KEEPS: paths, errnos and status codes. "Which
 * of our own files was refused, and with what errno" is the entire diagnosis and
 * the entire content of a vendor submission. A redaction that dropped paths
 * would take the report's reason for existing with it.
 *
 * ── WHAT NEVER REACHES HERE IN THE FIRST PLACE ───────────────────────────────
 * No check collects command text, job output, or a caller's paths. The probe
 * writes an inert command of our own. Redaction is the last line of defence, not
 * the first: the checks are written so that a mistake is harmless, rather than
 * so that a mistake is caught.
 *
 * That is not a hope, and it cannot be one: `redactDiagText` removes credentials
 * and account names, and has never claimed to remove ordinary text — a Run-key
 * value or a systemd `ExecStart=` line would pass through it word for word. The
 * rule about what a fact may hold is therefore enforced where facts are BUILT;
 * it is written down beside `DoctorFacts` in types.ts, and every check that
 * reads a command line to find a path in it records the path alone.
 *
 * ── THE HUMAN CONSOLE OUTPUT IS NOT REDACTED ─────────────────────────────────
 * On purpose. A user reading their own terminal needs the real path in "exclude
 * this directory in your antivirus" — a remedy that says `~` is a remedy they
 * cannot follow. The redaction boundary is the FILE and the `--json` output,
 * i.e. exactly the artefacts that get forwarded to somebody else.
 */

function redactFacts(facts: DoctorFacts): DoctorFacts {
  const out: DoctorFacts = {};
  for (const [key, value] of Object.entries(facts)) {
    out[key] = typeof value === "string" ? redactDiagText(value) : value;
  }
  return out;
}

function redactCheck(check: CheckResult): CheckResult {
  return {
    ...check,
    detail: redactDiagText(check.detail),
    ...(check.facts ? { facts: redactFacts(check.facts) } : {}),
    ...(check.remedy ? { remedy: redactDiagText(check.remedy) } : {}),
  };
}

/**
 * The report with every string put through the diagnostic log's redactor.
 * Idempotent — `redactDiagText` leaves an already-redacted value alone — so a
 * caller that redacts twice gets the same file, not `<<user>>`.
 */
export function redactDoctorReport(report: DoctorReport): DoctorReport {
  return { ...report, redacted: true, checks: report.checks.map(redactCheck) };
}

/** The `--json` payload: redacted, stable key order, ready to attach. */
export function doctorReportJson(report: DoctorReport): string {
  return `${JSON.stringify(redactDoctorReport(report), null, 2)}\n`;
}

/**
 * The `--report <path>` bundle: a header saying what the file is and what was
 * removed from it, the human rendering, and the machine-readable JSON — in that
 * order, because the first reader is a support engineer and the second is a
 * script.
 */
export function doctorReportBundle(report: DoctorReport): string {
  const redacted = redactDoctorReport(report);
  return [
    "AI Commander — diagnostic report",
    "================================",
    "",
    `generated  ${redacted.generatedAt}`,
    `agent      ${redacted.agentVersion}`,
    `platform   ${redacted.platform}/${redacted.arch}, Node ${redacted.node}`,
    `elevated   ${String(redacted.elevated)}`,
    "",
    "This file is safe to attach to a support case or an antivirus vendor submission.",
    "It contains NO access code, NO agent token, NO command text and NO command output.",
    "User account names have been removed from every path.",
    `Background on the antivirus false positives this command diagnoses: ${HELP_URL}`,
    "",
    renderDoctorReport(redacted, { color: false }),
    "",
    "--- machine-readable ---------------------------------------------------------",
    JSON.stringify(redacted, null, 2),
    "",
  ].join("\n");
}
