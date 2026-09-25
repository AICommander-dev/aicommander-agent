/**
 * `doctor` — the hour of hands-on forensics the 2026-09-02 incident cost,
 * automated.
 *
 * A library of checks plus a renderer. The CLI (ctl/commands/doctor.ts) is one
 * caller; the Electron tray (W2.2) and the privileged helper's own verb (W2.3)
 * are the other two, and neither of them may have to reimplement a verdict — so
 * nothing under `doctor/` prints, and nothing under `doctor/checks/` decides how
 * anything looks.
 *
 * Entry points:
 *   runDoctor(options)            → run every check, get a DoctorReport
 *   renderDoctorReport(report)    → the human view (returns a string)
 *   doctorReportJson(report)      → redacted JSON, for support tooling
 *   doctorReportBundle(report)    → the redacted file a user attaches to a ticket
 *
 * The safety rules every check obeys are written down in types.ts; the redaction
 * rule the report obeys is written down in report.ts. Read those two before
 * adding a check.
 */
export { runDoctor, resolveDoctorContext, DOCTOR_GROUPS } from "./run.js";
export { renderDoctorReport } from "./render.js";
export type { RenderOptions } from "./render.js";
export { doctorReportBundle, doctorReportJson, redactDoctorReport } from "./report.js";
export { HELP_URL } from "./types.js";
export type {
  CheckResult,
  CheckVerdict,
  DoctorCheckGroup,
  DoctorContext,
  DoctorFacts,
  DoctorFactValue,
  DoctorOptions,
  DoctorReport,
  DoctorSummary,
  DoctorTokenVault,
} from "./types.js";
