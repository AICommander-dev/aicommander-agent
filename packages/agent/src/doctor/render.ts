import chalk from "chalk";
import { HELP_URL, type CheckResult, type CheckVerdict, type DoctorReport } from "./types.js";

/**
 * The renderer. It is the ONLY thing in this directory that knows what a verdict
 * looks like, which is what lets the tray (W2.2) and the privileged helper's own
 * `doctor` verb (W2.3) present the same checks their own way without any of the
 * check code moving.
 *
 * Returns a STRING rather than printing. The report bundle embeds the same
 * rendering with colour off, so the file a user attaches reads exactly like the
 * output they were looking at when they decided to send it.
 *
 * ── HOW IT DECIDES WHAT TO SAY ───────────────────────────────────────────────
 * Everything is listed, including the `ok` lines: "we checked, and it is fine"
 * is what makes the failures mean something, and a report that only listed
 * problems could not be used to rule anything out. Remedies print only where
 * there is something to do, and the failures are repeated in a summary at the
 * end — the one part a user will actually read before pasting.
 */

const MARKS: Record<CheckVerdict, string> = {
  ok: "✓",
  warn: "⚠",
  fail: "✗",
  skipped: "–",
};

const WORDS: Record<CheckVerdict, string> = {
  ok: "OK",
  warn: "WARN",
  fail: "FAIL",
  skipped: "SKIP",
};

export interface RenderOptions {
  /** ANSI colour. Off for files and for anything that is not a terminal. */
  color?: boolean;
  /** Print each check's structured facts. */
  verbose?: boolean;
}

function paint(color: boolean, verdict: CheckVerdict, text: string): string {
  if (!color) return text;
  switch (verdict) {
    case "ok":
      return chalk.green(text);
    case "warn":
      return chalk.yellow(text);
    case "fail":
      return chalk.red(text);
    case "skipped":
      return chalk.gray(text);
  }
}

function renderCheck(check: CheckResult, opts: Required<RenderOptions>): string[] {
  const lines: string[] = [];
  const head = `  ${MARKS[check.verdict]}  ${check.title} — ${check.detail}`;
  lines.push(paint(opts.color, check.verdict, head));
  if (check.remedy) {
    lines.push(opts.color ? chalk.gray(`       → ${check.remedy}`) : `       → ${check.remedy}`);
  }
  if (opts.verbose && check.facts) {
    for (const [key, value] of Object.entries(check.facts)) {
      if (value === null || value === "") continue;
      const line = `       ${key}: ${String(value)}`;
      lines.push(opts.color ? chalk.gray(line) : line);
    }
  }
  return lines;
}

export function renderDoctorReport(report: DoctorReport, options: RenderOptions = {}): string {
  const opts: Required<RenderOptions> = { color: options.color ?? false, verbose: options.verbose ?? false };
  const lines: string[] = [];

  lines.push("");
  lines.push(
    opts.color
      ? chalk.bold.cyan(`  AI Commander — diagnostics (agent ${report.agentVersion}, ${report.platform}/${report.arch})`)
      : `  AI Commander — diagnostics (agent ${report.agentVersion}, ${report.platform}/${report.arch})`,
  );
  lines.push("");

  for (const check of report.checks) lines.push(...renderCheck(check, opts));

  const failures = report.checks.filter((c) => c.verdict === "fail");
  const warnings = report.checks.filter((c) => c.verdict === "warn");
  lines.push("");
  const counts =
    `  ${report.summary.ok} OK · ${report.summary.warn} ${WORDS.warn} · ` +
    `${report.summary.fail} ${WORDS.fail} · ${report.summary.skipped} ${WORDS.skipped}`;
  lines.push(opts.color ? chalk.bold(counts) : counts);

  if (failures.length > 0) {
    lines.push("");
    const heading = "  What is wrong:";
    lines.push(opts.color ? chalk.bold.red(heading) : heading);
    for (const check of failures) {
      lines.push(`    • ${check.title}: ${check.detail}`);
      if (check.remedy) lines.push(`      ${check.remedy}`);
    }
    lines.push("");
    lines.push(`  If any of this mentions security software, start here: ${HELP_URL}`);
    lines.push("  Then re-run with --report <path> and attach the file to your support case.");
  } else if (warnings.length > 0) {
    lines.push("");
    const heading = "  Nothing is broken. Worth knowing:";
    lines.push(opts.color ? chalk.bold.yellow(heading) : heading);
    for (const check of warnings) lines.push(`    • ${check.title}: ${check.detail}`);
  } else {
    lines.push("");
    lines.push("  Nothing to report — every check that could run, passed.");
  }
  lines.push("");
  return lines.join("\n");
}
