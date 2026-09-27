import chalk from "chalk";
import readline from "node:readline";

export const ui = {
  header: (msg: string) => console.log(chalk.bold.cyan(`\n  ${msg}\n`)),
  ok:     (msg: string) => console.log(chalk.green(`  ✓  ${msg}`)),
  warn:   (msg: string) => console.log(chalk.yellow(`  ⚠  ${msg}`)),
  error:  (msg: string) => console.error(chalk.red(`  ✗  ${msg}`)),
  info:   (key: string, val: string) =>
    console.log(`  ${chalk.gray(key.padEnd(14))}  ${chalk.white(val)}`),
  step:   (msg: string) => console.log(chalk.gray(`  ${msg}`)),
  blank:  () => console.log(),
};

export function requireRoot(): void {
  if (process.getuid?.() !== 0) {
    ui.error("This command must be run as root.");
    console.error(chalk.gray("  Re-run with: sudo aicommander-agent <command>"));
    process.exit(1);
  }
}

/**
 * Yes/no prompt. Returns false when stdin isn't a TTY (so scripted callers must
 * pass an explicit --yes flag rather than hanging or silently proceeding).
 */
export async function confirm(question: string): Promise<boolean> {
  if (!process.stdin.isTTY) return false;
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  try {
    const answer = await new Promise<string>((resolve) =>
      rl.question(`  ${question} [y/N] `, resolve),
    );
    return /^y(es)?$/i.test(answer.trim());
  } finally {
    rl.close();
  }
}
