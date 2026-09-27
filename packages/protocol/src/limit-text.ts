// Rendering the LIMITS in constants.ts the way the published texts state them.
//
// A dozen user-facing surfaces — MCP tool and argument descriptions, the stdio
// bridge's `--help`, relay error messages — quote these caps as prose: "1 MiB",
// "256 KiB", "1 hour", "24 hours", "a one-hour download link". Where the number
// was typed out by hand, changing the constant turned the sentence into a
// confident lie, and a wrong NUMBER is not wording drift: it changes what an AI
// client or an operator does. These helpers exist so every such sentence derives
// BOTH halves — the raw count and the human unit — from the constant itself.
//
// They render only the shapes the surfaces already use; they are not a general
// humanize-any-quantity library. Anything they cannot express falls back to a
// plain count so a rendering never silently drops the unit.

const BYTE_UNITS: readonly (readonly [unit: string, size: number])[] = [
  ["GiB", 1024 ** 3],
  ["MiB", 1024 ** 2],
  ["KiB", 1024],
];

/**
 * A byte cap in the binary unit the texts use: `1 MiB`, `256 KiB`, `100 MiB`.
 *
 * Only an EXACT multiple of a unit is rendered in it, so a cap that stops being
 * a round number reads as its byte count rather than as a rounded-off figure the
 * caller would then fail to reproduce.
 */
export function formatBytes(bytes: number): string {
  for (const [unit, size] of BYTE_UNITS) {
    if (bytes >= size && bytes % size === 0) return `${bytes / size} ${unit}`;
  }
  return `${bytes} bytes`;
}

// Every duration unit in three widths, because the surfaces genuinely use all
// three: prose says "1 hour", an argument description says "(1 hr)", and the
// bridge's `--help` column says "1 h hard kill".
const DURATION_UNITS: readonly (readonly [
  long: string,
  short: string,
  symbol: string,
  ms: number,
])[] = [
  ["day", "d", "d", 24 * 60 * 60 * 1000],
  ["hour", "hr", "h", 60 * 60 * 1000],
  ["minute", "min", "min", 60 * 1000],
  ["second", "s", "s", 1000],
];

interface DurationSplit {
  readonly count: number;
  readonly long: string;
  readonly short: string;
  readonly symbol: string;
}

/**
 * The unit a caller pins a rendering to.
 *
 * Needed because the surfaces do not all reduce to the largest whole unit: a
 * blob's 24-hour TTL is stated as "24 hours" everywhere, never as "1 day", and
 * a rendering that silently reworded it would be exactly the change these
 * helpers exist to avoid.
 */
export type DurationUnit = "day" | "hour" | "minute" | "second";

/** `ms` in `unit`, or — with no unit — in the largest one it divides into wholly. */
function splitDuration(ms: number, unit?: DurationUnit): DurationSplit | null {
  for (const [long, short, symbol, size] of DURATION_UNITS) {
    if (unit ? long !== unit : !(ms >= size)) continue;
    if (ms % size === 0) return { count: ms / size, long, short, symbol };
  }
  return null;
}

/** A duration as the texts spell it out: `1 hour`, `24 hours`, `7 days`. */
export function formatDuration(ms: number, unit?: DurationUnit): string {
  const split = splitDuration(ms, unit);
  if (!split) return `${ms} ms`;
  return `${split.count} ${split.long}${split.count === 1 ? "" : "s"}`;
}

/** A duration in the abbreviated form an argument description uses: `1 hr`, `5 min`. */
export function formatDurationShort(ms: number, unit?: DurationUnit): string {
  const split = splitDuration(ms, unit);
  return split ? `${split.count} ${split.short}` : `${ms} ms`;
}

/** A duration in the single-letter form the `--help` tool table uses: `1 h`. */
export function formatDurationSymbol(ms: number, unit?: DurationUnit): string {
  const split = splitDuration(ms, unit);
  return split ? `${split.count} ${split.symbol}` : `${ms} ms`;
}

const COUNT_WORDS = [
  "zero", "one", "two", "three", "four", "five", "six", "seven", "eight",
  "nine", "ten", "eleven", "twelve",
] as const;

/**
 * A duration written out as words, for the grammatical slots the texts use it
 * in: a noun phrase (`one hour`); hyphenated, an adjective before a noun (`a
 * one-hour download link` — where English keeps the unit singular); and with the
 * count shouted for emphasis (`stops working after ONE hour`).
 *
 * Counts past twelve fall back to digits, which is what the same sentence would
 * be written with by hand anyway.
 */
export function formatDurationWords(
  ms: number,
  options?: { hyphenate?: boolean; upperCount?: boolean; unit?: DurationUnit },
): string {
  const split = splitDuration(ms, options?.unit);
  if (!split) return `${ms} ms`;
  const word = COUNT_WORDS[split.count] ?? String(split.count);
  const count = options?.upperCount ? word.toUpperCase() : word;
  if (options?.hyphenate) return `${count}-${split.long}`;
  return `${count} ${split.long}${split.count === 1 ? "" : "s"}`;
}
