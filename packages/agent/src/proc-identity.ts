import { execFileSync } from "node:child_process";
import fs from "node:fs";

/**
 * Process identity — telling the process that holds a pid TODAY apart from the
 * one that held it when we wrote the pid down.
 *
 * A pid on its own is not an identity: pid counters wrap, and a job manager that
 * records a pid and asks `kill(pid, 0)` about it later is asking "is SOMETHING
 * running", not "is my job running". Getting that wrong twice over is what makes
 * it worth its own module: a status call would adopt a stranger's process, and a
 * cancel — which signals a process GROUP, often as root — would kill a stranger's
 * process TREE.
 *
 * The distinguishing property is the process START TIME, which a recycled pid
 * cannot reproduce. Every platform exposes it somewhere; the cost differs by two
 * orders of magnitude, which is why callers are told whether an answer is
 * missing rather than being given a default.
 *
 * The token is CANONICAL, not the probe's raw rendering, and callers compare it
 * through {@link compareProcIdentity}, never by raw string equality. The raw
 * renderings are not stable for a fixed process: Windows answers in wmic's CIM
 * form or PowerShell's ISO form depending on which backend happened to work
 * (wmic is removed on recent builds and can fail transiently), and macOS's
 * `ps -o lstart=` prints wall time, which a timezone change — or the
 * twice-yearly DST transition, well inside the lifetime of a training job —
 * re-renders differently for the same start instant. A raw-string comparison
 * then reads "different process" for OUR OWN process: a confident, wrong "gone"
 * that releases a GPU lock under a live job. So every wall-clock rendering is
 * normalised to the epoch instant it names at capture AND at check.
 *
 * How that normalisation is allowed to happen differs by what the rendering
 * carries. The Windows forms carry an EXPLICIT UTC offset, so applying it needs
 * no zone at all: those become `epoch:<ms>`. macOS's lstart carries none, and a
 * previous fix inverted it as local time on the premise that ps and this
 * process share a zone. They do not have to: ps is a fresh process reading the
 * CURRENT system zone, while this agent is long-running and Node caches
 * /etc/localtime at startup (only a changed TZ env var is re-read). After a
 * system zone change — or inside a DST fall-back hour, where one local stamp
 * names two instants — the inversion is confidently wrong, which is the exact
 * shape of answer no downstream guard can catch. So the macOS probe now removes
 * the zone from BOTH sides instead: ps is pinned to TZ=UTC and the stamp is
 * parsed as UTC, where no offset applies and no hour ever repeats. That token
 * is `utc:<ms>` — a deliberately DIFFERENT kind from `epoch:<ms>`, because a
 * macOS `epoch:` token still on disk was minted through the local inversion and
 * may be shifted by exactly the skew this removes; comparing the two kinds
 * could call our own live job "gone", so cross-kind is always `unverifiable`
 * (a hold), never a verdict. Linux keeps its /proc start-ticks as bare digits —
 * boot-relative, no wall clock involved, already canonical, and byte-compatible
 * with every record on disk.
 */

/**
 * Hard timeout on an identity probe. A wedged `ps`/WMI must never stall an RPC
 * the relay is waiting on; a probe that times out is simply "we do not know".
 */
const PROC_PROBE_TIMEOUT_MS = 5_000;

/**
 * A token that distinguishes the process CURRENTLY holding `pid` from any later
 * process that inherits the same number, or null when this platform will not
 * tell us. Null is never a match — it means the caller must decide how to fail.
 *
 * Called at spawn and again on every liveness check, so cost matters: Linux is a
 * file read, macOS one `ps` (~2 ms), and Windows a WMI/CIM query — the one that
 * is genuinely expensive, and the reason a Windows READ is allowed to settle for
 * bare liveness.
 */
export function readProcIdentity(pid: number): string | null {
  if (!Number.isInteger(pid) || pid <= 0) return null;
  if (process.platform === "linux") return readProcStartTicks(pid);
  if (process.platform === "darwin") return readBsdStartTime(pid);
  if (process.platform === "win32") return readWindowsCreationDate(pid);
  return null;
}

/**
 * How a captured identity relates to the one read just now.
 *
 * `unverifiable` is the load-bearing third answer: a token either side of the
 * comparison that cannot be parsed — a record written by the pre-canonical
 * format still on disk, a truncated or hand-edited value — proves NOTHING about
 * the process, and must never be allowed to masquerade as a mismatch. A false
 * mismatch is a confident "gone", and "gone" is what releases GPU locks and
 * refuses cancels; "unverifiable" merely holds. Tokens of different KINDS are
 * also unverifiable rather than a mismatch. Ticks vs an instant kind can only
 * meet across a platform change or a corrupted record; `epoch:` vs `utc:` meets
 * on EVERY macOS machine on the first upgrade past the zone fix, under every
 * job that is still running — the recorded `epoch:` was minted by a local-time
 * inversion whose value may be skewed by a zone change or a DST-ambiguous hour,
 * so agreeing or disagreeing with a zone-free `utc:` probe proves nothing
 * either way. Holding those jobs until their pid itself dies is the whole point
 * of the kind split: mismatching them would re-release a live job's GPU lock —
 * the defect — for exactly the population the fix protects.
 */
export function compareProcIdentity(
  captured: string,
  current: string,
): "match" | "mismatch" | "unverifiable" {
  const a = parseIdentityToken(captured);
  const b = parseIdentityToken(current);
  if (a === null || b === null) return "unverifiable";
  if (a.kind !== b.kind) return "unverifiable";
  return a.value === b.value ? "match" : "mismatch";
}

/**
 * The three canonical token shapes, kept as strings so exact equality is exact:
 *  - bare digits — Linux start ticks since boot (also every pre-canonical Linux
 *    record, which is why Linux deliberately did not gain a prefix);
 *  - `epoch:<ms>` — a rendering with an EXPLICIT UTC offset resolved to its
 *    instant (Windows). On macOS this shape is now legacy only: it was minted
 *    by inverting an offset-less local rendering with the runtime's cached
 *    zone, so its value may be skewed and must never meet `utc:` as a verdict;
 *  - `utc:<ms>` — a zone-free instant, from a probe pinned to TZ=UTC (macOS).
 * Anything else is a legacy or damaged token.
 */
function parseIdentityToken(token: string): { kind: "ticks" | "epoch" | "utc"; value: string } | null {
  if (/^\d+$/.test(token)) return { kind: "ticks", value: token };
  const epoch = /^epoch:(\d+)$/.exec(token);
  if (epoch?.[1] !== undefined) return { kind: "epoch", value: epoch[1] };
  const utc = /^utc:(\d+)$/.exec(token);
  if (utc?.[1] !== undefined) return { kind: "utc", value: utc[1] };
  return null;
}

/**
 * Render an epoch instant as a token of the stated kind, refusing anything a
 * parser produced by accident. The kind is part of the trust story (see
 * parseIdentityToken), so the caller must say which claim it is making.
 */
function instantToken(kind: "epoch" | "utc", ms: number): string | null {
  return Number.isSafeInteger(ms) && ms > 0 ? `${kind}:${ms}` : null;
}

/**
 * /proc/<pid>/stat field 22 — the process start time in clock ticks since boot.
 * Field 2 (`comm`) is the executable name in parentheses and may itself contain
 * spaces and parentheses, so the fields are counted from the LAST `)` rather than
 * by splitting the whole line.
 */
function readProcStartTicks(pid: number): string | null {
  try {
    const raw = fs.readFileSync(`/proc/${pid}/stat`, "utf8");
    const afterComm = raw.slice(raw.lastIndexOf(")") + 1).trim();
    // The first token after `comm` is field 3, so field 22 is index 19.
    const fields = afterComm.split(/\s+/);
    const ticks = fields[19];
    return ticks !== undefined && /^\d+$/.test(ticks) ? ticks : null;
  } catch {
    return null;
  }
}

/**
 * macOS: `ps -o lstart=` prints the process start time to the second, e.g.
 * "Tue Aug  4 22:36:20 2026". One second of resolution is plenty — a pid would
 * have to be recycled onto our job within the same second AND land on the same
 * start time to be confused with it.
 *
 * The rendering carries no offset, so which zone rendered it matters — and
 * runProbe pins ps to TZ=UTC precisely so the answer is "no zone at all". The
 * earlier local-time round trip ("ps and this process share a zone") failed
 * whenever they did not: ps reads the current system zone afresh while Node
 * cached /etc/localtime at this agent's startup, and a DST fall-back hour makes
 * even a shared zone ambiguous. Under UTC neither side owns a zone and no hour
 * repeats, so the stamp is parsed as the UTC fields it literally is. The result
 * is the `utc:` kind, NOT `epoch:`: on-disk macOS `epoch:` tokens came from the
 * local inversion and may be skewed, so they must hold, not verdict, against a
 * fresh probe (see parseIdentityToken). A stamp that does not parse is "we do
 * not know", never a raw string a later probe could falsely mismatch.
 */
function readBsdStartTime(pid: number): string | null {
  const out = runProbe("/bin/ps", ["-o", "lstart=", "-p", String(pid)]);
  if (out === null) return null;
  // Collapse the column padding `ps` uses before parsing the fields.
  const stamp = out.trim().replace(/\s+/g, " ");
  if (stamp === "") return null;
  const epoch = parseBsdLstart(stamp);
  return epoch === null ? null : instantToken("utc", epoch);
}

/** C-locale month abbreviations — runProbe pins LC_ALL=C so these are what ps prints. */
const MONTHS: Record<string, number> = {
  Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5,
  Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11,
};

/** "%a %b %e %H:%M:%S %Y" with padding already collapsed, as an epoch ms, or null. */
function parseBsdLstart(stamp: string): number | null {
  const m = /^[A-Za-z]{3} ([A-Za-z]{3}) (\d{1,2}) (\d{2}):(\d{2}):(\d{2}) (\d{4})$/.exec(stamp);
  if (!m) return null;
  const month = MONTHS[m[1] as string];
  if (month === undefined) return null;
  // Date.UTC on purpose, paired with the TZ=UTC pin in runProbe: the stamp was
  // rendered under UTC, so the same rules must read it back. A local-time
  // construction here would reintroduce the runtime's CACHED zone — the very
  // asymmetry against ps's fresh zone that this parse exists to remove.
  const ms = Date.UTC(
    Number(m[6]), month, Number(m[2]),
    Number(m[3]), Number(m[4]), Number(m[5]),
  );
  return Number.isFinite(ms) ? ms : null;
}

/**
 * Windows: the process CreationDate. wmic is tried first because it is an order
 * of magnitude faster to start than PowerShell, and CIM is the fallback for the
 * builds where wmic has been removed. Null when neither is available.
 *
 * The two backends render the SAME CreationDate differently — wmic as a CIM
 * datetime (`20260805143012.123456+120`), PowerShell as ISO — and which one
 * answers can change between a job's spawn and a later check (wmic disappears
 * in an upgrade, or fails transiently). Both renderings carry an explicit UTC
 * offset, so both are resolved to the instant they name, truncated to the
 * millisecond both can express: one process, one token, whichever backend
 * answered on which day.
 */
function readWindowsCreationDate(pid: number): string | null {
  const wmic = runProbe("wmic", ["process", "where", `processid=${pid}`, "get", "CreationDate", "/value"]);
  const fromWmic = wmic?.match(/CreationDate=(\S+)/);
  if (fromWmic?.[1]) {
    const epoch = parseCimDatetime(fromWmic[1]);
    // An unparseable wmic answer is not an answer — fall through to CIM rather
    // than minting a token no later probe could ever be compared against.
    if (epoch !== null) return instantToken("epoch", epoch);
  }

  const cim = runProbe("powershell.exe", [
    "-NoProfile",
    "-NonInteractive",
    "-Command",
    `(Get-CimInstance Win32_Process -Filter "ProcessId=${pid}").CreationDate.ToString("o")`,
  ]);
  const stamp = cim?.trim();
  if (!stamp) return null;
  const epoch = parseIsoDatetime(stamp);
  return epoch === null ? null : instantToken("epoch", epoch);
}

/** CIM datetime `yyyymmddHHMMSS.ffffff±UUU` (offset in minutes) as epoch ms, or null. */
function parseCimDatetime(stamp: string): number | null {
  const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})\.(\d{6})([+-]\d{3})$/.exec(stamp);
  if (!m) return null;
  const utc = Date.UTC(
    Number(m[1]), Number(m[2]) - 1, Number(m[3]),
    Number(m[4]), Number(m[5]), Number(m[6]),
  );
  return utc + msFromFraction(m[7] as string) - Number(m[8]) * 60_000;
}

/**
 * ISO 8601 with an EXPLICIT offset as epoch ms, or null. An offset-less stamp
 * (DateTimeKind.Unspecified) names a wall time in an unknown zone — resolving
 * it with a guessed offset would rebuild the exact instability this module
 * exists to remove, so it is "we do not know".
 */
function parseIsoDatetime(stamp: string): number | null {
  const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})$/.exec(stamp);
  if (!m) return null;
  const utc = Date.UTC(
    Number(m[1]), Number(m[2]) - 1, Number(m[3]),
    Number(m[4]), Number(m[5]), Number(m[6]),
  );
  const offset = m[8] as string;
  // Sign applies to the WHOLE offset: "-00:30" is minus thirty minutes, which
  // naive `Number("-00") * 60 + Number("30")` arithmetic would get wrong.
  const offsetMinutes =
    offset === "Z"
      ? 0
      : (offset.startsWith("-") ? -1 : 1) *
        (Number(offset.slice(1, 3)) * 60 + Number(offset.slice(4, 6)));
  return utc + msFromFraction(m[7] ?? "") - offsetMinutes * 60_000;
}

/**
 * A fractional-seconds field as whole milliseconds, TRUNCATED. wmic carries six
 * digits and PowerShell's "o" seven, so digit-for-digit they can never agree;
 * the first three digits are the milliseconds both describe, exactly.
 */
function msFromFraction(fraction: string): number {
  return Number(`${fraction}000`.slice(0, 3));
}

/**
 * Run a short identity probe. Anything unexpected — a missing binary, a non-zero
 * exit because the pid is already gone, a hung tool — is null, i.e. "we do not
 * know", never a match.
 *
 * The locale is pinned to C because the macOS parse reads month NAMES back out
 * of ps's output: an LC_TIME the box happens to have set must not make our own
 * process unparseable. The zone is pinned to UTC for the same reason at one
 * remove: the macOS parse reads an offset-less wall time back out, and the
 * probe is a FRESH process whose zone (system zone, or an inherited TZ) need
 * not be the one this long-running runtime cached — the asymmetry that made
 * the same start instant round-trip to two different tokens. Under TZ=UTC the
 * stamp is zone-free and DST-free by construction. Harmless to the other
 * probes, whose renderings carry explicit offsets or no wall clock at all.
 */
function runProbe(file: string, args: string[]): string | null {
  try {
    return execFileSync(file, args, {
      encoding: "utf8",
      timeout: PROC_PROBE_TIMEOUT_MS,
      stdio: ["ignore", "pipe", "ignore"],
      windowsHide: true,
      env: { ...process.env, LC_ALL: "C", LANG: "C", TZ: "UTC" },
    });
  } catch {
    return null;
  }
}
