import fs from "node:fs";
import {
  isJobUnknownReason,
  JOB_LIST_DEFAULT_ENTRIES,
  JOB_LOGS_DEFAULT_TAIL_LINES,
  JOB_LOGS_MAX_SLICE_BYTES,
  JOB_MAX_GPU_INDEX,
  JOB_MAX_LOG_BYTES,
  JOB_WIRE_MAX_COMMAND_CHARS,
  JOB_WIRE_MAX_LIST_ENTRIES,
  JOB_WIRE_MAX_NAME_CHARS,
  MAX_EPOCH_MS,
} from "@aicommander/protocol";
import type { JobRpcResult, JobSummary } from "@aicommander/protocol";
import { LOG_FILE, type JobStore } from "./job-store.js";
import type { JobLogsRequest, JobMeta } from "./job-types.js";

const MAX_JOB_NAME_LENGTH = 64;
const TRUNCATION_NOTICE =
  "\n[aicommander] output.log reached its size limit; nothing past this point is served. The job itself was not stopped.\n";

export function normalizeName(value: unknown, jobId: string): string {
  const fallback = `job-${jobId.slice(0, 8)}`;
  if (typeof value !== "string") return fallback;
  // eslint-disable-next-line no-control-regex
  const cleaned = value.replace(/[\u0000-\u001f\u007f]/g, " ").trim().slice(0, MAX_JOB_NAME_LENGTH);
  return cleaned === "" ? fallback : cleaned;
}

export function clampListLimit(requested: unknown): number {
  if (!isNonNegativeNumber(requested) || requested < 1) return JOB_LIST_DEFAULT_ENTRIES;
  return Math.min(Math.floor(requested), JOB_WIRE_MAX_LIST_ENTRIES);
}

export function readJobLogs(store: JobStore, meta: JobMeta, req: JobLogsRequest): JobRpcResult {
  const logPath = store.logPath(meta.jobId);
  const size = Math.min(
    store.fileStat(meta.jobId, LOG_FILE)?.size ?? 0,
    meta.truncatedAt ?? Number.MAX_SAFE_INTEGER,
  );
  const maxBytes = clampSliceBytes(req.maxBytes);
  let start: number;
  if (isNonNegativeNumber(req.offsetBytes)) {
    start = Math.min(Math.floor(req.offsetBytes), size);
  } else {
    const tailLines = clampTailLines(req.tailLines);
    const windowStart = Math.max(0, size - maxBytes);
    const window = readRange(logPath, windowStart, size - windowStart);
    start = windowStart + offsetOfLastLines(window, tailLines);
  }
  const chunk = readRange(logPath, start, Math.min(maxBytes, Math.max(0, size - start)));
  const nextOffsetBytes = start + chunk.length;
  return {
    ok: true,
    kind: "logs",
    logs: {
      jobId: meta.jobId,
      chunk: chunk.toString("base64"),
      offsetBytes: start,
      nextOffsetBytes,
      eof: nextOffsetBytes >= size,
      truncated: meta.truncatedAt !== null,
    },
  };
}

/** Caps bytes served to callers; it never stops or truncates the writer. */
export function checkLogCap(
  store: JobStore,
  meta: JobMeta,
  persist: (meta: JobMeta) => void,
): void {
  if (meta.truncatedAt !== null) return;
  const logPath = store.logPath(meta.jobId);
  const size = store.fileStat(meta.jobId, LOG_FILE)?.size ?? 0;
  if (size < JOB_MAX_LOG_BYTES) return;
  let noticeBytes = 0;
  try {
    fs.appendFileSync(logPath, TRUNCATION_NOTICE);
    noticeBytes = Buffer.byteLength(TRUNCATION_NOTICE, "utf8");
  } catch {
    // The boundary still applies even when its explanatory notice cannot land.
  }
  meta.truncatedAt = Math.min(size, JOB_MAX_LOG_BYTES) + noticeBytes;
  persist(meta);
}

/** The sole projection from permissive disk records to strict wire summaries. */
export function toSummary(store: JobStore, meta: JobMeta, includeCommand: boolean): JobSummary {
  const size = store.fileStat(meta.jobId, LOG_FILE)?.size ?? 0;
  const truncatedAt = wireByteCount(meta.truncatedAt);
  return {
    jobId: meta.jobId,
    name: wireBoundedString(meta.name, JOB_WIRE_MAX_NAME_CHARS),
    status: meta.status,
    exitCode: wireInteger(meta.exitCode),
    startedAt: wireEpochMs(meta.startedAt) ?? 0,
    endedAt: wireEpochMs(meta.endedAt),
    ...(meta.endedAtApproximate === true && wireEpochMs(meta.endedAt) !== null
      ? { endedAtApproximate: true }
      : {}),
    ...(meta.status === "unknown" && isJobUnknownReason(meta.unknownReason)
      ? { unknownReason: meta.unknownReason }
      : {}),
    gpuIndex: wireGpuIndex(meta.gpuIndex),
    logBytes: truncatedAt !== null
      ? Math.min(wireByteCount(size) ?? 0, truncatedAt)
      : wireByteCount(size) ?? 0,
    truncated: meta.truncatedAt !== null,
    ...(includeCommand
      ? { command: wireBoundedString(meta.command, JOB_WIRE_MAX_COMMAND_CHARS) }
      : {}),
  };
}

function wireBoundedString(value: unknown, maxChars: number): string {
  if (typeof value !== "string") return "";
  if (value.length <= maxChars) return value;
  const cut = value.slice(0, maxChars);
  const last = cut.charCodeAt(cut.length - 1);
  return last >= 0xd800 && last <= 0xdbff ? cut.slice(0, -1) : cut;
}

function wireInteger(value: number | null): number | null {
  return typeof value === "number" && Number.isSafeInteger(value) ? value : null;
}

function wireEpochMs(value: number | null): number | null {
  if (typeof value !== "number" || !Number.isFinite(value)) return null;
  const ms = Math.round(value);
  return Number.isSafeInteger(ms) && Math.abs(ms) <= MAX_EPOCH_MS ? ms : null;
}

function wireGpuIndex(value: number | null): number | null {
  return typeof value === "number" &&
    Number.isSafeInteger(value) &&
    value >= 0 &&
    value <= JOB_MAX_GPU_INDEX
    ? value
    : null;
}

function wireByteCount(value: number | null): number | null {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : null;
}

function readRange(target: string, position: number, length: number): Buffer {
  if (length <= 0) return Buffer.alloc(0);
  let fd: number | null = null;
  try {
    fd = fs.openSync(target, "r");
    const buffer = Buffer.alloc(length);
    const read = fs.readSync(fd, buffer, 0, length, position);
    return buffer.subarray(0, read);
  } catch {
    return Buffer.alloc(0);
  } finally {
    if (fd !== null) {
      try {
        fs.closeSync(fd);
      } catch {
        // Nothing useful can be done after a failed close.
      }
    }
  }
}

function offsetOfLastLines(window: Buffer, lines: number): number {
  let end = window.length;
  if (end > 0 && window[end - 1] === 0x0a) end--;
  let seen = 0;
  for (let i = end - 1; i >= 0; i--) {
    if (window[i] !== 0x0a) continue;
    seen++;
    if (seen === lines) return i + 1;
  }
  return 0;
}

function isNonNegativeNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0;
}

function clampSliceBytes(requested: unknown): number {
  if (!isNonNegativeNumber(requested) || requested < 1) return JOB_LOGS_MAX_SLICE_BYTES;
  return Math.min(Math.floor(requested), JOB_LOGS_MAX_SLICE_BYTES);
}

function clampTailLines(requested: unknown): number {
  if (!isNonNegativeNumber(requested) || requested < 1) return JOB_LOGS_DEFAULT_TAIL_LINES;
  return Math.floor(requested);
}
