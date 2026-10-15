import type { RemoteOperator } from "@aicommander/protocol";
import { fetchAdmins, type AdminsResult } from "./device-admin.js";
import { loadOrCreateDevice, type DeviceIdentity } from "./device.js";

export const JOB_NOTICE_ID_ENV = "AICOMMANDER_JOB_NOTICE_ID";
export const JOB_NOTICE_OPERATOR_ENV = "AICOMMANDER_JOB_NOTICE_OPERATOR";
export const JOB_NOTICE_STARTED_ENV = "AICOMMANDER_JOB_NOTICE_STARTED";
export const UNKNOWN_OPERATOR = "Account unavailable";
export const JOB_NOTICE_ACCOUNTS_TTL_MS = 5 * 60 * 1000;
type AdminsProvider = () => Promise<AdminsResult>;
type AccountsCache = { expiresAt: number; result: Promise<AdminsResult | null> };
const providerCaches = new WeakMap<AdminsProvider, AccountsCache>();
const defaultProviders = new Map<string, AdminsProvider>();

/** Stable banner-only provider across reconnects; device rotation gets a fresh cache. */
export function jobNoticeAdminsProvider(serverUrl: string, device: DeviceIdentity): AdminsProvider {
  const key = JSON.stringify([serverUrl, device.deviceId, device.deviceSecret]);
  let provider = defaultProviders.get(key);
  if (!provider) {
    provider = () => fetchAdmins(serverUrl, device);
    defaultProviders.set(key, provider);
  }
  return provider;
}

/** Share one request across users/jobs; failures also back off to protect device API quota. */
function cachedAccounts(provider: AdminsProvider): Promise<AdminsResult | null> {
  const previous = providerCaches.get(provider);
  if (previous && Date.now() < previous.expiresAt) return previous.result;
  const entry: AccountsCache = {
    expiresAt: Infinity,
    result: Promise.resolve().then(provider).catch(() => null).finally(() => {
      entry.expiresAt = Date.now() + JOB_NOTICE_ACCOUNTS_TTL_MS;
    }),
  };
  providerCaches.set(provider, entry);
  return entry.result;
}

/** These strings are expanded by cmd: exclude operators, expansions and controls. */
export function safeJobNoticeText(value: string): string {
  return value.replace(/[^a-zA-Z0-9 @.*_+:\-]/g, "?").slice(0, 160);
}

export function formatJobStartedAt(timestamp: number): string {
  const date = new Date(timestamp);
  if (!Number.isFinite(date.getTime())) return "Time unavailable";
  const pad = (value: number) => String(value).padStart(2, "0");
  const offset = -date.getTimezoneOffset();
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ` +
    `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())} ` +
    `UTC${offset >= 0 ? "+" : "-"}${pad(Math.floor(Math.abs(offset) / 60))}:${pad(Math.abs(offset) % 60)}`;
}

export function setJobNoticeEnv(env: NodeJS.ProcessEnv, jobId: string, operator: string, startedAt: number): void {
  for (const key of Object.keys(env)) {
    if ([JOB_NOTICE_ID_ENV, JOB_NOTICE_OPERATOR_ENV, JOB_NOTICE_STARTED_ENV].includes(key.toUpperCase())) delete env[key];
  }
  env[JOB_NOTICE_ID_ENV] = safeJobNoticeText(jobId);
  env[JOB_NOTICE_OPERATOR_ENV] = safeJobNoticeText(operator);
  env[JOB_NOTICE_STARTED_ENV] = formatJobStartedAt(startedAt);
}

/** Relay operator ids and server-masked emails only; never the machine alias. */
export async function resolveJobOperator(
  operator: RemoteOperator | undefined,
  serverUrl: string,
  listAdmins?: AdminsProvider,
): Promise<string> {
  if (!operator) return UNKNOWN_OPERATOR;
  if (operator.anonymous) return "Anonymous user";
  const result = await cachedAccounts(listAdmins ?? jobNoticeAdminsProvider(serverUrl, loadOrCreateDevice()));
  return result?.admins.find((entry) => entry.userId === operator.id)?.maskedEmail || UNKNOWN_OPERATOR;
}

/** Identity is optional decoration: a slow relay must not hold up a job. */
export async function boundedJobOperator(resolve?: () => Promise<string>, timeoutMs = 750): Promise<string> {
  if (!resolve) return UNKNOWN_OPERATOR;
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      Promise.resolve().then(resolve).catch(() => UNKNOWN_OPERATOR),
      new Promise<string>((done) => { timer = setTimeout(() => done(UNKNOWN_OPERATOR), timeoutMs); }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}
