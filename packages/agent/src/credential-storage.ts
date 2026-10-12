/** Thrown when root-exec credentials cannot be persisted in strict (service) mode. */
export class CredentialStorageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CredentialStorageError";
  }
}

/**
 * Production/service installs must fail closed when session or runtime state
 * cannot be written with owner-only permissions. Dev and ad-hoc foreground runs
 * keep the previous best-effort behavior.
 */
export function isStrictCredentialStorage(): boolean {
  if (process.env["AICOMMANDER_SERVICE"] === "1") return true;
  if (process.env["NODE_ENV"] === "production") return true;
  // systemd sets these for supervised units (see run.ts code-display gate).
  if (process.env["INVOCATION_ID"]) return true;
  if (process.env["JOURNAL_STREAM"]) return true;
  return false;
}

export function enforceCredentialStorageWrite(label: string, err: unknown): never {
  const detail = err instanceof Error ? err.message : String(err);
  throw new CredentialStorageError(
    `Failed to persist ${label} with required filesystem permissions: ${detail}`,
  );
}
