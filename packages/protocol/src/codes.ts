// High-entropy session codes. The old word+number scheme (~16.5 bits, Math.random)
// was brute-forceable; this replaces it with a CSPRNG-backed random string.
//
// Format: AIC-XXXX-XXXX-XXXX — three groups of 4 chars (12 random chars total).
// Alphabet: Crockford-style base32 minus ambiguous letters (no I, L, O, U) — 22
// letters + 10 digits = 32 symbols. 12 chars over 32 symbols = log2(32^12) = 60
// bits of entropy — infeasible to brute-force. (With 32 symbols REJECTION_THRESHOLD
// below is 256, so the modulo-bias rejection branch is inert but harmless.)
const ALPHABET = "ABCDEFGHJKMNPQRSTVWXYZ0123456789";
const CODE_LENGTH = 12;
const GROUP_SIZE = 4;

// Largest multiple of ALPHABET.length that fits in a byte (0..255). Random bytes
// at or above this are rejected so every symbol is equally likely (no modulo bias).
const REJECTION_THRESHOLD = Math.floor(256 / ALPHABET.length) * ALPHABET.length;

function randomChars(count: number): string {
  let out = "";
  while (out.length < count) {
    const bytes = new Uint8Array(count - out.length);
    crypto.getRandomValues(bytes);
    for (const byte of bytes) {
      if (byte >= REJECTION_THRESHOLD) continue; // reject to avoid modulo bias
      out += ALPHABET[byte % ALPHABET.length];
      if (out.length === count) break;
    }
  }
  return out;
}

export function generateSessionCode(): string {
  const chars = randomChars(CODE_LENGTH);
  const groups: string[] = [];
  for (let i = 0; i < CODE_LENGTH; i += GROUP_SIZE) {
    groups.push(chars.slice(i, i + GROUP_SIZE));
  }
  return `AIC-${groups.join("-")}`;
}

const SESSION_CODE_RE = /^AIC-[ABCDEFGHJKMNPQRSTVWXYZ0-9]{4}-[ABCDEFGHJKMNPQRSTVWXYZ0-9]{4}-[ABCDEFGHJKMNPQRSTVWXYZ0-9]{4}$/;

export function isValidSessionCode(code: string): boolean {
  // Codes are minted UPPERCASE but the alphabet (Crockford-style base32) is
  // case-insensitive by design, so accept any case here. Canonicalizing before
  // the test keeps the account path (which uses this to tell a code apart from a
  // saved alias) and `sessionId` keying in agreement for lowercase input.
  return SESSION_CODE_RE.test(code.trim().toUpperCase());
}

/**
 * Mask a session code for display: reveal only the `AIC-` prefix and the first
 * group, replacing the remaining two groups with `***`
 * (`AIC-7K3P-WX9M-RTBN` → `AIC-7K3P-***-***`). The code is a root-exec
 * credential, so it should never sit in plain sight in logs, status output, or a
 * tray label where a screenshot or screen-share would leak it — the full value
 * is only ever exposed deliberately (copy button / explicit reveal command).
 *
 * Non-code strings (and anything not matching the canonical format) are returned
 * unchanged so callers can pass through "—"/placeholder values safely.
 */
export function maskSessionCode(code: string): string {
  if (!isValidSessionCode(code)) return code;
  const firstGroup = code.slice(4, 8); // after "AIC-"
  return `AIC-${firstGroup}-***-***`;
}

/**
 * The first TWO (non-secret) chars of a session code, normalized UPPERCASE — the
 * two distinguishing chars right after the shared `AIC-` prefix
 * (`AIC-7k3p-wx9m-rtbn` → `7K`). This is the only part of a code we ever persist
 * or show back to a user (as a fingerprint that lets them tell their machines
 * apart); at ~10 bits it's kept deliberately minimal so a storage leak reveals as
 * little as possible while still letting a user pair a machine's alias with the
 * code they typed — the remaining ten chars stay secret, so the value can never be
 * brute-completed into the full root-exec credential. Returns `null` for anything
 * that isn't a canonical code.
 */
export function sessionCodePrefix(code: string): string | null {
  if (!isValidSessionCode(code)) return null;
  return code.trim().toUpperCase().slice(4, 6); // first two chars, after "AIC-"
}
