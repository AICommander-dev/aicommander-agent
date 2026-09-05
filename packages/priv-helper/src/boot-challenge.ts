// Per-boot random nonce ("boot challenge"). The relay binds it into every
// capability (claims.helperInstanceId) and the helper REQUIRES the match, so a
// capability minted before this helper's last restart (or for another helper) is
// rejected.

import { randomBytes } from "node:crypto";

/** Generate a fresh, unguessable boot id (hex). Called once at helper start. */
export function generateBootId(): string {
  return randomBytes(16).toString("hex");
}
