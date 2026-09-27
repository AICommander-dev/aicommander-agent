import { readState } from "../../state.js";
import { loadOrCreateDevice } from "../../device.js";
import {
  fetchAdmins,
  blockAdmin,
  unblockAdmin,
  orderAdmins,
  resolveAdminIdentifier,
} from "../../device-admin.js";
import { ui, requireRoot } from "../ui.js";

async function resolveServerUrl(): Promise<string> {
  const state = await readState();
  return state?.serverUrl ?? process.env["AICOMMANDER_SERVER"] ?? "https://aicommander.dev";
}

/**
 * Shared driver for block / unblock: fetch the listing, resolve the user-typed
 * identifier against the SAME ordering `list-admins` prints, then call the relay.
 */
async function runBlockAction(identifier: string, action: "block" | "unblock"): Promise<void> {
  requireRoot();
  const serverUrl = await resolveServerUrl();
  const device = loadOrCreateDevice();

  let listing;
  try {
    listing = await fetchAdmins(serverUrl, device);
  } catch (err) {
    ui.error((err as Error).message);
    process.exitCode = 1;
    return;
  }

  const ordered = orderAdmins(listing.admins);
  const resolved = resolveAdminIdentifier(ordered, identifier);
  if (resolved.kind === "not_found") {
    ui.error(`No linked account matches "${identifier}".`);
    ui.info("See options", "aicommander-agent list-admins");
    process.exitCode = 1;
    return;
  }
  if (resolved.kind === "ambiguous") {
    ui.error(`"${identifier}" is ambiguous — it matches ${resolved.matches.length} accounts.`);
    ui.info("Disambiguate", "use the list number or a longer id");
    process.exitCode = 1;
    return;
  }

  const admin = resolved.admin;
  const res =
    action === "block"
      ? await blockAdmin(serverUrl, device, admin.userId)
      : await unblockAdmin(serverUrl, device, admin.userId);

  if (res.ok) {
    if (action === "block") {
      ui.ok(`Blocked ${admin.maskedEmail} (${admin.alias}).`);
      ui.info("Note", "their access is cut off; run unblock-admin anytime to restore it");
    } else {
      ui.ok(`Unblocked ${admin.maskedEmail} (${admin.alias}) — access restored.`);
    }
  } else if (res.error === "not_found") {
    ui.warn(
      action === "block"
        ? "That account isn't linked (or is already blocked)."
        : "That account isn't blocked.",
    );
  } else {
    ui.error(res.message ?? `Failed to ${action} the account.`);
    process.exitCode = 1;
  }
  ui.blank();
}

export function cmdBlockAdmin(identifier: string): Promise<void> {
  return runBlockAction(identifier, "block");
}

export function cmdUnblockAdmin(identifier: string): Promise<void> {
  return runBlockAction(identifier, "unblock");
}
