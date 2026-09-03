import { readState } from "../../state.js";
import { loadOrCreateDevice } from "../../device.js";
import { fetchAdmins, orderAdmins } from "../../device-admin.js";
import { ui, requireRoot } from "../ui.js";

/** Resolve the relay URL the running service registered with (state → env → default). */
async function resolveServerUrl(): Promise<string> {
  const state = await readState();
  return state?.serverUrl ?? process.env["AICOMMANDER_SERVER"] ?? "https://aicommander.dev";
}

export async function cmdListAdmins(): Promise<void> {
  requireRoot();
  const serverUrl = await resolveServerUrl();
  const device = loadOrCreateDevice();

  let result;
  try {
    result = await fetchAdmins(serverUrl, device);
  } catch (err) {
    ui.error((err as Error).message);
    process.exitCode = 1;
    return;
  }

  if (result.admins.length === 0) {
    ui.header("Linked accounts");
    ui.info("None", "no accounts are linked to this device");
    ui.blank();
    return;
  }

  // Single continuous numbering across active + blocked so a list number means
  // the same thing in block-admin / unblock-admin.
  const ordered = orderAdmins(result.admins);
  const fmt = (a: (typeof ordered)[number], i: number) => {
    const num = String(i + 1).padStart(2, " ");
    const linked = a.linkedAt.slice(0, 10);
    ui.info(`${num}. ${a.maskedEmail}`, `${a.alias}  ·  linked ${linked}  ·  id ${a.userId.slice(0, 8)}…`);
  };

  const active = ordered.filter((a) => !a.blocked);
  const blocked = ordered.filter((a) => a.blocked);

  ui.header("Linked accounts");
  active.forEach((a) => fmt(a, ordered.indexOf(a)));
  if (active.length === 0) ui.info("None active", "every linked account is blocked");
  ui.blank();

  if (blocked.length > 0) {
    ui.header("Blocked");
    blocked.forEach((a) => fmt(a, ordered.indexOf(a)));
    ui.blank();
  }

  ui.step("Block one with:   aicommander-agent block-admin <number|id>");
  if (blocked.length > 0) {
    ui.step("Unblock one with: aicommander-agent unblock-admin <number|id>");
  }
  ui.blank();
}
