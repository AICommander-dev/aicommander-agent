import type WebSocket from "ws";
import type { ScreenShareProvider } from "./agent-controller.js";
import type { AgentToDoMsg, ScreenShareState, ScreenshotDisplaySelector } from "@aicommander/protocol";
import { SCREENSHOT_CHUNK_SIZE, SCREENSHOT_MAX_BYTES } from "@aicommander/protocol";

export const SCREEN_SHARE_OFF: ScreenShareState = { capable: false, enabled: false, expiresAt: null };

/**
 * Capture a screenshot and stream it back as base64 chunks. The grant is
 * re-checked here (defense in depth — the relay/MCP layer also gates it) so a
 * disabled or non-capable agent never leaks pixels. Errors are reported as a
 * single agent:screenshot_error; success ends with agent:screenshot_done.
 */
export async function streamScreenshot(
  ws: WebSocket,
  requestId: string,
  provider: ScreenShareProvider | undefined,
  display?: ScreenshotDisplaySelector,
): Promise<void> {
  const send = (msg: AgentToDoMsg) => {
    try { ws.send(JSON.stringify(msg)); } catch { /* socket gone */ }
  };
  const fail = (error: string) =>
    send({ type: "agent:screenshot_error", requestId, error });

  const state = provider?.getState() ?? SCREEN_SHARE_OFF;
  if (!provider || !state.capable) {
    fail("This machine cannot share its screen (desktop macOS/Windows only).");
    return;
  }
  if (!state.enabled) {
    fail("Screen sharing is turned off on this machine.");
    return;
  }
  // The OS permission is a SEPARATE grant from the owner's tray toggle, and on an
  // unattended machine nobody is there to answer the dialog macOS raises at the
  // first real capture. Without this guard the caller gets either a black
  // rectangle it will describe as if it were the screen, or a hang that surfaces
  // 30s later as a generic timeout — both of which hide the one fact that would
  // let a human fix it. "unknown" is NOT treated as a refusal: a failed query is
  // not a denial, and we would rather attempt a capture than invent a blocker.
  const denial = osPermissionRefusal(state.osPermission);
  if (denial) {
    fail(denial);
    return;
  }

  try {
    const { data, mimeType, meta } = await provider.capture({ display });
    if (data.length > SCREENSHOT_MAX_BYTES) {
      const mb = (data.length / (1024 * 1024)).toFixed(1);
      fail(`Screenshot is ${mb} MB, which exceeds the ${SCREENSHOT_MAX_BYTES / (1024 * 1024)} MB limit.`);
      return;
    }
    const b64 = data.toString("base64");
    for (let i = 0; i < b64.length; i += SCREENSHOT_CHUNK_SIZE) {
      send({ type: "agent:screenshot_chunk", requestId, chunk: b64.slice(i, i + SCREENSHOT_CHUNK_SIZE) });
    }
    send({
      type: "agent:screenshot_done",
      requestId,
      mimeType,
      totalBytes: data.length,
      ...(meta ? { meta } : {}),
    });
  } catch (err) {
    fail(`Screenshot failed: ${(err as Error).message}`);
  }
}

/**
 * Turn a non-granted OS screen-capture permission into a sentence a caller — and
 * through it, a human at the far end — can act on. Returns null when there is
 * nothing blocking (granted, unqueryable, or an agent that doesn't report it).
 */
function osPermissionRefusal(permission: ScreenShareState["osPermission"]): string | null {
  switch (permission) {
    case "denied":
      return (
        "macOS is blocking screen capture on this machine: AI Commander does not have the Screen Recording permission. " +
        "The tray's 'Share Screen' toggle is the owner's intent — this is the separate OS permission, and only a person " +
        "at that machine can grant it, in System Settings ▸ Privacy & Security ▸ Screen Recording (enable AI Commander, " +
        "then quit and reopen the app). Retrying before that changes nothing."
      );
    case "not-determined":
      return (
        "macOS has not yet been asked for the Screen Recording permission on this machine, and it prompts for it at the " +
        "first capture — on an unattended machine there is nobody to click Allow, so the screenshot would hang or come " +
        "back blank. Someone at that machine must grant it in System Settings ▸ Privacy & Security ▸ Screen Recording " +
        "(enable AI Commander, then quit and reopen the app). Retrying before that changes nothing."
      );
    case "granted-pending-restart":
      return (
        "macOS has granted AI Commander the Screen Recording permission on this machine, but it was granted after the " +
        "app started — and macOS only hands that permission to an app at launch, so this running copy would capture a " +
        "blank screen. Someone at that machine must quit and reopen AI Commander (the app is prompting them to); " +
        "retrying before that changes nothing."
      );
    case "restricted":
      return (
        "macOS reports screen capture as restricted on this machine — typically an MDM/parental-controls policy, which " +
        "the machine's owner cannot override from System Settings. Retrying will not help; whoever administers the " +
        "device has to allow Screen Recording for AI Commander."
      );
    default:
      // "granted", "unknown", or an agent too old to report it at all.
      return null;
  }
}
