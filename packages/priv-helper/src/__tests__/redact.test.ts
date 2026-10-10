/**
 * The helper report's redactor (src/redact.ts).
 *
 * It exists because doctor.ts shipped a report advertised in its own footer as
 * safe to send to support and to an antivirus vendor with NO redaction in the
 * package at all — while interpolating a marker file's content, a scanned
 * install root derived from this binary's own location, and exception messages.
 * One test per rule, so a rule quietly dropped fails here rather than in
 * somebody's inbox.
 */
import { describe, expect, it } from "vitest";
import os from "node:os";

import { maskSessionCode } from "@aicommander/protocol";

import { maskHelperSessionCode, redactHelperText } from "../redact.js";

describe("redactHelperText", () => {
  it("takes the account name out of a Windows path and keeps the path", () => {
    // Paths are the diagnosis — where it is installed, which file was refused.
    // The name in the middle of one is the user's identity leaving the machine.
    const text = redactHelperText("counted in C:\\Users\\alice\\Downloads\\AICommander");
    expect(text).not.toContain("alice");
    expect(text).toContain("C:\\Users\\<user>\\Downloads\\AICommander");
  });

  it("does the same for /home and for a second account's path", () => {
    expect(redactHelperText("stat '/home/bob/AI Commander'")).toContain("/home/<user>/");
    expect(redactHelperText("stat '/home/bob/AI Commander'")).not.toContain("bob");
  });

  it("collapses THIS process's own home directory, whatever shape the OS gave it", () => {
    const home = os.homedir();
    const text = redactHelperText(`the marker is at ${home}/Downloads/VERSION`);
    expect(text).not.toContain(home);
    expect(text).toContain("~/Downloads/VERSION");
  });

  it("blanks a signed capability before the blob rule can eat it piecemeal", () => {
    const jws = "eyJhbGciOiJFZERTQSJ9.eyJyZXF1ZXN0SWQiOiIxMjMifQ.c2lnbmF0dXJlLWhlcmU";
    expect(redactHelperText(`capability ${jws}`)).toBe("capability [redacted-jws]");
  });

  it("blanks any long opaque run — a ticket, a token, a device secret", () => {
    expect(redactHelperText(`token ${"a".repeat(48)}`)).toBe("token [redacted]");
  });

  it("masks a session code THE WAY THE AGENT DOES — the parity this file claims", () => {
    // The regression: this blanked all three groups while the header claimed the
    // rules were "deliberately the same rules" as `redactDiagText`'s, and the
    // reason given for mirroring them is that a support engineer correlates a
    // helper report against an agent report. Two fully-blanked codes correlate
    // with nothing. `maskSessionCode` keeps the first group; so does this.
    expect(redactHelperText("code AIC-9K3F-WX9M-RTBN")).toBe("code AIC-9K3F-***-***");
    expect(maskHelperSessionCode("AIC-9K3F-WX9M-RTBN")).toBe(maskSessionCode("AIC-9K3F-WX9M-RTBN"));
    // Codes are minted uppercase over a case-insensitive alphabet, and the agent
    // canonicalises before masking. Same input, same output, either case.
    expect(redactHelperText("code aic-9k3f-wx9m-rtbn")).toBe("code AIC-9K3F-***-***");
    // The one deliberate divergence, stated in the header: a code-shaped string
    // outside the minting alphabet (I/L/O/U) is passed through UNCHANGED by
    // `maskSessionCode`, and mirroring that would mirror a leak into a report
    // this module exists to make safe. It is blanked instead — never revealed.
    expect(redactHelperText("code AIC-ILOU-CD34-EF56")).toBe("code AIC-****-****-****");
  });

  it("leaves an already-masked code alone, so a second pass cannot re-mangle it", () => {
    expect(redactHelperText("code AIC-9K3F-***-***")).toBe("code AIC-9K3F-***-***");
  });

  it("strips control characters, so nothing pasted can forge a line", () => {
    expect(redactHelperText("a\nb\u0000c")).toBe("a b c");
  });

  it("caps a single value: a diagnostic line is a fact, never a payload", () => {
    const out = redactHelperText("x".repeat(5_000));
    expect(out.length).toBeLessThan(700);
  });

  it("is idempotent — a second pass does not produce /home/<<user>>", () => {
    const once = redactHelperText("in /home/carol/app");
    expect(redactHelperText(once)).toBe(once);
  });

  it("leaves a machine-wide path exactly as it was", () => {
    const text = "the installation is complete — all 81 shipped files are present in C:\\Program Files\\AICommander.";
    expect(redactHelperText(text)).toBe(text);
  });
});
