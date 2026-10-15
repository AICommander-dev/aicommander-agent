import { describe, expect, it } from "vitest";

import {
  SCREENSHOT_ANTIVIRUS_BLOCK_MESSAGE,
  SCREENSHOT_ANTIVIRUS_HELP_URL,
  explainScreenshotError,
  isAntivirusScriptBlock,
} from "../antivirus-block.js";

/** What a 1.4.1 agent actually relayed when Defender blocked its capture script. */
const AMSI_STDERR_141 =
  "powershell exited with code 1: At line:1 char:1\r\n" +
  "+ $ErrorActionPreference='Stop'; Add-Type -AssemblyName System.Windows.Forms ...\r\n" +
  "+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\r\n" +
  "This script contains malicious content and has been blocked by your antivirus software.\r\n" +
  "    + CategoryInfo          : ParserError: (:) [], ParentContainsErrorRecordException\r\n" +
  "    + FullyQualifiedErrorId : ScriptContainedMaliciousContent";

describe("isAntivirusScriptBlock", () => {
  it("recognises PowerShell's AMSI refusal", () => {
    expect(isAntivirusScriptBlock(AMSI_STDERR_141)).toBe(true);
  });

  it("recognises a localised refusal by its untranslated error id", () => {
    // German Windows: the sentence is translated, the FullyQualifiedErrorId is not.
    expect(
      isAntivirusScriptBlock(
        "Dieses Skript enthält schädliche Inhalte und wurde von Ihrer Antivirensoftware blockiert.\n" +
          "    + FullyQualifiedErrorId : ScriptContainedMaliciousContent",
      ),
    ).toBe(true);
  });

  it("recognises the English sentence even without the error id", () => {
    expect(
      isAntivirusScriptBlock("This script contains malicious content and has been blocked by your antivirus software."),
    ).toBe(true);
  });

  it("does not fire on ordinary failures", () => {
    expect(isAntivirusScriptBlock("powershell exited with code 1: Exception calling CopyFromScreen")).toBe(false);
    expect(isAntivirusScriptBlock("Screen sharing is turned off on this machine.")).toBe(false);
    expect(isAntivirusScriptBlock("")).toBe(false);
    expect(isAntivirusScriptBlock(undefined)).toBe(false);
  });
});

describe("SCREENSHOT_ANTIVIRUS_BLOCK_MESSAGE", () => {
  it("says what happened, that it is fixed, and what not to do", () => {
    const m = SCREENSHOT_ANTIVIRUS_BLOCK_MESSAGE;
    expect(m).toMatch(/blocked by this machine's antivirus/);
    expect(m).toMatch(/AI Commander 1\.4\.1/);
    expect(m).toMatch(/fixed in the next release/);
    expect(m).toMatch(/Retrying will not help/);
    expect(m).toMatch(/Do not disable antivirus protection/);
    expect(m).toMatch(/do not add antivirus exclusions/);
    expect(m).toContain(SCREENSHOT_ANTIVIRUS_HELP_URL);
  });

  it("never echoes PowerShell noise", () => {
    expect(SCREENSHOT_ANTIVIRUS_BLOCK_MESSAGE).not.toMatch(/exited with code|CategoryInfo/);
  });
});

describe("explainScreenshotError", () => {
  it("replaces an AMSI block with the caller-ready sentence", () => {
    expect(explainScreenshotError(`Screenshot failed: ${AMSI_STDERR_141}`)).toBe(SCREENSHOT_ANTIVIRUS_BLOCK_MESSAGE);
  });

  it("leaves every other error alone", () => {
    const other = "This machine has 2 displays, so display 5 does not exist.";
    expect(explainScreenshotError(other)).toBe(other);
  });
});
