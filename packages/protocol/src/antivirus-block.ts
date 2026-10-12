/**
 * Recognising — and answering — a Windows antivirus (AMSI) block.
 *
 * When Microsoft Defender or any other AMSI provider decides a PowerShell script
 * is malicious, PowerShell refuses to run it and prints, on stderr:
 *
 *   This script contains malicious content and has been blocked by your
 *   antivirus software.
 *       + CategoryInfo          : ParserError: (:) [], ParentContainsErrorRecordException
 *       + FullyQualifiedErrorId : ScriptContainedMaliciousContent
 *
 * AI Commander 1.4.1 captured Windows screenshots with an inline PowerShell
 * script (System.Drawing CopyFromScreen) that Defender classifies as
 * `HackTool:PowerShell/EmpireGetScreenshot.B`, and that stderr reached callers
 * verbatim as "powershell exited with code 1: …". A caller reading it cannot
 * tell whether to retry, whether the machine is compromised, or what to ask the
 * owner to do — and the obvious-looking remedy (an exclusion, or turning
 * protection off) is both wrong and useless: AMSI scans script CONTENT, so no
 * folder exclusion reaches it.
 *
 * Lives in protocol because two places need the same words: the agent (for any
 * child process it spawns) and the relay (for errors still arriving from 1.4.1
 * agents, which will keep sending the raw stderr until they are updated).
 */

/**
 * Markers of an AMSI block in a child process's stderr. The localised sentence
 * differs per Windows display language, but the FullyQualifiedErrorId is never
 * translated, so it is the marker that works on every machine; the English
 * sentence and the Defender family name cover output that lost the error id.
 */
const ANTIVIRUS_BLOCK_MARKERS: readonly RegExp[] = [
  /ScriptContainedMaliciousContent/i,
  /contains malicious content and has been blocked by your antivirus/i,
  /blocked by your antivirus software/i,
  /EmpireGetScreenshot/i,
];

/** True when `text` carries the signature of an AMSI/antivirus script block. */
export function isAntivirusScriptBlock(text: string | null | undefined): boolean {
  if (!text) return false;
  return ANTIVIRUS_BLOCK_MARKERS.some((re) => re.test(text));
}

/** Where the full explanation for the 1.4.1 screenshot detection lives. */
export const SCREENSHOT_ANTIVIRUS_HELP_URL =
  "https://aicommander.dev/troubleshooting/#defender-empire-getscreenshot";

/**
 * The caller-ready sentence for a screenshot the machine's antivirus blocked.
 * Written for a model to relay to a human unchanged: what happened, that it is
 * a known and fixed issue, that retrying is pointless, and — explicitly — the
 * remedies NOT to reach for.
 */
export const SCREENSHOT_ANTIVIRUS_BLOCK_MESSAGE =
  "The screenshot was blocked by this machine's antivirus (Microsoft Defender reports it as " +
  "HackTool:PowerShell/EmpireGetScreenshot.B). This is a known false positive in AI Commander 1.4.1's " +
  "PowerShell-based Windows screenshot, fixed in the next release, which no longer uses PowerShell to capture " +
  "the screen. Retrying will not help. Do not disable antivirus protection and do not add antivirus " +
  "exclusions — they are not needed and would not help; update AI Commander on that machine once the fix is " +
  `available. Other remote commands are not affected. Details: ${SCREENSHOT_ANTIVIRUS_HELP_URL}`;

/**
 * Replace an AMSI-blocked screenshot error with SCREENSHOT_ANTIVIRUS_BLOCK_MESSAGE;
 * any other text is returned unchanged.
 */
export function explainScreenshotError(text: string): string {
  return isAntivirusScriptBlock(text) ? SCREENSHOT_ANTIVIRUS_BLOCK_MESSAGE : text;
}
