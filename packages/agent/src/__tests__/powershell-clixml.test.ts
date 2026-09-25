// PowerShellClixmlDecoder (powershell-clixml.ts): undoing the CLIXML that
// -EncodedCommand makes PowerShell write to its own stderr.
//
// The fixtures below are the REAL payloads measured on a Windows machine, not
// invented ones — that is the whole point of them. If a future change makes one
// of these fail, the change is wrong about what PowerShell emits, not the test.

import { describe, it, expect } from "vitest";
import { PowerShellClixmlDecoder, decodeClixmlText } from "../powershell-clixml.js";
import { planExecShell } from "../exec-shell.js";

const HEADER = "#< CLIXML\r\n";

const OBJS_OPEN =
  '<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">';

/** Measured: what every single call carries, from module auto-loading. */
const PROGRESS_OBJ =
  '<Obj S="progress" RefId="0"><TN RefId="0"><T>System.Management.Automation.PSCustomObject</T>' +
  "<T>System.Object</T></TN><MS><I64 N=\"SourceId\">1</I64><PR N=\"Record\">" +
  "<AV>Preparing modules for first use.</AV><AI>0</AI><Nil /><PI>-1</PI><PC>-1</PC>" +
  "<T>Completed</T><SR>-1</SR><SD> </SD></PR></MS></Obj>";

/** Measured: `Write-Error "this-is-a-real-error"` as it actually came back. */
const ERROR_RECORDS =
  '<S S="Error">C:\\path\\script.ps1 : this_x000D__x000A_</S>' +
  '<S S="Error">-is-a-real-error_x000D__x000A_</S>' +
  '<S S="Error">    + CategoryInfo          : NotSpecified: (:) [Write-Error], ' +
  "WriteErrorException_x000D__x000A_</S>" +
  '<S S="Error">    + FullyQualifiedErrorId : Microsoft.PowerShell.Commands.WriteErrorException' +
  "_x000D__x000A_</S>";

const ERROR_TEXT =
  "C:\\path\\script.ps1 : this\r\n" +
  "-is-a-real-error\r\n" +
  "    + CategoryInfo          : NotSpecified: (:) [Write-Error], WriteErrorException\r\n" +
  "    + FullyQualifiedErrorId : Microsoft.PowerShell.Commands.WriteErrorException\r\n";

/** Feed a whole stderr stream in one chunk and return what the caller sees. */
function decodeAll(stderr: string): string {
  const decoder = new PowerShellClixmlDecoder();
  const parts = [decoder.push(Buffer.from(stderr, "latin1")), decoder.flush()];
  return Buffer.concat(parts).toString("latin1");
}

/** Feed a stream one byte at a time — the worst split a pipe can produce. */
function decodeByBytes(stderr: string): string {
  const decoder = new PowerShellClixmlDecoder();
  const parts: Buffer[] = [];
  const bytes = Buffer.from(stderr, "latin1");
  for (const byte of bytes) parts.push(decoder.push(Buffer.from([byte])));
  parts.push(decoder.flush());
  return Buffer.concat(parts).toString("latin1");
}

describe("PowerShellClixmlDecoder — the noise every call carries", () => {
  it("turns a progress-only block into nothing at all", () => {
    const stderr = `${HEADER}${OBJS_OPEN}${PROGRESS_OBJ}</Objs>`;
    expect(decodeAll(stderr)).toBe("");
  });

  it("drops a self-closing progress record too", () => {
    const stderr = `${HEADER}${OBJS_OPEN}<Obj S="progress" RefId="0" /></Objs>`;
    expect(decodeAll(stderr)).toBe("");
  });

  it("emits nothing for an empty envelope", () => {
    expect(decodeAll(`${HEADER}${OBJS_OPEN}</Objs>`)).toBe("");
    expect(decodeAll(`${HEADER}<Objs Version="1.1.0.1" />`)).toBe("");
  });
});

describe("PowerShellClixmlDecoder — real errors, reassembled", () => {
  it("puts a shredded Write-Error back together the way a console shows it", () => {
    const stderr = `${HEADER}${OBJS_OPEN}${PROGRESS_OBJ}${ERROR_RECORDS}</Objs>`;
    expect(decodeAll(stderr)).toBe(ERROR_TEXT);
  });

  it("reverses XML entities as well as _xNNNN_ escapes", () => {
    const stderr =
      `${HEADER}${OBJS_OPEN}` +
      '<S S="Error">a &lt;b&gt; &amp; &quot;c&quot;_x000D__x000A_</S></Objs>';
    expect(decodeAll(stderr)).toBe('a <b> & "c"\r\n');
  });

  it("treats _x005F_ as a literal underscore, in one left-to-right pass", () => {
    // A message containing the TEXT `_x000D_` is serialized as `_x005F_x000D_`.
    // Decoding it into a carriage return would be a lie about what was printed.
    expect(decodeClixmlText("_x005F_x000D_")).toBe("_x000D_");
    expect(decodeClixmlText("a_x0009_b")).toBe("a\tb");
  });

  // A non-BMP character is carried as the two UTF-16 surrogates that spell it.
  // Decoded separately each half is unpaired, and Node's UTF-8 encoder turns
  // those into U+FFFD — measured before the fix: two replacement characters, the
  // emoji destroyed. The decoder emits latin1-per-byte, so read it back as UTF-8.
  it("recombines a surrogate pair instead of destroying the character", () => {
    const utf8 = (s: string) => Buffer.from(s, "latin1").toString("utf8");
    expect(utf8(decodeClixmlText("_xD83D__xDE80_"))).toBe("🚀");
    expect(utf8(decodeClixmlText("before _xD83D__xDE80_ after"))).toBe("before 🚀 after");
    // Lowercase hex, and a pair adjacent to an ordinary escape on both sides.
    expect(utf8(decodeClixmlText("_x000A__xd83d__xde80__x000A_"))).toBe("\n🚀\n");
    // A LONE high surrogate spells no character; U+FFFD is the honest answer and
    // must not swallow the escape that follows it.
    expect(utf8(decodeClixmlText("_xD83D_x"))).toBe("�x");
    // The pair branch must not weaken the literal-underscore rule.
    expect(decodeClixmlText("_x005F_xD83D_")).toBe("_xD83D_");
  });

  it("keeps warning, verbose, debug and information records, in order", () => {
    const stderr =
      `${HEADER}${OBJS_OPEN}` +
      '<S S="Warning">careful_x000A_</S>' +
      '<S S="Verbose">chatty_x000A_</S>' +
      '<S S="Debug">inner_x000A_</S>' +
      '<S S="Information">note_x000A_</S>' +
      '<S S="Error">bad_x000A_</S>' +
      "</Objs>";
    // No synthesized "WARNING:" prefixes — the text is the script's, not ours —
    // and arrival order is preserved across kinds.
    expect(decodeAll(stderr)).toBe("careful\nchatty\ninner\nnote\nbad\n");
  });

  it("keeps a stream kind it has never heard of rather than dropping it", () => {
    const stderr = `${HEADER}${OBJS_OPEN}<S S="SomethingNew">hello</S></Objs>`;
    expect(decodeAll(stderr)).toBe("hello");
  });
});

describe("PowerShellClixmlDecoder — raw stderr interleaved with the block", () => {
  it("keeps a direct-stderr line written between the marker and the element", () => {
    // MEASURED ordering: [Console]::Error.WriteLine bypasses the serializer and
    // landed AFTER the marker but BEFORE <Objs>.
    const stderr =
      `${HEADER}direct-stderr-line\r\n${OBJS_OPEN}${PROGRESS_OBJ}${ERROR_RECORDS}</Objs>`;
    expect(decodeAll(stderr)).toBe(`direct-stderr-line\r\n${ERROR_TEXT}`);
  });

  it("keeps raw text that lands inside the element, in place", () => {
    const stderr =
      `${HEADER}${OBJS_OPEN}<S S="Error">first_x000A_</S>` +
      "inside-the-block\r\n" +
      '<S S="Error">second_x000A_</S></Objs>';
    expect(decodeAll(stderr)).toBe("first\ninside-the-block\r\nsecond\n");
  });

  it("keeps raw text after the element", () => {
    const stderr = `${HEADER}${OBJS_OPEN}${PROGRESS_OBJ}</Objs>trailing-line\r\n`;
    expect(decodeAll(stderr)).toBe("trailing-line\r\n");
  });

  it("leaves a stream that never had the marker completely untouched", () => {
    const stderr = 'plain error text\r\n<Objs Version="1.1.0.1"><S S="Error">x</S></Objs>\r\n';
    expect(decodeAll(stderr)).toBe(stderr);
  });

  it("passes short streams through when they only look like the marker", () => {
    expect(decodeAll("#< CLI")).toBe("#< CLI");
    expect(decodeAll("#")).toBe("#");
    expect(decodeAll("")).toBe("");
  });
});

describe("PowerShellClixmlDecoder — the command's stderr is never destroyed", () => {
  it("leaves an <Objs> block the COMMAND wrote after PowerShell's envelope alone", () => {
    // The security rule, and the one that was wrong before: PowerShell writes
    // `#< CLIXML` at offset 0 on EVERY call, so "the marker is at offset zero"
    // never distinguished anything. One marker arms exactly one envelope; what
    // the command prints afterwards is text, whatever shape it has. Before this,
    // the whole line below decoded to "" — the caller's bytes, deleted.
    const mine = `${HEADER}${OBJS_OPEN}${PROGRESS_OBJ}${ERROR_RECORDS}</Objs>`;
    const theirs =
      '<Objs Version="1.1.0.1"><Obj S="progress" RefId="9"><TN><T>x</T></TN>SECRET</Obj></Objs>';
    expect(decodeAll(`${mine}${theirs}`)).toBe(`${ERROR_TEXT}${theirs}`);
    expect(decodeByBytes(`${mine}${theirs}`)).toBe(`${ERROR_TEXT}${theirs}`);
  });

  it("stops deleting from an envelope that turned out to contain someone else's XML", () => {
    // Once a block holds markup we did not produce, the next progress-shaped
    // record in it may be the command's too — so nothing more goes, not the
    // record and not the `</Objs>`. The real error before it still decodes.
    const body =
      `${OBJS_OPEN}<S S="Error">real_x000A_</S>` +
      '<Objs Version="1.1.0.1">' +
      '<Obj S="progress" RefId="9"><TN><T>x</T></TN><MS><AV>SECRET</AV></MS></Obj>' +
      "</Objs>";
    const out = decodeAll(`${HEADER}${body}</Objs>`);
    expect(out).toContain("SECRET");
    expect(out.startsWith("real\n")).toBe(true);
    expect(out.endsWith("</Objs>")).toBe(true);
  });

  it("keeps decoding after a lone `<` in the command's interleaved output", () => {
    // `echo "a < b" 1>&2` inside the block. The `<` used to be read as the start
    // of a tag, match nothing, and switch the decoder off for good — so every
    // LATER error came back in exactly the shredded CLIXML this file undoes.
    const stderr =
      `${HEADER}${OBJS_OPEN}<S S="Error">first_x000A_</S>` +
      "a < b\r\n" +
      '<S S="Error">second_x000A_</S></Objs>';
    expect(decodeAll(stderr)).toBe("first\na < b\r\nsecond\n");
    expect(decodeByBytes(stderr)).toBe("first\na < b\r\nsecond\n");
  });

  it("keeps decoding after tag-shaped output the command wrote, and keeps it verbatim", () => {
    // `echo "<note>hi</note>" 1>&2`: forwarded byte-for-byte, the envelope is
    // marked dirty (so its `</Objs>` survives too), and the record after it is
    // still reassembled instead of arriving shredded.
    const stderr =
      `${HEADER}${OBJS_OPEN}<note>hi</note>` +
      '<S S="Error">still_x000A_</S></Objs>';
    expect(decodeAll(stderr)).toBe(`${OBJS_OPEN}<note>hi</note>still\n</Objs>`);
  });

  it("keeps whitespace the command wrote between two records", () => {
    // There is no serializer formatting between measured records, so a blank run
    // here came from the caller. It used to be deleted.
    const stderr =
      `${HEADER}${OBJS_OPEN}<S S="Error">a_x000A_</S>` +
      "\n" +
      '<S S="Error">b_x000A_</S></Objs>';
    expect(decodeAll(stderr)).toBe("a\n\nb\n");
  });

  it("recognises a SECOND envelope instead of leaking its marker as text", () => {
    // scan-after-</Objs> used to accept a bare `<Objs>` and never a marker, so a
    // further serialized block arrived with `#< CLIXML` printed in front of it —
    // re-emitting the exact noise this class exists to remove.
    const stderr =
      `${HEADER}${OBJS_OPEN}${PROGRESS_OBJ}</Objs>` +
      `${HEADER}${OBJS_OPEN}<S S="Error">boom_x000A_</S></Objs>`;
    expect(decodeAll(stderr)).toBe("boom\n");
    expect(decodeByBytes(stderr)).toBe("boom\n");
    // ...including across the line break PowerShell may put between them, which
    // is held back and only dropped if the marker really follows.
    expect(decodeAll(`${HEADER}${OBJS_OPEN}</Objs>\r\n${HEADER}${OBJS_OPEN}<S>x</S></Objs>`))
      .toBe("x");
    expect(decodeAll(`${HEADER}${OBJS_OPEN}</Objs>\r\nplain-text`)).toBe("\r\nplain-text");
  });
});

describe("PowerShellClixmlDecoder — arbitrary chunk boundaries", () => {
  it("decodes the measured error block one byte at a time", () => {
    const stderr = `${HEADER}${OBJS_OPEN}${PROGRESS_OBJ}${ERROR_RECORDS}</Objs>`;
    expect(decodeByBytes(stderr)).toBe(ERROR_TEXT);
  });

  it("decodes the interleaved-raw stream one byte at a time", () => {
    const stderr =
      `${HEADER}direct-stderr-line\r\n${OBJS_OPEN}${PROGRESS_OBJ}${ERROR_RECORDS}</Objs>`;
    expect(decodeByBytes(stderr)).toBe(`direct-stderr-line\r\n${ERROR_TEXT}`);
  });

  it("survives a split inside a tag and a split inside an escape", () => {
    const stderr = `${HEADER}${OBJS_OPEN}<S S="Error">one_x000D__x000A_</S></Objs>`;
    const splitInTag = stderr.indexOf('<S S="Error"') + 4; // mid `<S S=`
    const splitInEscape = stderr.indexOf("_x000D_") + 3; // mid `_x0|00D_`
    for (const at of [splitInTag, splitInEscape]) {
      const decoder = new PowerShellClixmlDecoder();
      const first = decoder.push(Buffer.from(stderr.slice(0, at), "latin1"));
      const second = decoder.push(Buffer.from(stderr.slice(at), "latin1"));
      const rest = decoder.flush();
      expect(Buffer.concat([first, second, rest]).toString("latin1")).toBe("one\r\n");
    }
  });

  it("does not forward a partial <Objs marker as raw text", () => {
    const decoder = new PowerShellClixmlDecoder();
    decoder.push(Buffer.from(HEADER, "latin1"));
    // `<Ob` is a live prefix of the envelope: forwarding it now would duplicate
    // bytes that the next chunk completes into structure.
    expect(decoder.push(Buffer.from("<Ob", "latin1")).length).toBe(0);
    const tail = `js Version="1.1.0.1"><S S="Error">z</S></Objs>`;
    const out = Buffer.concat([
      decoder.push(Buffer.from(tail, "latin1")),
      decoder.flush(),
    ]).toString("latin1");
    expect(out).toBe("z");
  });

  it("streams each record as it completes rather than waiting for </Objs>", () => {
    // remote_exec streams stderr; an error must not sit in a buffer until the
    // command ends just because the envelope has not closed yet.
    const decoder = new PowerShellClixmlDecoder();
    decoder.push(Buffer.from(`${HEADER}${OBJS_OPEN}`, "latin1"));
    const out = decoder.push(Buffer.from('<S S="Error">now_x000A_</S>', "latin1"));
    expect(out.toString("latin1")).toBe("now\n");
  });
});

describe("PowerShellClixmlDecoder — never lose anything", () => {
  it("passes malformed XML through instead of guessing", () => {
    // Everything but the marker line — which at offset zero of a PowerShell
    // stderr stream is unambiguously PowerShell's own framing — comes back
    // byte-for-byte.
    const body = `${OBJS_OPEN}<Bogus attr="1">?</Bogus></Objs>`;
    expect(decodeAll(`${HEADER}${body}`)).toBe(body);
  });

  it("passes a serialized object it cannot render through untouched", () => {
    const body = `${OBJS_OPEN}<Obj S="something" RefId="3"><TN><T>X</T></TN></Obj></Objs>`;
    expect(decodeAll(`${HEADER}${body}`)).toBe(body);
  });

  it("does not mistake a look-alike element for the envelope", () => {
    const body = "<Objsomething>hi</Objsomething>";
    expect(decodeAll(`${HEADER}${body}`)).toBe(body);
  });

  it("flushes a block that was cut off mid-record", () => {
    const truncated = `${OBJS_OPEN}<S S="Error">half a mess`;
    expect(decodeAll(`${HEADER}${truncated}`)).toBe(truncated);
  });

  it("flushes a block cut off between the marker and the envelope", () => {
    expect(decodeAll(`${HEADER}<Ob`)).toBe("<Ob");
  });

  it("stops buffering and hands everything back once the record is absurd", () => {
    // Bounded memory: a `<S>` that never closes must not be accumulated for the
    // life of the command. Past the cap the decoder gives up and forwards.
    const decoder = new PowerShellClixmlDecoder();
    decoder.push(Buffer.from(`${HEADER}${OBJS_OPEN}<S S="Error">`, "latin1"));
    const filler = "x".repeat(64 * 1024);
    const seen: Buffer[] = [];
    for (let i = 0; i < 8; i += 1) seen.push(decoder.push(Buffer.from(filler, "latin1")));
    const out = Buffer.concat([...seen, decoder.flush()]).toString("latin1");
    // Nothing invented, nothing lost: the envelope, the open tag and every
    // filler byte come back.
    expect(out.startsWith(`${OBJS_OPEN}<S S="Error">`)).toBe(true);
    expect(out.length).toBe(OBJS_OPEN.length + '<S S="Error">'.length + filler.length * 8);
    // And it stays in pass-through afterwards — no half-decoded tail.
    const after = decoder.push(Buffer.from("</S></Objs>tail", "latin1"));
    expect(after.toString("latin1")).toBe("</S></Objs>tail");
  });

  it("never throws on hostile or truncated input", () => {
    const nasty = [
      `${HEADER}<Objs`,
      `${HEADER}${OBJS_OPEN}<S S="Error">`,
      `${HEADER}${OBJS_OPEN}<Obj S="progress">`,
      `${HEADER}${OBJS_OPEN}</Objs></Objs></Objs>`,
      `${HEADER}${OBJS_OPEN}<S>_xZZZZ_&nope;</S></Objs>`,
      `${HEADER}\u0000\u00ff<Objs>`,
      "#< CLIXML",
      `${HEADER}`,
    ];
    for (const stderr of nasty) {
      expect(() => decodeAll(stderr)).not.toThrow();
      expect(() => decodeByBytes(stderr)).not.toThrow();
    }
  });

  it("hands back the very buffer it was given once it is in pass-through", () => {
    // `raw` is where every stream without the marker spends its whole life. The
    // generic path copies each chunk four times (latin1 decode, concat, join,
    // re-encode) to produce a byte-identical buffer; a megabyte of stderr does
    // not deserve several megabytes of garbage.
    const decoder = new PowerShellClixmlDecoder();
    decoder.push(Buffer.from("plain stderr, no marker\n", "latin1"));
    const chunk = Buffer.from("more output\n", "latin1");
    expect(decoder.push(chunk)).toBe(chunk);
  });

  it("preserves non-ASCII bytes exactly on the pass-through path", () => {
    const raw = Buffer.from([0x80, 0xff, 0x0a, 0xe2, 0x82, 0xac]).toString("latin1");
    expect(decodeAll(raw)).toBe(raw);
  });
});

describe("only the PowerShell path is decoded at all", () => {
  it("is requested by the -EncodedCommand plan and by no other", () => {
    const windows = { exists: () => true };
    expect(planExecShell("win32", "powershell", "echo hi", windows)).toMatchObject({
      ok: true,
      clixmlStderr: true,
    });
    for (const [platform, shell] of [
      ["win32", "cmd"],
      ["win32", undefined],
      ["linux", "sh"],
      ["linux", "bash"],
      ["darwin", undefined],
    ] as const) {
      const plan = planExecShell(platform, shell, "echo hi", { exists: () => true });
      expect(plan.ok).toBe(true);
      expect(plan.ok && plan.clixmlStderr).toBeUndefined();
    }
  });
});
