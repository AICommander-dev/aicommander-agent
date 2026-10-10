/**
 * Undo the CLIXML that Windows PowerShell writes to its OWN stderr when we run
 * it with -EncodedCommand.
 *
 * WHY THIS EXISTS AT ALL. `shell: "powershell"` is implemented in exec-shell.ts
 * by handing powershell.exe a base64 -EncodedCommand argument — see
 * wrapForPowerShell there for why base64 and not quoting (metacharacters do not
 * merely break quoting through cmd.exe's parser, they REPARSE into a different
 * command). That choice is not negotiable, and it has one measured side effect:
 * with -EncodedCommand, PowerShell 5.1 stops writing its error/warning/verbose/
 * debug/progress streams as plain text and instead SERIALIZES them to its stderr
 * as CLIXML. The caller then receives, verbatim:
 *
 *     #< CLIXML
 *     <Objs Version="1.1.0.1" xmlns="..."><Obj S="progress" RefId="0">…
 *       <AV>Preparing modules for first use.</AV>…</Obj></Objs>
 *
 * on EVERY call (module auto-loading progress), and — much worse — a real error
 * comes back shredded. Measured on a real Windows box, `Write-Error
 * "this-is-a-real-error"` arrived as:
 *
 *     <S S="Error">… : this_x000D__x000A_</S><S S="Error">-is-a-real-error_x000D__x000A_</S>
 *     <S S="Error">    + CategoryInfo          : NotSpecified: (:) [Write-Error],
 *       WriteErrorException_x000D__x000A_</S>…
 *
 * i.e. the message split across elements at PowerShell's own console-width wrap
 * points and `_xNNNN_`-escaped. An AI agent reading that has to reverse-engineer
 * PowerShell's serializer to recover one sentence. Reassembling it here is what
 * turns that back into the text a human sees on a console.
 *
 * WHAT WAS RULED OUT, MEASURED, so nobody "simplifies" this away:
 *
 *  - `-OutputFormat Text` DOES NOT WORK. Tested against our exact invocation:
 *    `powershell -NoProfile -NonInteractive -OutputFormat Text -EncodedCommand
 *    <b64>` produced BYTE-IDENTICAL CLIXML. (An earlier probe that appeared to
 *    work had used -Command, not -EncodedCommand — the flag was never the cause.
 *    The trigger is -EncodedCommand itself.) Do not replace this file with a
 *    flag; the flag was tried on the machine that has the bug.
 *  - Dropping -EncodedCommand restores the injection hazard it was chosen for,
 *    and the interior-line-break guarantee that rides on it.
 *  - A temp .ps1 file with -File breaks the launcher's trust model: the command
 *    travels only over the bounded stdin protocol, never disk, never a command
 *    line.
 *  - Prepending `$ProgressPreference='SilentlyContinue'` silences the progress
 *    noise but NOT the error serialization — the half that actually hurts — and
 *    it edits the caller's script, which this layer must not do.
 *
 * So the decoding happens HERE, on the transport, because the CLIXML is an
 * artifact of OUR wrapping choice and the caller's script is untouched by it.
 * executor.ts feeds stderr through this ONLY when exec-shell.ts says it did the
 * PowerShell wrapping (ExecShellPlan.clixmlStderr); cmd, sh and bash never see
 * an instance of this class and are byte-for-byte unaffected.
 *
 * THE HARD PART, and the reason this is a state machine rather than an XML
 * parse: RAW STDERR INTERLEAVES WITH THE SERIALIZED BLOCK. `[Console]::Error.
 * WriteLine("direct-stderr-line")` bypasses PowerShell's serializer entirely,
 * and measured output put it BETWEEN the marker and the element:
 *
 *     #< CLIXML
 *     direct-stderr-line
 *     <Objs …>…</Objs>
 *
 * The marker is therefore NOT followed by well-formed XML, and any raw text must
 * survive verbatim and in its original position. On top of that the pipe splits
 * chunks anywhere — mid-tag, mid-escape — and remote_exec STREAMS stderr, so
 * whatever is emitted cannot be recalled. Hence: incremental, per-record,
 * bounded, and pass-through-on-doubt.
 *
 * BYTES, NOT TEXT. Everything below works on latin1 strings — one JS char per
 * byte — so any byte sequence round-trips exactly and nothing is transcoded by
 * accident (PowerShell writes this stream in the console output encoding, which
 * is not necessarily UTF-8 and is not ours to reinterpret). The only place a
 * code point is created rather than copied is an unescape, and there it is
 * written back as UTF-8 bytes; every escape that occurs in practice
 * (_x000D_, _x000A_, _x0009_, _x005F_) is ASCII and identical either way.
 */

/**
 * PowerShell's own leader. It is written at the very start of its stderr, and
 * again in front of any further serialized block — never in the middle of one.
 * That position is the whole of this decoder's trust rule; see the class comment.
 */
const CLIXML_HEADER = "#< CLIXML";

/** The serialized envelope. Note `<Objs` is a prefix of nothing else we match. */
const OBJS_OPEN = "<Objs";

/**
 * Ceiling on how much unparsed CLIXML we will hold while waiting for the rest of
 * a record.
 *
 * A command can write megabytes to stderr and a closing tag might never arrive
 * (a killed PowerShell, a command printing its own `<Objs`), so waiting without
 * a bound would be a memory leak triggerable by ordinary output. At the cap we
 * do the safe thing rather than the tidy one: flush everything held, verbatim,
 * and stop decoding for the rest of this command. Noise is recoverable; a lost
 * or truncated stderr is not.
 *
 * 256 KiB is far above any real record (a wrapped PowerShell error is a few
 * hundred bytes) and far below the 1 MiB the relay will accept in total.
 */
const MAX_PENDING_BYTES = 256 * 1024;

/**
 * Write one code point back into our latin1 byte space.
 *
 * ASCII is a single byte either way, which covers every escape PowerShell
 * actually emits. Above that we encode UTF-8: it is the only defensible guess
 * for a stream whose encoding we do not otherwise reinterpret, and guessing
 * wrong there costs a mojibake character in a rare message rather than
 * correctness anywhere else.
 */
function codePointToLatin1(codePoint: number): string {
  if (codePoint <= 0x7f) return String.fromCharCode(codePoint);
  if (codePoint > 0x10ffff) return "";
  try {
    return Buffer.from(String.fromCodePoint(codePoint), "utf8").toString("latin1");
  } catch {
    return "";
  }
}

/**
 * Turn the text content of one CLIXML `<S>` element back into console text.
 *
 * Two layers, in the order PowerShell applied them in reverse. First XML entity
 * references, because the serializer XML-escapes after it escapes control
 * characters. Then the `_xHHHH_` form, which is how CLIXML carries anything XML
 * cannot: `_x000D_` is CR, `_x000A_` is LF, `_x0009_` is TAB — and `_x005F_` is
 * the escape for a LITERAL underscore, which is what makes a single left-to-right
 * pass correct. A message containing the text `_x000D_` is serialized as
 * `_x005F_x000D_`; scanning left to right consumes `_x005F_` first, yields `_`,
 * and leaves `x000D_` as the ordinary characters they were. A right-to-left or
 * repeated pass would "helpfully" turn that back into a carriage return.
 */
export function decodeClixmlText(text: string): string {
  const unentitized = text.replace(
    /&(?:(lt|gt|amp|quot|apos)|#(\d+)|#[xX]([0-9a-fA-F]+));/g,
    (match, name: string | undefined, dec: string | undefined, hex: string | undefined) => {
      if (name !== undefined) {
        return name === "lt" ? "<"
          : name === "gt" ? ">"
          : name === "amp" ? "&"
          : name === "quot" ? '"'
          : "'";
      }
      const codePoint = dec !== undefined ? Number.parseInt(dec, 10) : Number.parseInt(hex!, 16);
      return Number.isNaN(codePoint) ? match : codePointToLatin1(codePoint);
    },
  );
  // A character outside the BMP has no single 4-hex escape, so CLIXML carries it
  // as the two UTF-16 surrogates that spell it: 🚀 is `_xD83D__xDE80_`. Decoded
  // one at a time each half is an UNPAIRED surrogate, and Node's UTF-8 encoder
  // replaces those with U+FFFD — measured: `_xD83D__xDE80_` came back as the two
  // bytes-triples `efbfbd efbfbd`, i.e. the character was destroyed. So match a
  // high surrogate immediately followed by a low one FIRST and recombine them.
  // Rare in practice (an emoji is valid XML text, so the serializer has no reason
  // to escape it) but it is a data-losing path and the fix is two lines.
  //
  // The alternation keeps the single left-to-right pass that `_x005F_` requires:
  // a lone `_x005F_` cannot match the pair branch, so `_x005F_x000D_` still
  // yields the literal text `_x000D_` rather than a carriage return. An unpaired
  // surrogate that is genuinely alone still becomes U+FFFD — it spells no
  // character, so there is nothing truthful to put in its place.
  return unentitized.replace(
    /_x([dD][89abAB][0-9a-fA-F]{2})__x([dD][c-fC-F][0-9a-fA-F]{2})_|_x([0-9a-fA-F]{4})_/g,
    (_match, high: string | undefined, low: string | undefined, solo: string | undefined) => {
      if (high !== undefined && low !== undefined) {
        const codePoint =
          0x10000 +
          ((Number.parseInt(high, 16) - 0xd800) << 10) +
          (Number.parseInt(low, 16) - 0xdc00);
        return codePointToLatin1(codePoint);
      }
      return codePointToLatin1(Number.parseInt(solo!, 16));
    },
  );
}

/** Length of the longest suffix of `text` that is a proper prefix of `marker`. */
function partialTailLength(text: string, marker: string): number {
  const max = Math.min(marker.length - 1, text.length);
  for (let k = max; k > 0; k -= 1) {
    if (text.endsWith(marker.slice(0, k))) return k;
  }
  return 0;
}

/**
 * Incremental CLIXML-on-stderr decoder for the PowerShell path.
 *
 * ONE INSTANCE PER COMMAND. `push` returns the bytes to forward for that chunk
 * (possibly empty); `flush` returns whatever is still held when the command
 * ends. Between them nothing is ever dropped except things we positively
 * identified as PowerShell's own framing.
 *
 * WHAT IS TREATED AS POWERSHELL'S FRAMING, and what a hostile command can still
 * do. An earlier version of this comment claimed the marker "can only" be
 * PowerShell's because a command would have to be first on stderr to forge it.
 * That was FALSE, and the code was correspondingly unsafe: PowerShell writes
 * `#< CLIXML` at offset 0 on every single call — that is the premise of this
 * whole module — so the decoder stayed armed for the rest of the command and
 * happily read an `<Objs …>` the COMMAND printed later as its own envelope. A
 * script whose stderr ended in `<Objs …><Obj S="progress" …>SECRET</Obj></Objs>`
 * had those bytes DELETED. Losing a caller's stderr to our parser is strictly
 * worse than the noise we remove, so the rule is now positional and narrow:
 *
 *  1. An envelope is entered ONLY at a place PowerShell alone writes framing:
 *     directly after a `#< CLIXML` line that sat at stream offset zero, or
 *     directly after an envelope we ourselves closed (optionally across one line
 *     break). One `#< CLIXML` arms the decoder for exactly ONE `<Objs …>`; after
 *     `</Objs>` it is disarmed until another marker arrives in that position.
 *     A bare `<Objs …>` in the middle of a command's output is therefore just
 *     text now, and is forwarded untouched.
 *  2. Inside an envelope, anything that is not a record shape we produced is
 *     forwarded verbatim AND marks the envelope "dirty": from that point on this
 *     block is no longer purely PowerShell's, so nothing further is deleted from
 *     it — not the progress records, not even the `</Objs>` that closes it.
 *  3. Character data is never deleted anywhere else. Records are decoded, raw
 *     interleaved text (whitespace included) is passed through in place, and the
 *     only bytes dropped are the marker line, the envelope's own tags, the `<S>`
 *     tags around a record we decoded, and progress records in an undirtied
 *     envelope.
 *
 * WHAT REMAINS POSSIBLE, stated honestly. A command that writes `#< CLIXML` at
 * offset 0 of stderr — which requires PowerShell to have written nothing at all
 * before it — can hand the decoder its own envelope and mangle its OWN bytes in
 * a way it chose. A command that prints a CLIXML `<Obj S="progress" …>…</Obj>`
 * record while PowerShell's own envelope is open loses that record, because at
 * that point it is byte-for-byte indistinguishable from the module-autoload
 * progress this exists to remove (a caller's real `Write-Progress` is dropped by
 * design too). Nothing else: it cannot touch another command's output (one
 * instance per command), cannot make the decoder delete ordinary text, cannot
 * make it allocate without bound (MAX_PENDING_BYTES), cannot make it throw (pump
 * is try/caught into pass-through), and cannot make it reorder anything.
 */
export class PowerShellClixmlDecoder {
  /**
   * `header`  — deciding whether what follows is PowerShell's marker.
   * `headerRetry` — after an envelope closed: allow one line break, then re-run
   *              the marker test, so a SECOND serialized block is recognised
   *              instead of leaking its `#< CLIXML` line as text.
   * `headerEol` — marker matched, swallowing the newline that follows it.
   * `scan`    — armed: everything is raw, watching for this marker's `<Objs`.
   * `objs`    — inside `<Objs…>`: records are decoded, stray text stays raw.
   * `raw`     — give up, forever: forward every byte untouched.
   */
  private mode: "header" | "headerRetry" | "headerEol" | "scan" | "objs" | "raw" = "header";

  /** Unconsumed input, latin1 (one char per byte). */
  private buf = "";

  /**
   * Structural bytes we have consumed but not yet committed to dropping — in
   * practice the `<Objs …>` opening tag, and the single line break allowed
   * before a SECOND `#< CLIXML` marker (headerRetry), which is only framing if
   * that marker actually turns up.
   *
   * It is held rather than dropped so that a block which turns out NOT to be
   * something we understand can be forwarded byte-for-byte instead of arriving
   * headless. It is discarded the moment one record decodes successfully, and
   * flushed ahead of any raw text so ordering is never disturbed.
   *
   * The `#< CLIXML` line itself is NOT held: matched where only PowerShell
   * writes it, it is unambiguously PowerShell's framing, and
   * holding it would mean emitting it in front of interleaved raw text in the
   * measured `#< CLIXML` / direct-stderr-line / `<Objs>` case — reintroducing
   * exactly the noise this class removes.
   */
  private pendingPrefix = "";

  /** Output collected during the current push/flush. */
  private out: string[] = [];

  /**
   * Set when this envelope turned out to contain something we did not produce.
   *
   * From then on the block is not purely PowerShell's, so nothing more is
   * deleted from it — including its own `</Objs>` and any progress record, which
   * in a block a command is writing into may well be the command's. Cleared when
   * the next envelope opens.
   */
  private envelopeDirty = false;

  push(chunk: Buffer): Buffer {
    // TERMINAL PASS-THROUGH, and the reason it is a special case: `raw` is where
    // every stream that gave up (and every stream that never had the marker)
    // spends the rest of its life, and the generic path below would copy each
    // chunk four times — latin1 decode, string concat, join, re-encode — to
    // produce a byte-identical buffer. A megabyte of stderr is not worth several
    // megabytes of garbage, so the incoming buffer is handed straight back.
    // `raw` always leaves both holding areas empty, but they are checked rather
    // than assumed: forwarding a chunk ahead of bytes we are holding would
    // REORDER the stream, which is the one thing worse than copying it.
    if (this.mode === "raw" && this.buf.length === 0 && this.pendingPrefix.length === 0) {
      return chunk;
    }
    if (chunk.length > 0) this.buf += chunk.toString("latin1");
    this.run();
    return this.take();
  }

  /**
   * End of stream: forward everything still held, verbatim.
   *
   * A CLIXML block can be cut off mid-record (PowerShell killed, output
   * truncated). Emitting the fragment raw is the only option that loses nothing;
   * a caller seeing a stray `<S S="Error">` tail can still read the message
   * inside it, whereas a caller seeing nothing cannot.
   */
  flush(): Buffer {
    const held = this.pendingPrefix + this.buf;
    this.pendingPrefix = "";
    this.buf = "";
    this.mode = "raw";
    if (held.length > 0) this.out.push(held);
    return this.take();
  }

  private take(): Buffer {
    if (this.out.length === 0) return Buffer.alloc(0);
    const text = this.out.join("");
    this.out = [];
    return Buffer.from(text, "latin1");
  }

  /**
   * Drive the state machine as far as the buffered bytes allow.
   *
   * Wrapped whole in a try/catch on purpose: a parser bug here would cost a
   * caller their stderr, which is strictly worse than the noise we are removing,
   * so ANY throw degrades to forwarding the bytes untouched.
   */
  private run(): void {
    try {
      this.pump();
    } catch {
      this.giveUp();
      return;
    }
    if (this.mode !== "raw" && this.pendingPrefix.length + this.buf.length > MAX_PENDING_BYTES) {
      this.giveUp();
    }
  }

  /** Forward everything held and stop decoding for the rest of this command. */
  private giveUp(): void {
    const held = this.pendingPrefix + this.buf;
    this.pendingPrefix = "";
    this.buf = "";
    this.mode = "raw";
    if (held.length > 0) this.out.push(held);
  }

  /** Forward bytes as-is, flushing any held structural prefix ahead of them. */
  private emitRaw(text: string): void {
    if (text.length === 0) return;
    if (this.pendingPrefix.length > 0) {
      this.out.push(this.pendingPrefix);
      this.pendingPrefix = "";
    }
    this.out.push(text);
  }

  /** A record decoded cleanly: the structural bytes around it are now noise. */
  private emitDecoded(text: string): void {
    this.pendingPrefix = "";
    if (text.length > 0) this.out.push(text);
  }

  private pump(): void {
    for (;;) {
      switch (this.mode) {
        case "raw": {
          if (this.buf.length === 0 && this.pendingPrefix.length === 0) return;
          // emitRaw, not a bare push: a line break held back while we tested for
          // a second marker (headerRetry) has to go out AHEAD of these bytes.
          const held = this.buf;
          this.buf = "";
          this.emitRaw(held);
          if (this.pendingPrefix.length > 0) {
            this.out.push(this.pendingPrefix);
            this.pendingPrefix = "";
          }
          return;
        }
        case "headerRetry": {
          // An envelope just closed. PowerShell writes the marker for a further
          // serialized block right here, so the test is re-run — but the line
          // break that may precede it is only PowerShell's if the marker really
          // follows, so it is HELD rather than consumed. If no marker follows,
          // the raw case above puts it back in front of the command's bytes.
          if (this.buf.length === 0) return;
          if (this.buf.startsWith("\r\n")) {
            this.pendingPrefix += "\r\n";
            this.buf = this.buf.slice(2);
          } else if (this.buf === "\r") {
            return; // could still become "\r\n"
          } else if (this.buf.startsWith("\n") || this.buf.startsWith("\r")) {
            this.pendingPrefix += this.buf[0];
            this.buf = this.buf.slice(1);
          }
          this.mode = "header";
          break;
        }
        case "header": {
          if (this.buf.length < CLIXML_HEADER.length) {
            // Still ambiguous — but only while what we have is a live prefix.
            if (!CLIXML_HEADER.startsWith(this.buf)) {
              this.mode = "raw";
              break;
            }
            return;
          }
          if (!this.buf.startsWith(CLIXML_HEADER)) {
            // No marker where PowerShell would have put one: everything from
            // here is the command's own stderr. Never decode a thing from now
            // on — that is the whole of the trust rule.
            this.mode = "raw";
            break;
          }
          // The marker is real, so the line break held for it (headerRetry) is
          // PowerShell's framing too and goes with it.
          this.pendingPrefix = "";
          this.buf = this.buf.slice(CLIXML_HEADER.length);
          this.mode = "headerEol";
          break;
        }
        case "headerEol": {
          if (this.buf.length === 0) return;
          if (this.buf.startsWith("\r\n")) this.buf = this.buf.slice(2);
          else if (this.buf === "\r") return; // could still become "\r\n"
          else if (this.buf.startsWith("\n") || this.buf.startsWith("\r")) {
            this.buf = this.buf.slice(1);
          }
          this.mode = "scan";
          break;
        }
        case "scan": {
          if (!this.scanForObjs()) return;
          break;
        }
        case "objs": {
          if (!this.parseObjsChild()) return;
          break;
        }
      }
    }
  }

  /**
   * ARMED, between a marker and its envelope. Everything is the command's own
   * stderr and is forwarded untouched; we are only watching for the envelope to
   * start. Measured: a `[Console]::Error.WriteLine` really does land in here,
   * between the marker and `<Objs`, which is why raw text is expected at this
   * point rather than treated as a reason to stop.
   *
   * The tail held back is at most four bytes — a partial `<Objs` split across a
   * chunk boundary must not be forwarded as raw and then re-examined.
   *
   * Reached ONLY from the marker test, never from the end of an envelope: a
   * second `<Objs …>` needs a second `#< CLIXML` in front of it (headerRetry),
   * so an `<Objs …>` the command prints later is text, not an envelope.
   *
   * Returns true if the state changed and pump should keep going.
   */
  private scanForObjs(): boolean {
    const at = this.buf.indexOf(OBJS_OPEN);
    if (at === -1) {
      const keep = partialTailLength(this.buf, OBJS_OPEN);
      this.emitRaw(this.buf.slice(0, this.buf.length - keep));
      this.buf = keep === 0 ? "" : this.buf.slice(this.buf.length - keep);
      return false;
    }
    this.emitRaw(this.buf.slice(0, at));
    this.buf = this.buf.slice(at);

    const close = this.buf.indexOf(">");
    if (close === -1) return false; // opening tag split across chunks
    const tag = this.buf.slice(0, close + 1);
    if (!/^<Objs(\s[^<>]*)?\/?>$/.test(tag)) {
      // Not the envelope after all (a command printing `<Objsomething>`, or an
      // ordinary `<` in its output). Forward the `<` and carry on looking: these
      // are the command's bytes, and one of them is not a reason to stop
      // decoding PowerShell's block when it finally arrives.
      this.emitRaw("<");
      this.buf = this.buf.slice(1);
      return true;
    }
    this.buf = this.buf.slice(close + 1);
    if (tag.endsWith("/>")) {
      // A complete, empty envelope: disarm, exactly as a `</Objs>` would.
      this.emitDecoded("");
      this.mode = "headerRetry";
      return true;
    }
    this.pendingPrefix += tag;
    this.envelopeDirty = false;
    this.mode = "objs";
    return true;
  }

  /**
   * True for a progress record we are willing to DELETE.
   *
   * Progress records are module-autoload noise ("Preparing modules for first
   * use.") that PowerShell only serializes because it is talking to a pipe, so
   * in a block that is entirely PowerShell's they carry nothing the caller asked
   * for. In a block that has already proved to contain something we did not
   * produce, the next progress record may be the command's own bytes — and this
   * decoder does not delete those. Noise is recoverable; stderr is not.
   */
  private isDeletableProgress(tag: string): boolean {
    return !this.envelopeDirty && /\bS="progress"/i.test(tag);
  }

  /**
   * Inside `<Objs…>`. Consume exactly one child — a record, a stray text run, or
   * the closing tag — and say whether pump may continue.
   *
   * Anything we do not positively recognize is FORWARDED, in place, and marks
   * the envelope dirty. It is never guessed at and never dropped, and it no
   * longer ends decoding either: a single `<` in a script's own stderr
   * (`echo "a<b" 1>&2`, XML output, a nested tool) used to send the rest of the
   * command down the pass-through path, which handed every LATER error back in
   * exactly the shredded form this module exists to undo.
   */
  private parseObjsChild(): boolean {
    if (this.buf.length === 0) return false;

    if (this.buf[0] !== "<") {
      // Raw text interleaved into the serialized block — measured: a
      // [Console]::Error.WriteLine lands here, unserialized. Forward it exactly,
      // in place, WHITESPACE INCLUDED: the measured payloads carry no serializer
      // formatting between records, so a whitespace-only run here was written by
      // the command, and deleting it would be deleting the caller's bytes.
      const next = this.buf.indexOf("<");
      const run = next === -1 ? this.buf : this.buf.slice(0, next);
      this.emitRaw(run);
      this.buf = this.buf.slice(run.length);
      return next !== -1;
    }

    const close = this.buf.indexOf(">");
    if (close === -1) return false; // tag split across chunks

    const tag = this.buf.slice(0, close + 1);

    if (/^<\/Objs\s*>$/.test(tag)) {
      // The envelope's own closing tag is framing and goes — unless something in
      // this block was not ours, in which case the block is forwarded whole and
      // arriving without its closing tag would be us editing the command's XML.
      if (this.envelopeDirty) this.emitRaw(tag);
      else this.emitDecoded("");
      this.buf = this.buf.slice(tag.length);
      this.envelopeDirty = false;
      this.mode = "headerRetry";
      return true;
    }

    if (/^<S(\s[^<>]*)?\/>$/.test(tag)) {
      this.emitDecoded("");
      this.buf = this.buf.slice(tag.length);
      return true;
    }

    if (/^<S(\s[^<>]*)?>$/.test(tag)) {
      const end = this.buf.indexOf("</S>", tag.length);
      if (end === -1) return false; // record still arriving
      const kind = /\bS="([^"]*)"/.exec(tag)?.[1] ?? "";
      const body = decodeClixmlText(this.buf.slice(tag.length, end));
      // EVERY stream kind is forwarded, error and warning and verbose and debug
      // and information and anything Microsoft adds later, and none of them gets
      // a synthesized "WARNING:"-style prefix: the serialized text is what the
      // caller's script produced, a prefix would be text we invented, and its
      // console spelling is localized anyway. `kind` is read only so a future
      // reader can see the discrimination point exists — nothing is dropped on
      // it. Records are emitted in arrival order, so a warning that preceded an
      // error still precedes it here.
      void kind;
      this.emitDecoded(body);
      this.buf = this.buf.slice(end + 4);
      return true;
    }

    if (/^<Obj(\s[^<>]*)?\/>$/.test(tag)) {
      if (this.isDeletableProgress(tag)) {
        this.emitDecoded("");
        this.buf = this.buf.slice(tag.length);
        return true;
      }
      this.emitRaw(tag);
      this.buf = this.buf.slice(tag.length);
      this.envelopeDirty = true;
      return true;
    }

    if (/^<Obj(\s[^<>]*)?>$/.test(tag)) {
      const end = this.findObjEnd(tag.length);
      if (end === -1) {
        // Either still arriving, or unbalanced. Waiting is safe: the cap in run()
        // turns "never closes" into a pass-through instead of a leak.
        return false;
      }
      if (this.isDeletableProgress(tag)) {
        this.emitDecoded("");
        this.buf = this.buf.slice(end);
        return true;
      }
      // Any OTHER serialized object is a shape we cannot render faithfully, and
      // silently dropping it would lose data the caller produced. Forward the
      // whole record untouched — ugly, lossless, honest — and keep decoding the
      // records that come after it.
      this.emitRaw(this.buf.slice(0, end));
      this.buf = this.buf.slice(end);
      this.envelopeDirty = true;
      return true;
    }

    // Not a shape our serializer produces, so it is the command's own text.
    // Forward just the `<` and rescan from the next character rather than
    // swallowing everything up to the next `>`: `a < b` is followed by REAL
    // records, and treating `< b\r\n<S S="Error">` as one unknown tag would hand
    // the caller their next error back shredded. A token that is nonetheless
    // unmistakably one XML tag (no interior `<`) is markup we did not write, so
    // it dirties the envelope; a stray `<` in prose does not.
    this.emitRaw("<");
    this.buf = this.buf.slice(1);
    if (/^<\/?[A-Za-z][^<>]*\/?>$/.test(tag)) this.envelopeDirty = true;
    return true;
  }

  /**
   * Index just past the `</Obj>` matching an `<Obj…>` that opened at 0, or -1.
   *
   * Depth-counted, because a serialized record nests. `<Objs` must not read as
   * an `<Obj` open (the lookahead), `</Objs>` must not read as its close (the
   * alternation is ordered so the longer tag wins), and a self-closing `<Obj …/>`
   * changes no depth.
   */
  private findObjEnd(from: number): number {
    const pattern = /<\/Objs\s*>|<Obj(?=[\s/>])[^<>]*>|<\/Obj\s*>/g;
    pattern.lastIndex = from;
    let depth = 1;
    for (let match = pattern.exec(this.buf); match !== null; match = pattern.exec(this.buf)) {
      const text = match[0];
      if (text.startsWith("</Objs")) return -1; // envelope closed inside a record
      if (text.startsWith("</Obj")) {
        depth -= 1;
        if (depth === 0) return match.index + text.length;
      } else if (!text.endsWith("/>")) {
        depth += 1;
      }
    }
    return -1;
  }
}
