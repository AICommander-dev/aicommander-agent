import zlib from "zlib";

/**
 * Minimal, dependency-free PNG encoder for screen captures.
 *
 * Exists so a capture backend only has to hand over raw pixels (which is what
 * every OS screen API produces) and the agent can composite and encode them
 * without shelling out to anything — in particular without
 * the PowerShell + System.Drawing pipeline that antivirus engines classify as an
 * offensive tool (see antivirus-block.ts in @aicommander/protocol).
 *
 * Output is 8-bit truecolour WITHOUT alpha (colour type 2): a screenshot is
 * opaque by definition, and dropping the fourth channel cuts the encoded size
 * by roughly a quarter — which matters against SCREENSHOT_MAX_BYTES.
 */

/** Raw pixels, 4 bytes per pixel, rows top to bottom with no padding. */
export interface RawImage {
  width: number;
  height: number;
  /** BGRA bytes — the layout Electron's `nativeImage.toBitmap()` returns on Windows. */
  data: Buffer;
}

const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

let crcTable: Uint32Array | null = null;
function crc32(buf: Buffer): number {
  if (!crcTable) {
    crcTable = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      crcTable[n] = c >>> 0;
    }
  }
  let crc = 0xffffffff;
  for (let i = 0; i < buf.length; i++) crc = crcTable[(crc ^ buf[i]!) & 0xff]! ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

function chunk(type: string, body: Buffer): Buffer {
  const head = Buffer.alloc(8);
  head.writeUInt32BE(body.length, 0);
  head.write(type, 4, "ascii");
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(Buffer.concat([head.subarray(4), body])), 0);
  return Buffer.concat([head, body, crc]);
}

/** The PNG Paeth predictor. */
function paeth(a: number, b: number, c: number): number {
  const p = a + b - c;
  const pa = Math.abs(p - a);
  const pb = Math.abs(p - b);
  const pc = Math.abs(p - c);
  return pa <= pb && pa <= pc ? a : pb <= pc ? b : c;
}

/**
 * Convert BGRA to filtered RGB scanlines. Each row picks whichever of the None,
 * Sub, Up and Paeth filters has the smallest sum of absolute residuals — the
 * libpng heuristic. Paeth matters for photographic content (wallpapers), Sub/Up
 * for UI imagery (large flat areas, repeated rows).
 */
function filteredScanlines(img: RawImage): Buffer {
  const { width, height, data } = img;
  const stride = width * 3;
  const out = Buffer.alloc((stride + 1) * height);
  let prev = Buffer.alloc(stride);
  let row = Buffer.alloc(stride);
  const sub = Buffer.alloc(stride);
  const up = Buffer.alloc(stride);
  const pae = Buffer.alloc(stride);
  for (let y = 0; y < height; y++) {
    const src = y * width * 4;
    for (let x = 0, s = src, d = 0; x < width; x++, s += 4, d += 3) {
      row[d] = data[s + 2]!; // R
      row[d + 1] = data[s + 1]!; // G
      row[d + 2] = data[s]!; // B
    }
    let sumNone = 0;
    let sumSub = 0;
    let sumUp = 0;
    let sumPaeth = 0;
    for (let i = 0; i < stride; i++) {
      const v = row[i]!;
      const a = i >= 3 ? row[i - 3]! : 0;
      const b = prev[i]!;
      const c = i >= 3 ? prev[i - 3]! : 0;
      const sv = (v - a) & 0xff;
      const uv = (v - b) & 0xff;
      const pv = (v - paeth(a, b, c)) & 0xff;
      sub[i] = sv;
      up[i] = uv;
      pae[i] = pv;
      sumNone += v < 128 ? v : 256 - v;
      sumSub += sv < 128 ? sv : 256 - sv;
      sumUp += uv < 128 ? uv : 256 - uv;
      sumPaeth += pv < 128 ? pv : 256 - pv;
    }
    const at = y * (stride + 1);
    const best = Math.min(sumNone, sumSub, sumUp, sumPaeth);
    if (best === sumUp) {
      out[at] = 2;
      up.copy(out, at + 1);
    } else if (best === sumSub) {
      out[at] = 1;
      sub.copy(out, at + 1);
    } else if (best === sumPaeth) {
      out[at] = 4;
      pae.copy(out, at + 1);
    } else {
      out[at] = 0;
      row.copy(out, at + 1);
    }
    const t = prev;
    prev = row;
    row = t;
  }
  return out;
}

const deflate = (buf: Buffer, level: number): Promise<Buffer> =>
  new Promise((resolve, reject) =>
    zlib.deflate(buf, { level }, (err, res) => (err ? reject(err) : resolve(res))),
  );

/**
 * Encode a BGRA image as an opaque RGB PNG. Compression runs on libuv's thread
 * pool (async zlib), so a 4K encode does not freeze an Electron main process.
 */
export async function encodePng(img: RawImage): Promise<Buffer> {
  if (!Number.isInteger(img.width) || !Number.isInteger(img.height) || img.width < 1 || img.height < 1) {
    throw new Error(`Cannot encode a ${img.width}x${img.height} image.`);
  }
  if (img.data.length < img.width * img.height * 4) {
    throw new Error(
      `Captured image is truncated: ${img.data.length} bytes for ${img.width}x${img.height} pixels.`,
    );
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(img.width, 0);
  ihdr.writeUInt32BE(img.height, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 2; // colour type: truecolour, no alpha
  ihdr[10] = 0; // compression
  ihdr[11] = 0; // filter method
  ihdr[12] = 0; // no interlace
  const idat = await deflate(filteredScanlines(img), 9);
  return Buffer.concat([
    PNG_SIGNATURE,
    chunk("IHDR", ihdr),
    chunk("IDAT", idat),
    chunk("IEND", Buffer.alloc(0)),
  ]);
}

/**
 * Copy `src` into `dst` with its top-left corner at (dx, dy), clipping to dst.
 * Both are BGRA. `dst` areas no source covers keep whatever they were filled
 * with — the caller paints them opaque black, which is how gaps between
 * mismatched monitors look in a whole-desktop capture.
 */
export function blit(dst: RawImage, src: RawImage, dx: number, dy: number): void {
  const x0 = Math.max(0, dx);
  const y0 = Math.max(0, dy);
  const x1 = Math.min(dst.width, dx + src.width);
  const y1 = Math.min(dst.height, dy + src.height);
  if (x1 <= x0 || y1 <= y0) return;
  const bytes = (x1 - x0) * 4;
  for (let y = y0; y < y1; y++) {
    const s = ((y - dy) * src.width + (x0 - dx)) * 4;
    const d = (y * dst.width + x0) * 4;
    src.data.copy(dst.data, d, s, s + bytes);
  }
}

/** A BGRA canvas filled with opaque black. */
export function blackCanvas(width: number, height: number): RawImage {
  const data = Buffer.alloc(width * height * 4);
  for (let i = 3; i < data.length; i += 4) data[i] = 0xff;
  return { width, height, data };
}
