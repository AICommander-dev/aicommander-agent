import { describe, expect, it } from "vitest";
import zlib from "node:zlib";

import { blackCanvas, blit, encodePng, type RawImage } from "../png-encode.js";
import { pngSize } from "../screenshot.js";

function bgra(width: number, height: number, at: (x: number, y: number) => [number, number, number]): RawImage {
  const data = Buffer.alloc(width * height * 4);
  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      const [r, g, b] = at(x, y);
      const i = (y * width + x) * 4;
      data[i] = b;
      data[i + 1] = g;
      data[i + 2] = r;
      data[i + 3] = 255;
    }
  }
  return { width, height, data };
}

/** Undo the PNG filters (None/Sub/Up — all encodePng emits) back to RGB bytes. */
function decode(png: Buffer): Buffer {
  const width = png.readUInt32BE(16);
  const height = png.readUInt32BE(20);
  const len = png.readUInt32BE(33);
  expect(png.toString("ascii", 37, 41)).toBe("IDAT");
  const raw = zlib.inflateSync(png.subarray(41, 41 + len));
  const stride = width * 3;
  const out = Buffer.alloc(stride * height);
  for (let y = 0; y < height; y++) {
    const f = raw[y * (stride + 1)]!;
    expect([0, 1, 2, 4]).toContain(f);
    for (let i = 0; i < stride; i++) {
      const v = raw[y * (stride + 1) + 1 + i]!;
      const a = i >= 3 ? out[y * stride + i - 3]! : 0;
      const b = y > 0 ? out[(y - 1) * stride + i]! : 0;
      const c = y > 0 && i >= 3 ? out[(y - 1) * stride + i - 3]! : 0;
      const p = a + b - c;
      const paeth = Math.abs(p - a) <= Math.abs(p - b) && Math.abs(p - a) <= Math.abs(p - c) ? a : Math.abs(p - b) <= Math.abs(p - c) ? b : c;
      const pred = f === 1 ? a : f === 2 ? b : f === 4 ? paeth : 0;
      out[y * stride + i] = (v + pred) & 0xff;
    }
  }
  return out;
}

describe("encodePng", () => {
  it("round-trips pixels exactly, BGRA in → RGB out", async () => {
    const img = bgra(37, 23, (x, y) => [(x * 7) & 0xff, (y * 11) & 0xff, (x * y) & 0xff]);
    const png = await encodePng(img);
    expect(pngSize(png)).toEqual({ width: 37, height: 23 });
    const rgb = decode(png);
    for (let y = 0; y < 23; y++) {
      for (let x = 0; x < 37; x++) {
        const i = (y * 37 + x) * 3;
        expect([rgb[i], rgb[i + 1], rgb[i + 2]]).toEqual([(x * 7) & 0xff, (y * 11) & 0xff, (x * y) & 0xff]);
      }
    }
  });

  it("writes valid chunk CRCs", async () => {
    const png = await encodePng(bgra(2, 2, () => [1, 2, 3]));
    // IHDR CRC of a 2x2 RGB8 image is fixed; zlib.crc32 is the reference where available.
    const crc32 = (zlib as unknown as { crc32?: (b: Buffer) => number }).crc32;
    if (crc32) expect(png.readUInt32BE(29)).toBe(crc32(png.subarray(12, 29)));
    expect(png.subarray(-12).toString("hex")).toBe("0000000049454e44ae426082"); // IEND, canonical CRC
  });

  it("refuses a truncated frame rather than encoding garbage", async () => {
    await expect(encodePng({ width: 10, height: 10, data: Buffer.alloc(10) })).rejects.toThrow(/truncated/);
  });
});

describe("blit", () => {
  it("copies into place and clips at the canvas edge", () => {
    const canvas = blackCanvas(4, 2);
    blit(canvas, bgra(3, 3, () => [255, 255, 255]), 2, 1);
    const white = (x: number, y: number) => canvas.data[(y * 4 + x) * 4] === 255;
    expect(white(2, 1)).toBe(true);
    expect(white(3, 1)).toBe(true);
    expect(white(1, 1)).toBe(false);
    expect(white(2, 0)).toBe(false);
    // Untouched pixels stay opaque black.
    expect([...canvas.data.subarray(0, 4)]).toEqual([0, 0, 0, 255]);
  });
});
