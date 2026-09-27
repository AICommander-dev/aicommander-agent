import { describe, it, expect } from "vitest";
import {
  generateSessionCode,
  isValidSessionCode,
  maskSessionCode,
  sessionCodePrefix,
} from "../codes.js";

const ALPHABET_CLASS = /^[ABCDEFGHJKMNPQRSTVWXYZ0-9]{4}$/;

describe("generateSessionCode", () => {
  it("returns AIC-XXXX-XXXX-XXXX format", () => {
    const code = generateSessionCode();
    expect(code).toMatch(
      /^AIC-[ABCDEFGHJKMNPQRSTVWXYZ0-9]{4}-[ABCDEFGHJKMNPQRSTVWXYZ0-9]{4}-[ABCDEFGHJKMNPQRSTVWXYZ0-9]{4}$/,
    );
  });

  it("has the AIC- prefix and three 4-char groups", () => {
    const code = generateSessionCode();
    const parts = code.split("-");
    expect(parts[0]).toBe("AIC");
    expect(parts).toHaveLength(4);
    for (const group of parts.slice(1)) {
      expect(group).toMatch(ALPHABET_CLASS);
    }
  });

  it("never emits ambiguous characters (I, L, O, U)", () => {
    for (let i = 0; i < 100; i++) {
      const code = generateSessionCode();
      expect(code.slice(4)).not.toMatch(/[ILOU]/);
    }
  });

  it("produces varied (effectively unique) codes across many draws", () => {
    const codes = new Set(Array.from({ length: 1000 }, generateSessionCode));
    // 59 bits of entropy -> collisions across 1000 draws are astronomically unlikely.
    expect(codes.size).toBe(1000);
  });

  it("every generated code passes isValidSessionCode", () => {
    for (let i = 0; i < 200; i++) {
      expect(isValidSessionCode(generateSessionCode())).toBe(true);
    }
  });
});

describe("isValidSessionCode", () => {
  it("accepts valid new-format codes", () => {
    expect(isValidSessionCode("AIC-ABCD-2345-WXYZ")).toBe(true);
    expect(isValidSessionCode("AIC-0123-4567-89AB")).toBe(true);
  });

  it("rejects the old AIC-WORD-NNNN format", () => {
    expect(isValidSessionCode("AIC-WOLF-1234")).toBe(false);
    expect(isValidSessionCode("AIC-CROW-1000")).toBe(false);
    expect(isValidSessionCode("AIC-ASH-9999")).toBe(false);
  });

  it("rejects missing AIC- prefix", () => {
    expect(isValidSessionCode("ABCD-2345-WXYZ")).toBe(false);
    expect(isValidSessionCode("abcd-2345-wxyz")).toBe(false);
  });

  it("accepts lowercase / mixed case (codes are case-insensitive)", () => {
    // The base32 alphabet is case-insensitive by design; codes are minted
    // UPPERCASE but a lowercased copy (hand-typed, lowercased UI, MCP client)
    // must still validate so it keys to the same stored session.
    expect(isValidSessionCode("aic-abcd-2345-wxyz")).toBe(true);
    expect(isValidSessionCode("AIC-abcd-2345-wxyz")).toBe(true);
    // Surrounding whitespace is trimmed too.
    expect(isValidSessionCode("  aic-abcd-2345-wxyz  ")).toBe(true);
  });

  it("rejects ambiguous characters (I, L, O, U)", () => {
    expect(isValidSessionCode("AIC-IIII-2345-WXYZ")).toBe(false);
    expect(isValidSessionCode("AIC-ABCD-LLLL-WXYZ")).toBe(false);
    expect(isValidSessionCode("AIC-ABCD-2345-OOOO")).toBe(false);
    expect(isValidSessionCode("AIC-ABCD-2345-UUUU")).toBe(false);
  });

  it("rejects wrong group count or length", () => {
    expect(isValidSessionCode("AIC-ABCD-2345")).toBe(false);
    expect(isValidSessionCode("AIC-ABCD-2345-WXYZ-EXTRA")).toBe(false);
    expect(isValidSessionCode("AIC-ABC-2345-WXYZ")).toBe(false);
    expect(isValidSessionCode("AIC-ABCDE-2345-WXYZ")).toBe(false);
  });

  it("rejects empty or malformed", () => {
    expect(isValidSessionCode("")).toBe(false);
    expect(isValidSessionCode("AIC--2345-WXYZ")).toBe(false);
    expect(isValidSessionCode("AIC-ABCD-2345-")).toBe(false);
    expect(isValidSessionCode("AIC-ABCD")).toBe(false);
  });
});

describe("maskSessionCode", () => {
  it("reveals only the prefix + first group", () => {
    expect(maskSessionCode("AIC-7K3P-WX9M-RTBN")).toBe("AIC-7K3P-***-***");
    expect(maskSessionCode("AIC-ABCD-2345-WXYZ")).toBe("AIC-ABCD-***-***");
  });

  it("never exposes the masked groups", () => {
    const code = generateSessionCode();
    const masked = maskSessionCode(code);
    const groups = code.split("-"); // ["AIC", g1, g2, g3]
    expect(masked).toContain(groups[1]!);
    expect(masked).not.toContain(groups[2]!);
    expect(masked).not.toContain(groups[3]!);
  });

  it("passes through non-code / placeholder strings unchanged", () => {
    expect(maskSessionCode("—")).toBe("—");
    expect(maskSessionCode("AIC-WOLF-1234")).toBe("AIC-WOLF-1234");
    expect(maskSessionCode("")).toBe("");
  });
});

describe("sessionCodePrefix", () => {
  it("returns the first two chars (after AIC-), UPPERCASE", () => {
    expect(sessionCodePrefix("AIC-7K3P-WX9M-RTBN")).toBe("7K");
    expect(sessionCodePrefix("aic-abcd-2345-wxyz")).toBe("AB");
    expect(sessionCodePrefix("  AIC-ABCD-2345-WXYZ  ")).toBe("AB");
  });

  it("never leaks the secret groups", () => {
    const code = generateSessionCode();
    const groups = code.split("-"); // ["AIC", g1, g2, g3]
    const prefix = sessionCodePrefix(code)!;
    expect(prefix).toBe(groups[1]!.slice(0, 2));
    expect(prefix.length).toBe(2);
    expect(prefix).not.toContain(groups[2]!);
    expect(prefix).not.toContain(groups[3]!);
  });

  it("returns null for non-code / placeholder strings", () => {
    expect(sessionCodePrefix("—")).toBeNull();
    expect(sessionCodePrefix("AIC-WOLF-1234")).toBeNull();
    expect(sessionCodePrefix("")).toBeNull();
  });
});
