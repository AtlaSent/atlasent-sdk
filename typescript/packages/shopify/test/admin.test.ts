import { describe, expect, it } from "vitest";
import { normalizeShopDomain, toOrderGid } from "../src/admin.js";

describe("normalizeShopDomain", () => {
  it("accepts the forms Shopify sends", () => {
    for (const s of ["pinecone.myshopify.com", "https://pinecone.myshopify.com/", "http://Pinecone.myshopify.com//", " pinecone.myshopify.com "]) {
      expect(normalizeShopDomain(s)).toBe("pinecone.myshopify.com");
    }
  });
  it("rejects anything that is not a myshopify.com domain", () => {
    for (const s of ["", "evil.com", "pinecone.myshopify.com.evil.com", "https://evil.com/pinecone.myshopify.com", "-x.myshopify.com", "a.b.myshopify.com"]) {
      expect(() => normalizeShopDomain(s)).toThrow();
    }
  });
  it("rejects oversized input quickly instead of scanning it", () => {
    const start = Date.now();
    expect(() => normalizeShopDomain("a" + "/".repeat(100_000) + "x")).toThrow(/too long/);
    expect(() => normalizeShopDomain("a" + "/".repeat(250))).toThrow();
    expect(Date.now() - start).toBeLessThan(100);
  });
});

describe("toOrderGid", () => {
  it("accepts numeric ids and order gids only", () => {
    expect(toOrderGid("123")).toBe("gid://shopify/Order/123");
    expect(toOrderGid("gid://shopify/Order/123")).toBe("gid://shopify/Order/123");
    for (const s of ["", "abc", "gid://shopify/Customer/1", "12 3"]) expect(() => toOrderGid(s)).toThrow();
  });
});
