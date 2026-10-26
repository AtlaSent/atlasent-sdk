import { spawn } from "node:child_process";
import { once } from "node:events";
import { createHmac } from "node:crypto";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createOperationsPreviewHandler, type OperationsPreviewDeps } from "../src/preview-server.js";
import { signSessionToken } from "../src/session-token.js";
import { makeOrder, NOW } from "./fakes.js";

const CLIENT_ID = "preview-client";
const SECRET = "synthetic-preview-secret";
const SHOP = "preview.myshopify.com";
const t = Math.floor(NOW.getTime() / 1000);
const token = (claims: Record<string, unknown> = {}, secret = SECRET) => signSessionToken({
  iss: `https://${SHOP}/admin`, dest: `https://${SHOP}`, aud: CLIENT_ID,
  sub: "42", exp: t + 60, nbf: t - 5, ...claims,
}, secret);

let server: Server | undefined;
afterEach(async () => {
  if (!server) return;
  server.closeAllConnections();
  await new Promise<void>((resolve) => server!.close(() => resolve()));
  server = undefined;
});

async function start(extra: Partial<OperationsPreviewDeps> = {}) {
  const getOrder = vi.fn(async () => makeOrder({ id: 1001, delivery: "delivered" }));
  // Deliberately provide no refund method, runtime client, ledger or approvals client.
  const adminFor = vi.fn(async () => ({ getOrder }));
  server = createServer(createOperationsPreviewHandler({
    clientId: CLIENT_ID, clientSecret: SECRET, allowedShops: [SHOP],
    now: () => NOW, adminFor, ...extra,
  }));
  await new Promise<void>((resolve) => server!.listen(0, "127.0.0.1", resolve));
  return { base: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, getOrder, adminFor };
}

const request = (base: string, body: unknown = { orderId: "1001", amount: "18.99" }, auth = `Bearer ${token()}`) =>
  fetch(`${base}/api/operations/refund-preview`, {
    method: "POST", headers: { authorization: auth, "content-type": "application/json" },
    body: JSON.stringify(body),
  });

describe("standalone read-only preview server", () => {
  it("reads only the authenticated shop/order and never treats caller approval as authority", async () => {
    const s = await start();
    const session = token();
    const response = await request(s.base, {
      orderId: "1001", amount: "18.99", shop: "attacker.myshopify.com",
      approved: true, execute: true, approvalRequestId: "forged", customerEmail: "forged@example.com",
    }, `Bearer ${session}`);
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body).toMatchObject({
      mode: "read_only", authorization: "not_evaluated", execution: "not_attempted",
      customer_notification: "not_sent", observed: { order_id: "gid://shopify/Order/1001", requested_cents: 1899 },
    });
    expect(JSON.stringify(body)).not.toMatch(/forged|attacker/);
    expect(s.adminFor).toHaveBeenCalledExactlyOnceWith(SHOP, session);
    expect(s.getOrder).toHaveBeenCalledExactlyOnceWith("gid://shopify/Order/1001");
  });

  it.each([
    ["missing", "", 401],
    ["bad signature", `Bearer ${token({}, "wrong-secret")}`, 401],
    ["expired", `Bearer ${token({ exp: t - 120 })}`, 401],
    ["wrong audience", `Bearer ${token({ aud: "different-client" })}`, 401],
    ["wrong shop", `Bearer ${token({ iss: "https://other.myshopify.com/admin", dest: "https://other.myshopify.com" })}`, 403],
  ])("refuses %s sessions before any provider access", async (_, auth, status) => {
    const s = await start();
    expect((await request(s.base, undefined, String(auth))).status).toBe(status);
    expect(s.adminFor).not.toHaveBeenCalled();
    expect(s.getOrder).not.toHaveBeenCalled();
  });

  it.each([null, [], {}, { orderId: "1001", amount: "0" }, { orderId: "1001", amount: 1899 },
    { orderId: "https://other.myshopify.com/orders/1001", amount: "18.99" }])("rejects invalid input %j before reads", async (input) => {
    const s = await start();
    expect((await request(s.base, input)).status).toBe(400);
    expect(s.adminFor).not.toHaveBeenCalled();
  });

  it("has no write, resume, webhook or method-override route even for a valid session and signed webhook", async () => {
    const s = await start();
    const raw = JSON.stringify({ orderId: "1001", amount: "18.99", approvalRequestId: "forged", execute: true });
    for (const path of ["/api/refunds", "/api/refunds/resume", "/webhooks/refunds-create", "/api/operations/refund-preview/execute"]) {
      for (const method of ["POST", "OPTIONS"]) {
        const response = await fetch(s.base + path, {
          method, headers: {
            authorization: `Bearer ${token()}`, "content-type": "application/json",
            "x-shopify-hmac-sha256": createHmac("sha256", SECRET).update(raw).digest("base64"),
            "x-shopify-topic": "refunds/create", "x-shopify-shop-domain": SHOP,
            "x-http-method-override": "POST",
          }, ...(method === "POST" ? { body: raw } : {}),
        });
        expect(response.status).toBe(404);
      }
    }
    expect((await fetch(s.base + "/api/operations/refund-preview", { method: "PUT", body: raw })).status).toBe(404);
    expect(s.adminFor).not.toHaveBeenCalled();
  });

  it("allows only preview preflight and discloses read-only health", async () => {
    const s = await start();
    const response = await fetch(s.base + "/api/operations/refund-preview", { method: "OPTIONS" });
    expect(response.status).toBe(204);
    expect(response.headers.get("access-control-allow-methods")).toBe("POST, OPTIONS");
    expect(await (await fetch(s.base + "/healthz")).json()).toEqual({ ok: true, mode: "read_only" });
    expect(s.adminFor).not.toHaveBeenCalled();
  });

  it("returns unavailable on missing/revoked Admin API access without leaking the credential error", async () => {
    const s = await start({ adminFor: async () => { throw new Error("secret credential rejected"); } });
    const response = await request(s.base);
    expect(response.status).toBe(503);
    expect(await response.json()).toEqual({ error: "Shopify connection unavailable", mode: "read_only" });
    expect(s.getOrder).not.toHaveBeenCalled();
  });

  it("starts the default CLI without AtlaSent runtime credentials", async () => {
    const env: NodeJS.ProcessEnv = { ...process.env, SHOPIFY_CLIENT_ID: CLIENT_ID, SHOPIFY_CLIENT_SECRET: SECRET, SHOPIFY_SHOP: SHOP, PORT: "0" };
    delete env.ATLASENT_API_KEY;
    delete env.ATLASENT_ENVIRONMENT;
    const child = spawn(process.execPath, ["--import", import.meta.resolve("tsx"), fileURLToPath(new URL("../src/preview-server.ts", import.meta.url))], {
      env, stdio: ["ignore", "pipe", "pipe"],
    });
    try {
      const output = await Promise.race([
        once(child.stdout, "data").then(([data]) => String(data)),
        once(child, "exit").then(([code]) => { throw new Error(`preview server exited: ${code}`); }),
      ]);
      expect(output).toContain("AtlaSent read-only order preview listening");
    } finally {
      if (child.exitCode === null && child.signalCode === null) {
        const exited = once(child, "exit");
        child.kill();
        await exited;
      }
    }
  });
});
