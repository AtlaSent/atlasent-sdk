/**
 * Pre-flight for the first live run: are the Shopify dev store, the Stripe
 * test-mode key and the AtlaSent test org set up the way the gates need,
 * before any refund is attempted?
 *
 *   npm run preflight                      # read-only checks
 *   npm run preflight -- --probe-policy    # also asks AtlaSent to decide 3 sample refunds
 *   npm run preflight -- --probe-policy --probe-escalation
 *                                          # and a 4th, which opens a real approval request
 *
 * Env: ATLASENT_API_KEY, ATLASENT_ENVIRONMENT (required); ATLASENT_BASE_URL;
 * SHOPIFY_SHOP + SHOPIFY_ADMIN_TOKEN (optional, checks Shopify);
 * STRIPE_SECRET_KEY (optional, checks Stripe).
 *
 * WHAT IT DOES NOT DO. It never creates a refund, never verifies (consumes) a
 * permit, and never prints a credential. The read-only checks change
 * nothing. `--probe-policy` is NOT read-only: each probe is a real
 * evaluation, so it writes an audit entry, and the allowed one mints a
 * permit that is never used and expires. `--probe-escalation` also opens an
 * approval request a manager will see; decline it.
 *
 * Each check reports pass, fail or not checked. "Not checked" is said out
 * loud: a check this script cannot make is never reported as a pass.
 */

import { randomBytes } from "node:crypto";
import { parseArgs } from "node:util";
import { pathToFileURL } from "node:url";
import { AtlaSentClient, type ApiKeySelfResponse, type EvaluateRequest, type EvaluateResponse } from "@atlasent/sdk";

export type CheckStatus = "pass" | "fail" | "not_checked";

export interface Check {
  system: "atlasent" | "shopify" | "stripe";
  name: string;
  status: CheckStatus;
  detail: string;
}

/** The scopes every gate key needs (`resource:action` form, the only form a key can hold). */
export const REQUIRED_ATLASENT_SCOPES = ["evaluate:write", "verify:execute"] as const;
export const REQUIRED_SHOPIFY_SCOPES = ["read_orders", "write_orders"] as const;

const errorText = (err: unknown) => (err instanceof Error ? err.message : String(err));

export interface AtlaSentProbeClient {
  keySelf(): Promise<ApiKeySelfResponse>;
  evaluate(input: EvaluateRequest): Promise<EvaluateResponse>;
}

export interface PolicyProbe {
  label: string;
  context: Record<string, unknown>;
  expect: { decision: "allow" | "deny" | "escalate"; denyCode?: string };
}

/** The demo policy's rules, one probe each. Escalation is separate: it opens an approval request. */
export const POLICY_PROBES: PolicyProbe[] = [
  {
    label: "$18.99, delivered 5 days ago",
    context: { amount_cents: 1899, currency: "USD", order_status: "delivered", days_since_delivery: 5, refundable_cents: 3499 },
    expect: { decision: "allow" },
  },
  {
    label: "$12.00, not delivered",
    context: { amount_cents: 1200, currency: "USD", order_status: "not_delivered", refundable_cents: 2450 },
    expect: { decision: "deny", denyCode: "ORDER_NOT_DELIVERED" },
  },
  {
    label: "$25.00, 45 days after delivery",
    context: { amount_cents: 2500, currency: "USD", order_status: "delivered", days_since_delivery: 45, refundable_cents: 4200 },
    expect: { decision: "deny", denyCode: "RETURN_WINDOW_EXPIRED" },
  },
];

export const ESCALATION_PROBE: PolicyProbe = {
  label: "$72.00, delivered 3 days ago",
  context: { amount_cents: 7200, currency: "USD", order_status: "delivered", days_since_delivery: 3, refundable_cents: 12900 },
  expect: { decision: "escalate", denyCode: "MANAGER_APPROVAL_REQUIRED" },
};

export async function checkAtlaSent(
  client: AtlaSentProbeClient,
  opts: { environment: string; probes: PolicyProbe[]; actor: string },
): Promise<Check[]> {
  const checks: Check[] = [];
  const add = (name: string, status: CheckStatus, detail: string) => checks.push({ system: "atlasent", name, status, detail });

  let self: ApiKeySelfResponse;
  try {
    self = await client.keySelf();
  } catch (err) {
    add("API key accepted", "fail", `the runtime rejected the key or could not be reached: ${errorText(err)}`);
    return checks;
  }
  add("API key accepted", "pass", `key ${self.keyId} in org ${self.orgId}`);
  if (self.environment === "test") add("Test key", "pass", "the key's environment is test");
  else add("Test key", "fail", `the key's environment is ${JSON.stringify(self.environment)}; use a test key for the first live run`);
  const missing = REQUIRED_ATLASENT_SCOPES.filter((s) => !self.scopes.includes(s));
  add("Key scopes", missing.length === 0 ? "pass" : "fail", missing.length === 0 ? REQUIRED_ATLASENT_SCOPES.join(", ") : `missing ${missing.join(", ")}`);
  if (self.expiresAt !== null && Date.parse(self.expiresAt) < Date.now() + 86_400_000) {
    add("Key expiry", "fail", `the key expires at ${self.expiresAt}, within a day`);
  }
  add("Approval claim permission", "not_checked", "no read-only way to check that this key may claim an approved permit; the first real approval shows it");

  if (opts.probes.length === 0) {
    add("Refund policy", "not_checked", "run with --probe-policy to have AtlaSent decide sample refunds against the org's finance.payment.authorize bundle");
    return checks;
  }
  for (const p of opts.probes) {
    let ev: EvaluateResponse;
    try {
      ev = await client.evaluate({
        actor_id: opts.actor,
        action_type: "finance.payment.authorize",
        environment: opts.environment,
        resource_id: "preflight-probe",
        execution_payload_hash: randomBytes(32).toString("hex"),
        context: { ...p.context, target: { id: "preflight-probe" }, preflight: true },
      });
    } catch (err) {
      add(`Policy: ${p.label}`, "fail", `evaluate failed: ${errorText(err)}`);
      continue;
    }
    const codeOk = p.expect.denyCode === undefined || ev.deny_code === p.expect.denyCode;
    const ok = ev.decision === p.expect.decision && codeOk;
    const got = `${ev.decision}${ev.deny_code ? ` ${ev.deny_code}` : ""}`;
    const want = `${p.expect.decision}${p.expect.denyCode ? ` ${p.expect.denyCode}` : ""}`;
    let detail = ok ? got : `expected ${want}, got ${got}${ev.reason ? ` (${ev.reason})` : ""}`;
    if (!ok && p.expect.decision === "allow" && (ev.decision === "escalate" || ev.decision === "hold")) {
      detail += ". If the action class requires human or independent approval, every refund routes to a manager";
    }
    if (!ok && ev.deny_code === "NO_TEMPLATE_MATCH") detail += ". The bundle may not carry the demo policy, or is not active for this environment";
    if (p.expect.decision === "escalate" && ev.decision === "escalate") {
      detail += ev.approvalRequestId
        ? `; approval request ${ev.approvalRequestId} opened. Decline it in the console`
        : "; but the runtime returned no approval request id, so an escalated refund cannot be resumed";
      if (!ev.approvalRequestId) {
        add(`Policy: ${p.label}`, "fail", detail);
        continue;
      }
    }
    add(`Policy: ${p.label}`, ok ? "pass" : "fail", detail);
  }
  return checks;
}

export async function checkShopify(
  doFetch: typeof fetch,
  opts: { shop: string; accessToken: string; apiVersion: string },
): Promise<Check[]> {
  const checks: Check[] = [];
  const add = (name: string, status: CheckStatus, detail: string) => checks.push({ system: "shopify", name, status, detail });
  const gql = async <T>(query: string): Promise<{ data: T } | { error: string }> => {
    try {
      const res = await doFetch(`https://${opts.shop}/admin/api/${opts.apiVersion}/graphql.json`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-shopify-access-token": opts.accessToken },
        body: JSON.stringify({ query }),
        signal: AbortSignal.timeout(10_000),
      });
      const body = (await res.json().catch(() => null)) as { data?: T; errors?: unknown } | null;
      if (res.ok && body !== null && body.data !== undefined && body.errors === undefined) return { data: body.data };
      const why = body?.errors !== undefined ? `: ${JSON.stringify(body.errors).slice(0, 300)}` : "";
      return { error: `HTTP ${res.status}${why}` };
    } catch (err) {
      return { error: errorText(err) };
    }
  };
  const base = await gql<{
    shop?: { name?: string; myshopifyDomain?: string };
    currentAppInstallation?: { accessScopes?: { handle?: string }[] };
  }>("{ shop { name myshopifyDomain } currentAppInstallation { accessScopes { handle } } }");
  if ("error" in base) {
    add("Admin API token accepted", "fail", base.error);
    return checks;
  }
  const data = base.data;
  add("Admin API token accepted", "pass", `${data.shop?.name ?? "shop"} (${data.shop?.myshopifyDomain ?? opts.shop}), API ${opts.apiVersion}`);
  // Asked separately, so a field this API version lacks cannot fail the token check.
  const plan = await gql<{ shop?: { plan?: { partnerDevelopment?: boolean } } }>("{ shop { plan { partnerDevelopment } } }");
  const dev = "data" in plan ? plan.data.shop?.plan?.partnerDevelopment : undefined;
  if (dev === true) add("Development store", "pass", "refunds here move no real money when orders are paid with the manual gateway");
  else if (dev === false) add("Development store", "fail", "this is not a Partner development store; run the first live demo on a dev store");
  else add("Development store", "not_checked", `Shopify did not report plan.partnerDevelopment${"error" in plan ? ` (${plan.error})` : ""}`);
  const scopes = (data.currentAppInstallation?.accessScopes ?? []).map((s) => s.handle).filter((h): h is string => typeof h === "string");
  // write_orders implies read_orders in Shopify's scope model.
  const have = (s: string) => scopes.includes(s) || (s === "read_orders" && scopes.includes("write_orders"));
  const missing = REQUIRED_SHOPIFY_SCOPES.filter((s) => !have(s));
  add("Access scopes", missing.length === 0 ? "pass" : "fail", missing.length === 0 ? REQUIRED_SHOPIFY_SCOPES.join(", ") : `missing ${missing.join(", ")} (have: ${scopes.join(", ") || "none"})`);
  add("Staff cannot refund in the admin", "not_checked", "a store setting; confirm with a restricted test staff account that it cannot refund");
  return checks;
}

export async function checkStripe(doFetch: typeof fetch, opts: { secretKey: string; baseUrl?: string }): Promise<Check[]> {
  const checks: Check[] = [];
  const add = (name: string, status: CheckStatus, detail: string) => checks.push({ system: "stripe", name, status, detail });
  const k = opts.secretKey;
  if (k.startsWith("sk_live_") || k.startsWith("rk_live_")) {
    add("Test-mode key", "fail", "this is a live-mode key; the demo runs in test mode only, and nothing else was checked");
    return checks;
  }
  if (!k.startsWith("sk_test_") && !k.startsWith("rk_test_")) {
    add("Test-mode key", "fail", "not a Stripe secret or restricted key (expected sk_test_ or rk_test_)");
    return checks;
  }
  add("Test-mode key", "pass", k.startsWith("rk_") ? "restricted test key" : "test secret key");
  if (k.startsWith("sk_")) {
    add("Restricted key", "fail", "a full secret key can do anything; give the gate a restricted key (read PaymentIntents and Charges, write Refunds)");
  }
  const base = (opts.baseUrl ?? "https://api.stripe.com").replace(/\/$/, "");
  try {
    const res = await doFetch(`${base}/v1/payment_intents?limit=1`, {
      headers: { authorization: `Bearer ${k}` },
      signal: AbortSignal.timeout(10_000),
    });
    if (res.ok) add("Read PaymentIntents", "pass", "the key can list PaymentIntents");
    else add("Read PaymentIntents", "fail", `HTTP ${res.status}; the gate reads each PaymentIntent before refunding`);
  } catch (err) {
    add("Read PaymentIntents", "fail", errorText(err));
  }
  add("Write Refunds", "not_checked", "cannot be checked without creating a refund; the first gated test-mode refund shows it");
  add("Only the gate can refund", "not_checked", "check that no other key or Dashboard role can create refunds");
  return checks;
}

export function formatChecks(checks: Check[]): string {
  const mark = { pass: "PASS", fail: "FAIL", not_checked: " -- " } as const;
  const lines = checks.map((c) => `  [${mark[c.status]}] ${c.system.padEnd(8)} ${c.name}: ${c.detail}`);
  const fails = checks.filter((c) => c.status === "fail").length;
  const unchecked = checks.filter((c) => c.status === "not_checked").length;
  lines.push("", fails === 0 ? `Ready: no failures. ${unchecked} item(s) cannot be checked from here; see above.` : `${fails} failure(s). Fix them before the live run.`);
  return lines.join("\n");
}

async function main(): Promise<number> {
  const { values } = parseArgs({ options: { "probe-policy": { type: "boolean" }, "probe-escalation": { type: "boolean" } } });
  const apiKey = process.env.ATLASENT_API_KEY;
  const environment = process.env.ATLASENT_ENVIRONMENT;
  if (!apiKey || !environment) {
    console.error("ATLASENT_API_KEY and ATLASENT_ENVIRONMENT are required");
    return 2;
  }
  if (values["probe-escalation"] && !values["probe-policy"]) {
    console.error("--probe-escalation needs --probe-policy");
    return 2;
  }
  const probes = values["probe-policy"] ? [...POLICY_PROBES, ...(values["probe-escalation"] ? [ESCALATION_PROBE] : [])] : [];
  if (probes.length > 0) {
    console.log(`Probing the policy: ${probes.length} real evaluation(s), each writing an audit entry. No permit is used and no refund is made.\n`);
  }
  const atlasent = new AtlaSentClient({ apiKey, ...(process.env.ATLASENT_BASE_URL ? { baseUrl: process.env.ATLASENT_BASE_URL } : {}) });
  const checks = await checkAtlaSent(atlasent, { environment, probes, actor: `preflight:${process.env.USER ?? "operator"}` });

  const shop = process.env.SHOPIFY_SHOP;
  const token = process.env.SHOPIFY_ADMIN_TOKEN;
  if (shop && token) {
    const { normalizeShopDomain, DEFAULT_ADMIN_API_VERSION } = await import("../../shopify/src/admin.js");
    checks.push(...(await checkShopify(fetch, { shop: normalizeShopDomain(shop), accessToken: token, apiVersion: process.env.SHOPIFY_API_VERSION ?? DEFAULT_ADMIN_API_VERSION })));
  } else {
    checks.push({ system: "shopify", name: "Shopify", status: "not_checked", detail: "set SHOPIFY_SHOP and SHOPIFY_ADMIN_TOKEN to check the dev store" });
  }
  const stripeKey = process.env.STRIPE_SECRET_KEY;
  if (stripeKey) checks.push(...(await checkStripe(fetch, { secretKey: stripeKey })));
  else checks.push({ system: "stripe", name: "Stripe", status: "not_checked", detail: "set STRIPE_SECRET_KEY to check the test-mode key" });

  console.log(formatChecks(checks));
  return checks.some((c) => c.status === "fail") ? 1 : 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().then(
    (code) => process.exit(code),
    (err) => {
      console.error(errorText(err));
      process.exit(1);
    },
  );
}
