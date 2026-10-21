// Run in a separate process by ledger.test.ts: records `count` refunds into
// the JSON ledger at `path`, each with gate_ref `<prefix>-<i>` for order `<i + 1>`.
import { JsonFileLedger } from "../../src/ledger.js";

const [path, prefix, countText] = process.argv.slice(2);
if (!path || !prefix || !countText) throw new Error("usage: ledger-writer <path> <prefix> <count>");
const ledger = new JsonFileLedger(path, { lockTimeoutMs: 20_000 });
for (let i = 0; i < Number(countText); i++) {
  await ledger.recordAuthorized({
    gate_ref: `${prefix}-${i}`,
    permit_sha256: "0".repeat(64),
    audit_hash: "audit",
    order_id: `gid://shopify/Order/${i + 1}`,
    amount_cents: 1000 + i,
    actor_id: "shopify-staff:test",
    authorized_at: new Date(0).toISOString(),
  });
}
