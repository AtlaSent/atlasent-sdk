/**
 * Build the evidence report from an existing decision log.
 *
 *   npm run report -- --log decisions.jsonl --store "Pinecone Pet Supply" \
 *     [--from 2026-10-01 --to 2026-11-01] [--out evidence-out]
 *
 * The log is JSONL of `atlasent.refund_decision.v1` (from the gates'
 * `onDecision` hook) and `atlasent.refund_alarm.v1` records. Lines that are
 * neither are listed in the report, never silently dropped.
 */

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { parseArgs } from "node:util";
import { parseLog } from "./records.js";
import { buildEvidenceReport } from "./report.js";

const { values } = parseArgs({
  options: {
    log: { type: "string" },
    store: { type: "string" },
    from: { type: "string" },
    to: { type: "string" },
    out: { type: "string" },
    simulated: { type: "boolean" },
  },
});
if (!values.log || !values.store) {
  console.error('usage: report --log decisions.jsonl --store "Store name" [--from YYYY-MM-DD --to YYYY-MM-DD] [--out dir] [--simulated]');
  process.exit(2);
}
const day = (s: string) => {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(s)) {
    console.error(`not a date: ${s}`);
    process.exit(2);
  }
  return new Date(`${s}T00:00:00Z`);
};
if ((values.from === undefined) !== (values.to === undefined)) {
  console.error("--from and --to go together");
  process.exit(2);
}
const parsed = parseLog(readFileSync(values.log, "utf8"));
const report = buildEvidenceReport({
  decisions: parsed.decisions,
  alarms: parsed.alarms,
  storeName: values.store,
  generatedAt: new Date(),
  rejectedLines: parsed.rejectedLines,
  ...(values.from && values.to ? { period: { from: day(values.from), to: day(values.to) } } : {}),
  ...(values.simulated ? { simulated: { stores: true, decisions: true } } : {}),
});
const out = values.out ?? "evidence-out";
mkdirSync(out, { recursive: true });
writeFileSync(join(out, "report.html"), report.html);
writeFileSync(join(out, "report.csv"), report.csv);
console.log(`Wrote ${join(out, "report.html")} and report.csv (${report.summary.decisions} decisions, ${parsed.rejectedLines.length} rejected lines)`);
