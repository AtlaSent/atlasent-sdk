/**
 * Data-export gate: evaluate, then verifyPermit() at the execution
 * boundary before emitting a patient-data export. Captures the
 * auditHash and permit in the export manifest so regulators can tie
 * every exported row back to a policy decision.
 *
 * The gate is `verifyPermit()` (`POST /v1-verify-permit`), which checks
 * the permit's signature, its bindings (action, actor, environment,
 * execution hash) and replay, and consumes it. Do NOT gate on
 * `verifyPermitById()`: that is a lifecycle/status call and performs
 * none of those checks.
 *
 * Run with:
 *   ATLASENT_API_KEY=ask_live_... REQUESTER=$USER \
 *     DATASET=trial_ABC-2026-phase2 \
 *     npx tsx examples/data-export-gate.ts
 */

import { createHash } from "node:crypto";

import { AtlaSentClient, AtlaSentError } from "@atlasent/sdk";

const apiKey = process.env.ATLASENT_API_KEY;
if (!apiKey) {
  console.error("ATLASENT_API_KEY env var is required");
  process.exit(2);
}

const client = new AtlaSentClient({ apiKey, timeoutMs: 5_000 });

const ACTION = "export_patient_dataset";
const ACTOR = "data-export-agent";
const ENVIRONMENT = process.env.ENVIRONMENT ?? "production";

const exportContext = {
  dataset: process.env.DATASET ?? "trial_unspecified",
  requester: process.env.REQUESTER ?? "unknown",
  destination: process.env.DESTINATION ?? "s3://atlasent-exports/outbound/",
  classification: process.env.CLASSIFICATION ?? "PHI",
  purpose: process.env.PURPOSE ?? "regulatory_submission",
};

// Bind the permit to the exact export that will run: a bare 64-char hex
// SHA-256 of the key-sorted export descriptor, sent top-level at evaluate
// and presented again at verify. A different export cannot reuse the permit.
function sha256Hex(value: Record<string, unknown>): string {
  const sorted = Object.fromEntries(
    Object.keys(value)
      .sort()
      .map((k) => [k, value[k]]),
  );
  return createHash("sha256").update(JSON.stringify(sorted)).digest("hex");
}
const payloadHash = sha256Hex(exportContext);

interface ExportManifest {
  dataset: string;
  requester: string;
  permitId: string;
  payloadHash: string;
  auditHash: string;
  approvedAt: string;
  verifiedAt: string;
}

function failClosed(err: unknown, step: string): never {
  if (err instanceof AtlaSentError) {
    console.error(
      `AtlaSent ${step} failed (code=${err.code} status=${err.status ?? "?"} requestId=${err.requestId ?? "?"}): ${err.message}`,
    );
  } else {
    console.error(`AtlaSent ${step} failed: ${String(err)}`);
  }
  // fail-closed: cannot confirm authorization → do not export
  process.exit(3);
}

async function main(): Promise<void> {
  let evaluation;
  try {
    evaluation = await client.evaluate({
      action_type: ACTION,
      actor_id: ACTOR,
      environment: ENVIRONMENT,
      context: { ...exportContext, environment: ENVIRONMENT },
      execution_payload_hash: payloadHash,
    });
  } catch (err) {
    failClosed(err, "evaluate");
  }

  if (evaluation.decision !== "allow" || !evaluation.permitId) {
    console.error(`Export blocked: ${evaluation.reason}`);
    console.error(`  permitId:  ${evaluation.permitId}`);
    console.error(`  auditHash: ${evaluation.auditHash}`);
    process.exit(1);
  }

  // Execution boundary: verify (and consume) the permit against the same
  // action, actor, environment and payload binding that was evaluated.
  let verification;
  try {
    verification = await client.verifyPermit({
      permitId: evaluation.permitId,
      action: ACTION,
      agent: ACTOR,
      environment: ENVIRONMENT,
      execution_hash: payloadHash,
    });
  } catch (err) {
    failClosed(err, "verify");
  }

  if (verification.verified !== true) {
    console.error(
      `Permit ${evaluation.permitId} failed verification: ${verification.outcome || "unknown"}`,
    );
    process.exit(1);
  }

  const manifest: ExportManifest = {
    dataset: exportContext.dataset,
    requester: exportContext.requester,
    permitId: evaluation.permitId,
    payloadHash,
    auditHash: evaluation.auditHash,
    approvedAt: evaluation.timestamp,
    verifiedAt: verification.timestamp,
  };

  console.log(JSON.stringify(manifest, null, 2));
  // Only reached on verified === true:
  // writeManifest(manifest); streamExport(exportContext);
}

void main();
