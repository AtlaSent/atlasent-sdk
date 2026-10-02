import { functionRegionHeaders } from "./functionRegion.js";
import { protect } from "./protect.js";
import { AtlaSentDeniedError } from "./errors.js";
import type { ProtectRequest, Permit } from "./protect.js";

export type ShadowMode = "observe" | "warn" | "enforce";

export interface ShadowOutcome {
  readonly decision: "permit" | "deny" | "hold" | "escalate";
  readonly permit: Permit | null;
  readonly error: AtlaSentDeniedError | null;
  readonly would_have_blocked: boolean;
  readonly latencyMs: number;
  readonly evaluationId: string | null;
  readonly request: ProtectRequest;
  readonly mode: ShadowMode;
}

export interface ShadowConfig {
  mode?: ShadowMode;
  onOutcome?: (outcome: ShadowOutcome) => void | Promise<void>;
  reportToApi?: boolean;
  apiKey?: string;
  baseUrl?: string;
}

let _defaultConfig: ShadowConfig = {};

export function configureShadow(config: ShadowConfig): void {
  _defaultConfig = { ..._defaultConfig, ...config };
}

export interface ShadowOptions extends ShadowConfig {}

export async function protectShadow(
  request: ProtectRequest,
  opts?: ShadowOptions,
): Promise<ShadowOutcome> {
  const merged: ShadowConfig = { ..._defaultConfig, ...opts };
  const mode = merged.mode ?? "observe";

  if (mode === "enforce") {
    const start = Date.now();
    const permit = await protect(request);
    const outcome: ShadowOutcome = {
      decision: "permit",
      permit,
      error: null,
      would_have_blocked: false,
      latencyMs: Date.now() - start,
      evaluationId: permit.permitId,
      request,
      mode,
    };
    await _notify(outcome, merged);
    return outcome;
  }

  const start = Date.now();
  try {
    const permit = await protect(request);
    const outcome: ShadowOutcome = {
      decision: "permit",
      permit,
      error: null,
      would_have_blocked: false,
      latencyMs: Date.now() - start,
      evaluationId: permit.permitId,
      request,
      mode,
    };
    await _notify(outcome, merged);
    if (merged.reportToApi) {
      void reportShadowEvent(outcome, merged).catch(() => undefined);
    }
    return outcome;
  } catch (err) {
    if (err instanceof AtlaSentDeniedError) {
      const outcome: ShadowOutcome = {
        decision: err.decision as "deny" | "hold" | "escalate",
        permit: null,
        error: err,
        would_have_blocked: true,
        latencyMs: Date.now() - start,
        evaluationId: err.evaluationId ?? null,
        request,
        mode,
      };
      if (mode === "warn") {
        // eslint-disable-next-line no-console
        console.warn(
          `[AtlaSent shadow:warn] Action '${request.action}' would have been blocked (decision=${err.decision}, evaluationId=${err.evaluationId ?? "unknown"})`,
        );
      }
      await _notify(outcome, merged);
      if (merged.reportToApi) {
        void reportShadowEvent(outcome, merged).catch(() => undefined);
      }
      return outcome;
    }
    throw err;
  }
}

async function _notify(
  outcome: ShadowOutcome,
  config: ShadowConfig,
): Promise<void> {
  if (config.onOutcome) {
    try {
      await config.onOutcome(outcome);
    } catch {
      // onOutcome errors must never propagate
    }
  }
}

export interface ShadowEventPayload {
  action: string;
  agentId: string | null;
  decision: ShadowOutcome["decision"];
  would_have_blocked: boolean;
  latencyMs: number;
  evaluationId: string | null;
  mode: ShadowMode;
  deniedReason?: string;
  timestamp: string;
}

export async function reportShadowEvent(
  outcome: ShadowOutcome,
  opts?: Pick<ShadowConfig, "apiKey" | "baseUrl">,
): Promise<void> {
  const apiKey =
    opts?.apiKey ?? _defaultConfig.apiKey ?? process.env["ATLASENT_API_KEY"] ?? "";
  const baseUrl =
    opts?.baseUrl ?? _defaultConfig.baseUrl ?? process.env["ATLASENT_BASE_URL"] ?? "https://api.atlasent.ai";

  const payload: ShadowEventPayload = {
    action: outcome.request.action,
    agentId: outcome.request.agent ?? null,
    decision: outcome.decision,
    would_have_blocked: outcome.would_have_blocked,
    latencyMs: outcome.latencyMs,
    evaluationId: outcome.evaluationId,
    mode: outcome.mode,
    ...(outcome.error ? { deniedReason: outcome.error.message } : {}),
    timestamp: new Date().toISOString(),
  };

  const response = await fetch(`${baseUrl}/v1/shadow-events`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${apiKey}`,
      ...functionRegionHeaders(baseUrl),
    },
    body: JSON.stringify(payload),
  });

  if (!response.ok && response.status >= 500) {
    throw new Error(`Shadow event reporting failed: ${response.status}`);
  }
}
