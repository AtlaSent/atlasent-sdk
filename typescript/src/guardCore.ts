/**
 * Shared orchestration for the framework tool guards
 * (`@atlasent/cursor`, `@atlasent/langchain`, `@atlasent/llamaindex`).
 *
 * Each of those packages wraps a framework's tool `execute` callback with
 * the same authorize-first loop:
 *
 *   1. resolve agent / action / extra context / state snapshot
 *   2. evaluate     — check the policy engine
 *   3. verifyPermit — confirm the permit cryptographically
 *   4. execute      — run the tool only if both pass, racing it against the
 *                     optional continuous-authorization heartbeat (PROD-D9)
 *
 * Before this module each guard carried its own byte-for-byte copy of the
 * loop (AtlaSent/atlasent#350). The only real differences between them are
 * framework-shaped and are supplied by the adapter:
 *
 *   - how a successful result is annotated with permit metadata
 *     ({@link GuardAdapter.onExecuted}), and
 *   - how a denial is represented when `onDeny: "tool-result"`
 *     ({@link GuardAdapter.encodeDenial}) — a JSON string for string-returning
 *     frameworks, the plain object for LlamaIndex.
 *
 * Fail-closed throughout: the tool body runs only after `evaluate` returned
 * `allow` AND `verifyPermit` returned `verified: true`. Any error inside the
 * evaluate → verify → execute window either propagates or (in
 * `"tool-result"` mode) becomes an `"error"` denial; it never falls through
 * to execution. `AtlaSentDeniedError` and `PermitRevoked` always propagate,
 * regardless of `onDeny`.
 *
 * This module sends nothing new on the wire: it calls the existing
 * {@link AtlaSentClient.evaluate}, {@link AtlaSentClient.verifyPermit} and
 * (when present) {@link AtlaSentClient.checkPermitValid}.
 */

import type { AtlaSentClient } from "./client.js";
import { AtlaSentDeniedError, PermitRevoked } from "./errors.js";

/**
 * Action type evaluated when no `action` option is given: the canonical
 * action for an agent invoking a tool (Canon ACT-0029).
 */
export const DEFAULT_GUARD_TOOL_ACTION = "agent.tool.invoke";

/** A static value, or a function of the tool name and input that yields one. */
export type GuardResolver<T> =
  | T
  | ((toolName: string, toolInput: Record<string, unknown>) => T | Promise<T>);

/** Options shared by every framework guard. See each package for full docs. */
export interface GuardCoreOptions {
  agent: GuardResolver<string>;
  action?: GuardResolver<string>;
  extraContext?: GuardResolver<Record<string, unknown>>;
  stateSnapshot?: GuardResolver<Record<string, unknown>>;
  onDeny?: "throw" | "tool-result";
  permitRevalidationIntervalMs?: number;
}

/** Denial payload returned (in adapter encoding) when `onDeny: "tool-result"`. */
export interface GuardDenialResult {
  denied: true;
  decision: string;
  evaluationId: string;
  reason: string;
  auditHash?: string;
}

/** Permit metadata handed to {@link GuardAdapter.onExecuted}. */
export interface GuardPermitInfo {
  permitId: string;
  auditHash: string;
}

/** Framework-specific hooks. */
export interface GuardAdapter<TResult, TOut> {
  /** Annotate a successful tool result with permit metadata. */
  onExecuted: (result: TResult, permit: GuardPermitInfo) => TOut;
  /** Represent a denial when `onDeny: "tool-result"`. */
  encodeDenial: (denial: GuardDenialResult) => TOut;
}

/**
 * Adapter for string-returning tools (Cursor/MCP, LangChain): a result that
 * parses as a JSON object is re-serialized with `_atlasent_permit_id` and
 * `_atlasent_audit_hash` added; any other string passes through unchanged.
 * Denials (in `"tool-result"` mode) are JSON-serialized.
 */
export const jsonStringResultAdapter: GuardAdapter<string, string> = {
  onExecuted: (result, permit) => {
    try {
      const parsed = JSON.parse(result) as unknown;
      if (parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)) {
        return JSON.stringify({
          ...(parsed as Record<string, unknown>),
          _atlasent_permit_id: permit.permitId,
          _atlasent_audit_hash: permit.auditHash,
        });
      }
    } catch {
      // Non-JSON or non-object result — return as-is.
    }
    return result;
  },
  encodeDenial: (denial) => JSON.stringify(denial),
};

/**
 * Adapter for object-returning tools (LlamaIndex): a plain-object result is
 * returned with `_atlasent_permit_id` and `_atlasent_audit_hash` added; any
 * other value passes through unchanged. Denials (in `"tool-result"` mode)
 * are returned as the plain {@link GuardDenialResult}.
 */
export const objectResultAdapter: GuardAdapter<unknown, unknown> = {
  onExecuted: (result, permit) => {
    if (result !== null && typeof result === "object" && !Array.isArray(result)) {
      return {
        ...(result as Record<string, unknown>),
        _atlasent_permit_id: permit.permitId,
        _atlasent_audit_hash: permit.auditHash,
      };
    }
    return result;
  },
  encodeDenial: (denial) => denial,
};

/** One tool invocation to authorize and (maybe) run. */
export interface GuardedToolCall<TResult> {
  toolName: string;
  input: Record<string, unknown>;
  execute: () => Promise<TResult>;
}

/** Resolve a {@link GuardResolver}. */
export async function resolveGuardValue<T>(
  r: GuardResolver<T>,
  toolName: string,
  toolInput: Record<string, unknown>,
): Promise<T> {
  return typeof r === "function"
    ? await (r as (n: string, i: Record<string, unknown>) => T | Promise<T>)(
        toolName,
        toolInput,
      )
    : r;
}

// ── Heartbeat (PROD-D9 continuous-authorization) ──────────────────────────────

interface PermitValidLike {
  status: string;
  revocation_id?: string;
}

type ClientWithHeartbeat = AtlaSentClient & {
  checkPermitValid?: (permitId: string) => Promise<PermitValidLike>;
};

interface HeartbeatHandle {
  revocationSignal: Promise<never>;
  stop: () => void;
}

/**
 * Poll the permit's validity every `intervalMs` (clamped to ≥ 1000 ms) and
 * reject `revocationSignal` with {@link PermitRevoked} the first time it is
 * reported revoked. Network errors during a poll are ignored and polling
 * continues. A client without `checkPermitValid` gets a no-op heartbeat.
 *
 * @internal exported for the guard-core tests.
 */
export function startPermitHeartbeat(
  client: AtlaSentClient,
  permitId: string,
  intervalMs: number,
): HeartbeatHandle {
  const clampedMs = Math.max(intervalMs, 1000);
  let stopped = false;
  let rejectFn: ((e: PermitRevoked) => void) | undefined;
  const revocationSignal = new Promise<never>((_, reject) => {
    rejectFn = reject;
  });

  const extended = client as ClientWithHeartbeat;
  if (!extended.checkPermitValid) {
    return {
      revocationSignal,
      stop: () => {
        stopped = true;
      },
    };
  }

  const timer = setInterval(() => {
    if (stopped) return;
    void extended.checkPermitValid!(permitId)
      .then((resp) => {
        if (!stopped && resp.status === "revoked") {
          stopped = true;
          clearInterval(timer);
          rejectFn!(new PermitRevoked(permitId, resp.revocation_id));
        }
      })
      .catch(() => {
        // Network error during heartbeat poll — continue polling.
      });
  }, clampedMs);

  return {
    revocationSignal,
    stop: () => {
      stopped = true;
      clearInterval(timer);
    },
  };
}

function handleDenial<TOut>(
  onDeny: "throw" | "tool-result" | undefined,
  denial: GuardDenialResult,
  encode: (d: GuardDenialResult) => TOut,
): TOut {
  if ((onDeny ?? "throw") === "tool-result") return encode(denial);
  throw new AtlaSentDeniedError({
    decision: "deny",
    evaluationId: denial.evaluationId,
    reason: denial.reason,
    ...(denial.auditHash !== undefined ? { auditHash: denial.auditHash } : {}),
  });
}

/**
 * Authorize and run one guarded tool call: evaluate → verifyPermit →
 * execute (with optional heartbeat). The framework guards are thin adapters
 * over this function.
 *
 * Resolver errors (agent / action / extraContext / stateSnapshot) propagate
 * unchanged in every `onDeny` mode, exactly as before the extraction.
 */
export async function runGuardedToolCall<TResult, TOut>(
  client: AtlaSentClient,
  options: GuardCoreOptions,
  call: GuardedToolCall<TResult>,
  adapter: GuardAdapter<TResult, TOut>,
): Promise<TOut> {
  const { toolName: name, input } = call;
  const agent = await resolveGuardValue(options.agent, name, input);
  const action = options.action
    ? await resolveGuardValue(options.action, name, input)
    : DEFAULT_GUARD_TOOL_ACTION;
  const extra = options.extraContext
    ? await resolveGuardValue(options.extraContext, name, input)
    : {};
  // `tool` is spread AFTER `extra` on purpose: the tool actually being
  // invoked is authoritative. A caller-supplied `extraContext.tool` must
  // not be able to make a call to one tool evaluate as another.
  const context: Record<string, unknown> = {
    ...extra,
    tool: name,
    tool_input: input,
  };
  const stateSnapshot = options.stateSnapshot
    ? await resolveGuardValue(options.stateSnapshot, name, input)
    : undefined;
  const verifyEnvironment =
    typeof context.environment === "string"
      ? context.environment
      : typeof context.environment_name === "string"
        ? context.environment_name
        : undefined;

  try {
    const evalResp = await client.evaluate({
      agent,
      action,
      context,
      ...(stateSnapshot !== undefined ? { state_snapshot: stateSnapshot } : {}),
    } as Parameters<typeof client.evaluate>[0]);

    if (evalResp.decision !== "allow") {
      return handleDenial(
        options.onDeny,
        {
          denied: true,
          decision: evalResp.decision,
          evaluationId: evalResp.permitId,
          reason: evalResp.reason,
          auditHash: evalResp.auditHash,
        },
        adapter.encodeDenial,
      );
    }

    const verifyResp = await client.verifyPermit({
      permitId: evalResp.permitId,
      agent,
      action,
      context,
      ...(verifyEnvironment !== undefined
        ? { environment: verifyEnvironment }
        : {}),
    });

    if (!verifyResp.verified) {
      return handleDenial(
        options.onDeny,
        {
          denied: true,
          decision: "verify_failed",
          evaluationId: evalResp.permitId,
          reason: `permit verification failed: ${verifyResp.outcome}`,
          auditHash: evalResp.auditHash,
        },
        adapter.encodeDenial,
      );
    }

    // Start continuous-authorization heartbeat (PROD-D9).
    const hb =
      options.permitRevalidationIntervalMs != null
        ? startPermitHeartbeat(
            client,
            evalResp.permitId,
            options.permitRevalidationIntervalMs,
          )
        : null;

    const result = await (hb
      ? Promise.race([call.execute(), hb.revocationSignal]).finally(() =>
          hb.stop(),
        )
      : call.execute());

    return adapter.onExecuted(result, {
      permitId: evalResp.permitId,
      auditHash: evalResp.auditHash,
    });
  } catch (err) {
    if (err instanceof AtlaSentDeniedError) throw err;
    if (err instanceof PermitRevoked) throw err;
    if ((options.onDeny ?? "throw") === "tool-result") {
      return adapter.encodeDenial({
        denied: true,
        decision: "error",
        evaluationId: "",
        reason: err instanceof Error ? err.message : String(err),
      });
    }
    throw err;
  }
}
