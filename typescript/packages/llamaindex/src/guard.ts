/**
 * AtlaSent authorization wrapper for LlamaIndex tools.
 *
 * Mirrors the LlamaIndex BaseTool / FunctionTool shape:
 *   tool.metadata.{ name, description, parameters? }
 *   tool.call(input) → Promise<unknown>
 *
 * The guard wraps `execute` with authorize-first semantics:
 *   1. evaluate   — check the policy engine
 *   2. verifyPermit — confirm the permit cryptographically
 *   3. execute    — run the tool only if both pass
 *
 * When `permitRevalidationIntervalMs` is set, the guard also runs a
 * continuous-authorization heartbeat (PROD-D9): it polls
 * `GET /v1-permits/:id/valid` at the configured interval and throws
 * `PermitRevoked` if the permit is revoked mid-execution.
 *
 * Zero dependency on `llamaindex` — duck-typed so the wrapped `execute`
 * (or the whole returned tool object) works with any LlamaIndex version.
 * Pass the result directly to `FunctionTool.from(guarded.execute, guarded.metadata)`
 * or use it as a BaseTool in an AgentRunner.
 */

import type { AtlaSentClient } from "@atlasent/sdk";
import {
  DEFAULT_GUARD_TOOL_ACTION,
  runGuardedToolCall,
  objectResultAdapter,
  type GuardResolver,
} from "@atlasent/sdk";

// ── LlamaIndex tool shapes (duck-typed) ───────────────────────────────────────

/** LlamaIndex-style tool metadata. */
export interface LlamaIndexToolMetadata {
  name: string;
  description: string;
  /** JSON Schema for the tool's input parameters. */
  parameters?: Record<string, unknown>;
}

/**
 * A LlamaIndex-style tool definition extended with an `execute` callback.
 * The guard wraps `execute` with AtlaSent authorization.
 *
 * @example
 * ```ts
 * const searchTool: LlamaIndexGuardedTool = {
 *   metadata: {
 *     name: "vector_search",
 *     description: "Semantic search over the knowledge base",
 *     parameters: {
 *       type: "object",
 *       properties: { query: { type: "string" } },
 *       required: ["query"],
 *     },
 *   },
 *   execute: async ({ query }) => vectorStore.search(query),
 * };
 * ```
 */
export interface LlamaIndexGuardedTool<
  TInput extends Record<string, unknown> = Record<string, unknown>,
  TOutput = unknown,
> {
  metadata: LlamaIndexToolMetadata;
  execute: (input: TInput) => Promise<TOutput>;
}

/**
 * Action type evaluated when no `action` option is given: the canonical
 * action for an agent invoking a tool (Canon ACT-0029). Its action class
 * requires context inputs `tool` (supplied by the guard) and `environment`
 * (supplied by the caller).
 */
export const DEFAULT_TOOL_ACTION = DEFAULT_GUARD_TOOL_ACTION;

// ── Options ───────────────────────────────────────────────────────────────────

type Resolver<T> = GuardResolver<T>;

export interface LlamaIndexGuardOptions {
  /** Agent identifier (e.g. `"service:knowledge-bot"`). */
  agent: Resolver<string>;
  /**
   * Action type evaluated for every tool call. Defaults to
   * {@link DEFAULT_TOOL_ACTION} (`"agent.tool.invoke"`, Canon ACT-0029) — the
   * canonical action for an agent invoking a tool. The tool's own name is
   * always sent as `context.tool`, so policy can distinguish tools without a
   * per-tool action class.
   *
   * Before this default existed the action was the bare tool name (e.g.
   * `"delete_user"`), which names no runtime action class, so every call was
   * denied. Pass a resolver returning the tool name to restore that behaviour.
   *
   * The `agent.tool.invoke` action class requires context inputs `tool` and
   * `environment`. The guard supplies `tool`; supply `environment` yourself
   * via `extraContext` — the guard never invents one.
   */
  action?: Resolver<string>;
  /** Extra context forwarded to every AtlaSent evaluation. */
  extraContext?: Resolver<Record<string, unknown>>;
  /**
   * State snapshot forwarded to every AtlaSent evaluation.
   *
   * Required when the action class has `requires_state_snapshot = true`
   * (the default for all action classes). Omitting this option causes
   * `SNAPSHOT_REQUIRED` denies. At minimum, pass:
   * `{ source: "your-system", complete: true }`
   */
  stateSnapshot?: Resolver<Record<string, unknown>>;
  /**
   * - `"throw"` (default) — throw `AtlaSentDeniedError` on denial.
   * - `"tool-result"` — return a `DenialResult` object so the agent
   *   can observe and adapt.
   */
  onDeny?: "throw" | "tool-result";
  /**
   * Continuous-authorization heartbeat interval in milliseconds (PROD-D9).
   *
   * When set (minimum 1000 ms), the guard polls `GET /v1-permits/:id/valid`
   * at this interval during tool execution. If the permit is revoked
   * mid-execution, `PermitRevoked` is thrown immediately regardless of
   * `onDeny`. Requires the `AtlaSentClient` to expose `checkPermitValid`
   * (available once atlasent-api ships `GET /v1-permits/:id/valid`).
   */
  permitRevalidationIntervalMs?: number;
}

/** Returned instead of throwing when `onDeny: "tool-result"`. */
export interface DenialResult {
  denied: true;
  decision: string;
  evaluationId: string;
  reason: string;
  auditHash?: string;
}

// ── withLlamaIndexGuard ───────────────────────────────────────────────────────

/**
 * Wrap an array of {@link LlamaIndexGuardedTool} definitions with AtlaSent
 * authorization. Returns a new array with the same metadata but with
 * `execute` replaced by an authorize-first version.
 *
 * Object results are annotated with `_atlasent_permit_id` and
 * `_atlasent_audit_hash`. Non-object results pass through unchanged.
 *
 * @example
 * ```ts
 * import { FunctionTool } from "llamaindex";
 * import { withLlamaIndexGuard } from "@atlasent/llamaindex";
 *
 * const guarded = withLlamaIndexGuard([searchTool], atlasent, {
 *   agent: "service:knowledge-bot",
 *   permitRevalidationIntervalMs: 5000,
 * });
 *
 * const tools = guarded.map((t) =>
 *   FunctionTool.from(t.execute, t.metadata),
 * );
 * ```
 */
export function withLlamaIndexGuard<
  T extends LlamaIndexGuardedTool<Record<string, unknown>, unknown>,
>(
  tools: readonly T[],
  client: AtlaSentClient,
  options: LlamaIndexGuardOptions,
): T[] {
  return tools.map((tool) => ({
    ...tool,
    execute: async (input: Record<string, unknown>): Promise<unknown> =>
      runGuardedToolCall(
        client,
        options,
        {
          toolName: tool.metadata.name,
          input,
          execute: () => tool.execute(input as Parameters<T["execute"]>[0]),
        },
        objectResultAdapter,
      ),
  })) as unknown as T[];
}
