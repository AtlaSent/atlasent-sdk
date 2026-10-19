/**
 * AtlaSent authorization wrapper for LangChain tools.
 *
 * Works with any LangChain tool factory (DynamicStructuredTool,
 * DynamicTool, custom Tool subclasses) by wrapping the underlying
 * `execute` / `func` callback with authorize-first semantics:
 *   1. evaluate — check the policy engine
 *   2. verifyPermit — confirm the permit cryptographically
 *   3. execute — run the tool only if both pass
 *
 * When `permitRevalidationIntervalMs` is set, the guard also runs a
 * continuous-authorization heartbeat (PROD-D9): it polls
 * `GET /v1-permits/:id/valid` at the configured interval and throws
 * `PermitRevoked` if the permit is revoked mid-execution.
 *
 * The package is zero-dependency on @langchain/core — it operates on
 * plain objects. Pass the wrapped `execute` to whichever LangChain
 * tool constructor you prefer.
 */

import type { AtlaSentClient } from "@atlasent/sdk";
import {
  DEFAULT_GUARD_TOOL_ACTION,
  runGuardedToolCall,
  jsonStringResultAdapter,
  type GuardResolver,
} from "@atlasent/sdk";

// ── LangChain tool shapes (duck-typed) ────────────────────────────────────────

/** Minimal JSON Schema for a LangChain structured tool's input. */
export interface LangChainToolSchema {
  type: "object";
  properties: Record<string, unknown>;
  required?: string[];
  [key: string]: unknown;
}

/**
 * A LangChain-style tool definition extended with an `execute` callback.
 * LangChain tools return strings; the guard annotates the string result
 * with permit metadata when the output format allows it (i.e. when the
 * result is valid JSON). Otherwise the raw string is returned unchanged.
 *
 * @example
 * ```ts
 * const queryTool: LangChainGuardedTool = {
 *   name: "query_database",
 *   description: "Run a read-only SQL query and return results as JSON",
 *   schema: {
 *     type: "object",
 *     properties: { query: { type: "string" } },
 *     required: ["query"],
 *   },
 *   execute: async ({ query }) => JSON.stringify(await db.query(query)),
 * };
 * ```
 */
export interface LangChainGuardedTool<
  TInput extends Record<string, unknown> = Record<string, unknown>,
> {
  name: string;
  description: string;
  schema?: LangChainToolSchema;
  execute: (input: TInput) => Promise<string>;
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

export interface LangChainGuardOptions {
  /** Agent identifier (e.g. `"service:analytics-bot"`). */
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
   * - `"tool-result"` — return a JSON-serialized `DenialResult` string
   *   so the LLM can adapt its behaviour.
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
   *
   * Recommended range: 1000–10 000 ms. Enterprise minimum sweep interval
   * is 5000 ms (PROD-D9); setting this below the sweep interval provides
   * no additional latency reduction.
   */
  permitRevalidationIntervalMs?: number;
}

/** Returned (as a JSON string) instead of throwing when `onDeny: "tool-result"`. */
export interface DenialResult {
  denied: true;
  decision: string;
  evaluationId: string;
  reason: string;
  auditHash?: string;
}

// ── withLangChainGuard ────────────────────────────────────────────────────────

/**
 * Wrap an array of {@link LangChainGuardedTool} definitions with AtlaSent
 * authorization. Returns a new array with the same tool metadata but
 * with `execute` replaced by an authorize-first version.
 *
 * Pass the wrapped `execute` to `DynamicStructuredTool`, `DynamicTool`,
 * or any other LangChain tool factory:
 *
 * @example
 * ```ts
 * import { DynamicStructuredTool } from "@langchain/core/tools";
 * import { z } from "zod";
 * import { withLangChainGuard } from "@atlasent/langchain";
 *
 * const defs = withLangChainGuard(
 *   [{ name: "query_db", description: "...", execute: async ({ sql }) => db.run(sql) }],
 *   atlasent,
 *   { agent: "service:analytics-bot", permitRevalidationIntervalMs: 5000 },
 * );
 *
 * const tools = defs.map((d) =>
 *   new DynamicStructuredTool({
 *     name: d.name,
 *     description: d.description,
 *     schema: z.object({ sql: z.string() }),
 *     func: d.execute,
 *   }),
 * );
 * ```
 */
export function withLangChainGuard<T extends LangChainGuardedTool>(
  tools: readonly T[],
  client: AtlaSentClient,
  options: LangChainGuardOptions,
): T[] {
  return tools.map((tool) => ({
    ...tool,
    execute: async (input: Record<string, unknown>): Promise<string> =>
      runGuardedToolCall(
        client,
        options,
        {
          toolName: tool.name,
          input,
          execute: () => tool.execute(input as Parameters<T["execute"]>[0]),
        },
        jsonStringResultAdapter,
      ),
  })) as unknown as T[];
}
