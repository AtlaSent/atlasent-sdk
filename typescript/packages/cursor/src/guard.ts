/**
 * AtlaSent authorization wrapper for Cursor agent tools.
 *
 * Cursor's background agent calls tools via the Model Context Protocol
 * (MCP) wire format: each tool has a flat `parameters` JSON Schema and
 * returns a string. This package wraps that shape with authorize-first
 * semantics without depending on any Cursor or MCP SDK:
 *
 *   1. evaluate     — check the policy engine
 *   2. verifyPermit — confirm the permit cryptographically
 *   3. execute      — run the tool only if both pass
 *
 * When `permitRevalidationIntervalMs` is set, the guard also runs a
 * continuous-authorization heartbeat (PROD-D9): it polls
 * `GET /v1/permits/:id/valid` at the configured interval and throws
 * `PermitRevoked` if the permit is revoked mid-execution.
 *
 * The returned objects are drop-in replacements for your existing tool
 * array: pass them to your Cursor MCP server's `ListToolsResult` and
 * call `execute` from your `CallToolResult` handler.
 */

import type { AtlaSentClient } from "@atlasent/sdk";
import {
  DEFAULT_GUARD_TOOL_ACTION,
  runGuardedToolCall,
  jsonStringResultAdapter,
  type GuardResolver,
} from "@atlasent/sdk";

// ── Cursor tool shape (MCP-compatible, duck-typed) ────────────────────────────

/** JSON Schema for a Cursor tool's input parameters. */
export interface CursorToolParameters {
  type: "object";
  properties: Record<string, unknown>;
  required?: string[];
  [key: string]: unknown;
}

/**
 * A Cursor-style tool definition extended with an `execute` callback.
 * Cursor tools return strings (MCP `content[0].text` convention).
 *
 * @example
 * ```ts
 * const editFileTool: CursorGuardedTool = {
 *   name: "edit_file",
 *   description: "Apply a patch to a file in the workspace",
 *   parameters: {
 *     type: "object",
 *     properties: {
 *       path: { type: "string" },
 *       patch: { type: "string" },
 *     },
 *     required: ["path", "patch"],
 *   },
 *   execute: async ({ path, patch }) => applyPatch(path, patch),
 * };
 * ```
 */
export interface CursorGuardedTool<
  TInput extends Record<string, unknown> = Record<string, unknown>,
> {
  name: string;
  description: string;
  parameters?: CursorToolParameters;
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

export interface CursorGuardOptions {
  /** Agent identifier (e.g. `"cursor:my-project"`). */
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
   *   so the agent can observe and adapt.
   */
  onDeny?: "throw" | "tool-result";
  /**
   * Continuous-authorization heartbeat interval in milliseconds (PROD-D9).
   *
   * When set (minimum 1000 ms), the guard polls `GET /v1/permits/:id/valid`
   * at this interval during tool execution. If the permit is revoked
   * mid-execution, `PermitRevoked` is thrown immediately regardless of
   * `onDeny`. Requires the `AtlaSentClient` to expose `checkPermitValid`
   * (available once atlasent-api ships `GET /v1/permits/:id/valid`).
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

// ── withCursorGuard ───────────────────────────────────────────────────────────

/**
 * Wrap an array of {@link CursorGuardedTool} definitions with AtlaSent
 * authorization. Returns a new array with the same shape but `execute`
 * replaced by an authorize-first version.
 *
 * Successful string results are returned as-is (Cursor renders them
 * directly), except that a result which parses as a JSON object is
 * re-serialized with `_atlasent_permit_id` and `_atlasent_audit_hash`
 * added (this has always been the runtime behaviour; an earlier version of
 * this comment said such results were unchanged).
 *
 * @example
 * ```ts
 * import { withCursorGuard } from "@atlasent/cursor";
 *
 * const guardedTools = withCursorGuard(
 *   [editFileTool, runCommandTool],
 *   atlasent,
 *   { agent: "cursor:my-project", permitRevalidationIntervalMs: 5000 },
 * );
 *
 * // In your MCP server's CallToolRequestSchema handler:
 * const tool = guardedTools.find((t) => t.name === request.params.name);
 * const result = await tool.execute(request.params.arguments ?? {});
 * return { content: [{ type: "text", text: result }] };
 * ```
 */
export function withCursorGuard<T extends CursorGuardedTool>(
  tools: readonly T[],
  client: AtlaSentClient,
  options: CursorGuardOptions,
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
