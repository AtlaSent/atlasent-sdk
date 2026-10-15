import { afterEach, describe, expect, it, vi } from "vitest";
import type { AtlaSentClient } from "../src/client.js";
import { AtlaSentDeniedError, PermitRevoked } from "../src/errors.js";
import {
  DEFAULT_GUARD_TOOL_ACTION,
  jsonStringResultAdapter,
  objectResultAdapter,
  resolveGuardValue,
  runGuardedToolCall,
  startPermitHeartbeat,
  type GuardAdapter,
  type GuardDenialResult,
} from "../src/guardCore.js";
import * as sdk from "../src/index.js";

const ALLOW = {
  decision: "allow" as const,
  permitId: "dec_1",
  reason: "ok",
  auditHash: "hash_1",
};
const VERIFIED = { verified: true, outcome: "verified" };

function makeClient(overrides: Record<string, unknown> = {}) {
  const evaluate = vi.fn(async (_req: unknown) => ALLOW as unknown);
  const verifyPermit = vi.fn(async (_req: unknown) => VERIFIED as unknown);
  const client = { evaluate, verifyPermit, ...overrides };
  return {
    client: client as unknown as AtlaSentClient,
    evaluate: client.evaluate as typeof evaluate,
    verifyPermit: client.verifyPermit as typeof verifyPermit,
  };
}

/** Records adapter calls and returns tagged values so routing is visible. */
function recordingAdapter() {
  const denials: GuardDenialResult[] = [];
  const adapter: GuardAdapter<string, string> = {
    onExecuted: (result, permit) => `ok:${result}:${permit.permitId}:${permit.auditHash}`,
    encodeDenial: (d) => {
      denials.push(d);
      return `denied:${d.decision}`;
    },
  };
  return { adapter, denials };
}

function toolCall(result = "R") {
  const execute = vi.fn(async () => result);
  return { call: { toolName: "delete_user", input: { id: 7 }, execute }, execute };
}

afterEach(() => {
  vi.useRealTimers();
});

describe("runGuardedToolCall — allow path", () => {
  it("allow + verified runs the tool once and annotates via the adapter", async () => {
    const { client, evaluate, verifyPermit } = makeClient();
    const { call, execute } = toolCall();
    const { adapter } = recordingAdapter();
    const out = await runGuardedToolCall(client, { agent: "bot" }, call, adapter);
    expect(out).toBe("ok:R:dec_1:hash_1");
    expect(execute).toHaveBeenCalledTimes(1);
    expect(evaluate).toHaveBeenCalledTimes(1);
    expect(verifyPermit).toHaveBeenCalledTimes(1);
    // evaluate precedes verify precedes execute
    expect(evaluate.mock.invocationCallOrder[0]!).toBeLessThan(
      verifyPermit.mock.invocationCallOrder[0]!,
    );
    expect(verifyPermit.mock.invocationCallOrder[0]!).toBeLessThan(
      execute.mock.invocationCallOrder[0]!,
    );
  });

  it("sends the default action, tool name, tool_input and no state_snapshot", async () => {
    const { client, evaluate, verifyPermit } = makeClient();
    const { call } = toolCall();
    await runGuardedToolCall(client, { agent: "bot" }, call, recordingAdapter().adapter);
    const req = evaluate.mock.calls[0]![0] as Record<string, unknown>;
    expect(req).toEqual({
      agent: "bot",
      action: DEFAULT_GUARD_TOOL_ACTION,
      context: { tool: "delete_user", tool_input: { id: 7 } },
    });
    expect("state_snapshot" in req).toBe(false);
    const vreq = verifyPermit.mock.calls[0]![0] as Record<string, unknown>;
    expect(vreq).toEqual({
      permitId: "dec_1",
      agent: "bot",
      action: DEFAULT_GUARD_TOOL_ACTION,
      context: { tool: "delete_user", tool_input: { id: 7 } },
    });
    expect("environment" in vreq).toBe(false);
  });

  it("forwards stateSnapshot (static and resolved) as state_snapshot", async () => {
    const { client, evaluate } = makeClient();
    await runGuardedToolCall(
      client,
      { agent: "bot", stateSnapshot: { source: "s", complete: true } },
      toolCall().call,
      recordingAdapter().adapter,
    );
    expect((evaluate.mock.calls[0]![0] as Record<string, unknown>).state_snapshot).toEqual({
      source: "s",
      complete: true,
    });

    const snap = vi.fn(async (name: string) => ({ source: name }));
    await runGuardedToolCall(
      client,
      { agent: "bot", stateSnapshot: snap },
      toolCall().call,
      recordingAdapter().adapter,
    );
    expect(snap).toHaveBeenCalledWith("delete_user", { id: 7 });
    expect((evaluate.mock.calls[1]![0] as Record<string, unknown>).state_snapshot).toEqual({
      source: "delete_user",
    });
  });

  it("resolves agent/action/extraContext functions with tool name and input", async () => {
    const { client, evaluate } = makeClient();
    await runGuardedToolCall(
      client,
      {
        agent: (n) => `agent:${n}`,
        action: async (n, i) => `${n}.${String(i.id)}`,
        extraContext: () => ({ environment: "prod" }),
      },
      toolCall().call,
      recordingAdapter().adapter,
    );
    expect(evaluate.mock.calls[0]![0]).toMatchObject({
      agent: "agent:delete_user",
      action: "delete_user.7",
      context: { environment: "prod" },
    });
  });

  it("the invoked tool name overrides a caller-supplied extraContext.tool", async () => {
    const { client, evaluate } = makeClient();
    await runGuardedToolCall(
      client,
      { agent: "bot", extraContext: { tool: "harmless", tool_input: "x" } },
      toolCall().call,
      recordingAdapter().adapter,
    );
    expect(evaluate.mock.calls[0]![0]).toMatchObject({
      context: { tool: "delete_user", tool_input: { id: 7 } },
    });
  });

  it("presents context.environment (preferred) or environment_name at verify", async () => {
    const a = makeClient();
    await runGuardedToolCall(
      a.client,
      { agent: "bot", extraContext: { environment: "prod", environment_name: "x" } },
      toolCall().call,
      recordingAdapter().adapter,
    );
    expect(a.verifyPermit.mock.calls[0]![0]).toMatchObject({ environment: "prod" });

    const b = makeClient();
    await runGuardedToolCall(
      b.client,
      { agent: "bot", extraContext: { environment: 1, environment_name: "stage" } },
      toolCall().call,
      recordingAdapter().adapter,
    );
    expect(b.verifyPermit.mock.calls[0]![0]).toMatchObject({ environment: "stage" });
  });
});

describe("runGuardedToolCall — non-allow decisions never execute", () => {
  for (const decision of ["deny", "hold", "escalate"] as const) {
    it(`${decision}: throws AtlaSentDeniedError by default and does not run the tool`, async () => {
      const { client, verifyPermit } = makeClient({
        evaluate: vi.fn(async () => ({ ...ALLOW, decision, reason: `r-${decision}` })),
      });
      const { call, execute } = toolCall();
      const err = await runGuardedToolCall(
        client,
        { agent: "bot" },
        call,
        recordingAdapter().adapter,
      ).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(AtlaSentDeniedError);
      expect((err as AtlaSentDeniedError).reason).toBe(`r-${decision}`);
      expect((err as AtlaSentDeniedError).evaluationId).toBe("dec_1");
      expect(execute).not.toHaveBeenCalled();
      expect(verifyPermit).not.toHaveBeenCalled();
    });

    it(`${decision}: tool-result mode encodes the denial and does not run the tool`, async () => {
      const { client } = makeClient({
        evaluate: vi.fn(async () => ({ ...ALLOW, decision, reason: "no" })),
      });
      const { call, execute } = toolCall();
      const { adapter, denials } = recordingAdapter();
      const out = await runGuardedToolCall(
        client,
        { agent: "bot", onDeny: "tool-result" },
        call,
        adapter,
      );
      expect(out).toBe(`denied:${decision}`);
      expect(denials[0]).toEqual({
        denied: true,
        decision,
        evaluationId: "dec_1",
        reason: "no",
        auditHash: "hash_1",
      });
      expect(execute).not.toHaveBeenCalled();
    });
  }

  it("omits auditHash on the thrown error when evaluate returned none", async () => {
    const { client } = makeClient({
      evaluate: vi.fn(async () => ({ decision: "deny", permitId: "d", reason: "x" })),
    });
    const err = (await runGuardedToolCall(
      client,
      { agent: "bot" },
      toolCall().call,
      recordingAdapter().adapter,
    ).catch((e: unknown) => e)) as AtlaSentDeniedError;
    expect(err).toBeInstanceOf(AtlaSentDeniedError);
    expect(err.auditHash).toBeUndefined();
  });
});

describe("runGuardedToolCall — verify failure never executes", () => {
  it("throws by default", async () => {
    const { client } = makeClient({
      verifyPermit: vi.fn(async () => ({ verified: false, outcome: "revoked" })),
    });
    const { call, execute } = toolCall();
    const err = await runGuardedToolCall(
      client,
      { agent: "bot" },
      call,
      recordingAdapter().adapter,
    ).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(AtlaSentDeniedError);
    expect((err as AtlaSentDeniedError).reason).toBe("permit verification failed: revoked");
    expect(execute).not.toHaveBeenCalled();
  });

  it("tool-result mode encodes a verify_failed denial", async () => {
    const { client } = makeClient({
      verifyPermit: vi.fn(async () => ({ verified: false, outcome: "expired" })),
    });
    const { call, execute } = toolCall();
    const { adapter, denials } = recordingAdapter();
    const out = await runGuardedToolCall(
      client,
      { agent: "bot", onDeny: "tool-result" },
      call,
      adapter,
    );
    expect(out).toBe("denied:verify_failed");
    expect(denials[0]).toEqual({
      denied: true,
      decision: "verify_failed",
      evaluationId: "dec_1",
      reason: "permit verification failed: expired",
      auditHash: "hash_1",
    });
    expect(execute).not.toHaveBeenCalled();
  });
});

describe("runGuardedToolCall — errors fail closed", () => {
  it("an evaluate transport error propagates and the tool does not run", async () => {
    const boom = new Error("network down");
    const { client } = makeClient({ evaluate: vi.fn(async () => Promise.reject(boom)) });
    const { call, execute } = toolCall();
    await expect(
      runGuardedToolCall(client, { agent: "bot" }, call, recordingAdapter().adapter),
    ).rejects.toBe(boom);
    expect(execute).not.toHaveBeenCalled();
  });

  it("a verify transport error in tool-result mode becomes an 'error' denial", async () => {
    const { client } = makeClient({
      verifyPermit: vi.fn(async () => Promise.reject("raw string failure")),
    });
    const { call, execute } = toolCall();
    const { adapter, denials } = recordingAdapter();
    const out = await runGuardedToolCall(
      client,
      { agent: "bot", onDeny: "tool-result" },
      call,
      adapter,
    );
    expect(out).toBe("denied:error");
    expect(denials[0]).toEqual({
      denied: true,
      decision: "error",
      evaluationId: "",
      reason: "raw string failure",
    });
    expect(execute).not.toHaveBeenCalled();
  });

  it("a tool error in tool-result mode becomes an 'error' denial with its message", async () => {
    const { client } = makeClient();
    const { adapter, denials } = recordingAdapter();
    const out = await runGuardedToolCall(
      client,
      { agent: "bot", onDeny: "tool-result" },
      { toolName: "t", input: {}, execute: async () => Promise.reject(new Error("tool broke")) },
      adapter,
    );
    expect(out).toBe("denied:error");
    expect(denials[0]!.reason).toBe("tool broke");
  });

  it("AtlaSentDeniedError from the tool propagates even in tool-result mode", async () => {
    const { client } = makeClient();
    const inner = new AtlaSentDeniedError({ decision: "deny", evaluationId: "x", reason: "y" });
    await expect(
      runGuardedToolCall(
        client,
        { agent: "bot", onDeny: "tool-result" },
        { toolName: "t", input: {}, execute: async () => Promise.reject(inner) },
        recordingAdapter().adapter,
      ),
    ).rejects.toBe(inner);
  });

  it("resolver errors propagate even in tool-result mode (no evaluate call)", async () => {
    const { client, evaluate } = makeClient();
    await expect(
      runGuardedToolCall(
        client,
        {
          agent: () => {
            throw new Error("no agent");
          },
          onDeny: "tool-result",
        },
        toolCall().call,
        recordingAdapter().adapter,
      ),
    ).rejects.toThrow("no agent");
    expect(evaluate).not.toHaveBeenCalled();
  });
});

describe("runGuardedToolCall — continuous-authorization heartbeat", () => {
  it("PermitRevoked from the heartbeat stops the call, even in tool-result mode", async () => {
    vi.useFakeTimers();
    const checkPermitValid = vi.fn(async () => ({
      valid: false,
      status: "revoked",
      revocation_id: "rev_9",
    }));
    const { client } = makeClient({ checkPermitValid });
    let resolveTool: (v: string) => void = () => {};
    const slowTool = vi.fn(
      () => new Promise<string>((r) => {
        resolveTool = r;
      }),
    );
    const onExecuted = vi.fn((r: string) => r);
    const p = runGuardedToolCall(
      client,
      { agent: "bot", onDeny: "tool-result", permitRevalidationIntervalMs: 2000 },
      { toolName: "t", input: {}, execute: slowTool },
      { onExecuted, encodeDenial: () => "should-not-encode" },
    );
    const settled = p.catch((e: unknown) => e);
    await vi.advanceTimersByTimeAsync(2000);
    const err = await settled;
    expect(err).toBeInstanceOf(PermitRevoked);
    expect((err as PermitRevoked).permitId).toBe("dec_1");
    expect((err as PermitRevoked).revocationId).toBe("rev_9");
    expect(checkPermitValid).toHaveBeenCalledWith("dec_1");
    expect(onExecuted).not.toHaveBeenCalled();
    resolveTool("late");
  });

  it("the heartbeat is stopped once the tool completes", async () => {
    vi.useFakeTimers();
    const checkPermitValid = vi.fn(async () => ({ valid: true, status: "active" }));
    const { client } = makeClient({ checkPermitValid });
    const out = await runGuardedToolCall(
      client,
      { agent: "bot", permitRevalidationIntervalMs: 1000 },
      toolCall("done").call,
      recordingAdapter().adapter,
    );
    expect(out).toBe("ok:done:dec_1:hash_1");
    await vi.advanceTimersByTimeAsync(5000);
    expect(checkPermitValid).not.toHaveBeenCalled();
  });

  it("no heartbeat is started when permitRevalidationIntervalMs is unset", async () => {
    vi.useFakeTimers();
    const checkPermitValid = vi.fn(async () => ({ valid: false, status: "revoked" }));
    const { client } = makeClient({ checkPermitValid });
    let resolveTool: (v: string) => void = () => {};
    const p = runGuardedToolCall(
      client,
      { agent: "bot" },
      {
        toolName: "t",
        input: {},
        execute: () => new Promise<string>((r) => {
          resolveTool = r;
        }),
      },
      recordingAdapter().adapter,
    );
    await vi.advanceTimersByTimeAsync(10_000);
    expect(checkPermitValid).not.toHaveBeenCalled();
    resolveTool("x");
    await expect(p).resolves.toBe("ok:x:dec_1:hash_1");
  });
});

describe("startPermitHeartbeat", () => {
  it("clamps the interval to at least 1000 ms", async () => {
    vi.useFakeTimers();
    const checkPermitValid = vi.fn(async () => ({ status: "active" }));
    const hb = startPermitHeartbeat(
      { checkPermitValid } as unknown as AtlaSentClient,
      "p",
      10,
    );
    await vi.advanceTimersByTimeAsync(999);
    expect(checkPermitValid).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1);
    expect(checkPermitValid).toHaveBeenCalledTimes(1);
    hb.stop();
    await vi.advanceTimersByTimeAsync(5000);
    expect(checkPermitValid).toHaveBeenCalledTimes(1);
  });

  it("keeps polling after a network error and only rejects on revoked", async () => {
    vi.useFakeTimers();
    const checkPermitValid = vi
      .fn()
      .mockRejectedValueOnce(new Error("blip"))
      .mockResolvedValueOnce({ status: "expired" })
      .mockResolvedValueOnce({ status: "revoked" });
    const hb = startPermitHeartbeat(
      { checkPermitValid } as unknown as AtlaSentClient,
      "p",
      1000,
    );
    const outcome = hb.revocationSignal.catch((e: unknown) => e);
    await vi.advanceTimersByTimeAsync(3000);
    expect(await outcome).toBeInstanceOf(PermitRevoked);
    await vi.advanceTimersByTimeAsync(3000);
    expect(checkPermitValid).toHaveBeenCalledTimes(3);
  });

  it("does not reject when stopped before an in-flight revoked poll resolves", async () => {
    vi.useFakeTimers();
    let resolvePoll: (v: unknown) => void = () => {};
    const checkPermitValid = vi.fn(
      () => new Promise((r) => {
        resolvePoll = r;
      }),
    );
    const hb = startPermitHeartbeat(
      { checkPermitValid } as unknown as AtlaSentClient,
      "p",
      1000,
    );
    const rejected = vi.fn();
    hb.revocationSignal.catch(rejected);
    await vi.advanceTimersByTimeAsync(1000);
    hb.stop();
    resolvePoll({ status: "revoked" });
    await vi.advanceTimersByTimeAsync(0);
    expect(rejected).not.toHaveBeenCalled();
  });

  it("is a no-op for a client without checkPermitValid", async () => {
    vi.useFakeTimers();
    const hb = startPermitHeartbeat({} as AtlaSentClient, "p", 1000);
    const rejected = vi.fn();
    hb.revocationSignal.catch(rejected);
    await vi.advanceTimersByTimeAsync(5000);
    hb.stop();
    expect(rejected).not.toHaveBeenCalled();
  });
});

describe("stock adapters", () => {
  const permit = { permitId: "p1", auditHash: "h1" };

  it("jsonStringResultAdapter annotates JSON-object strings only", () => {
    expect(JSON.parse(jsonStringResultAdapter.onExecuted('{"a":1}', permit))).toEqual({
      a: 1,
      _atlasent_permit_id: "p1",
      _atlasent_audit_hash: "h1",
    });
    expect(jsonStringResultAdapter.onExecuted("plain text", permit)).toBe("plain text");
    expect(jsonStringResultAdapter.onExecuted("[1,2]", permit)).toBe("[1,2]");
    expect(jsonStringResultAdapter.onExecuted("null", permit)).toBe("null");
    expect(
      jsonStringResultAdapter.encodeDenial({
        denied: true,
        decision: "deny",
        evaluationId: "e",
        reason: "r",
      }),
    ).toBe('{"denied":true,"decision":"deny","evaluationId":"e","reason":"r"}');
  });

  it("objectResultAdapter annotates plain objects only", () => {
    expect(objectResultAdapter.onExecuted({ a: 1 }, permit)).toEqual({
      a: 1,
      _atlasent_permit_id: "p1",
      _atlasent_audit_hash: "h1",
    });
    expect(objectResultAdapter.onExecuted("s", permit)).toBe("s");
    expect(objectResultAdapter.onExecuted([1], permit)).toEqual([1]);
    expect(objectResultAdapter.onExecuted(null, permit)).toBeNull();
    const d: GuardDenialResult = { denied: true, decision: "deny", evaluationId: "e", reason: "r" };
    expect(objectResultAdapter.encodeDenial(d)).toBe(d);
  });
});

describe("exports", () => {
  it("resolveGuardValue handles static and async values", async () => {
    await expect(resolveGuardValue("x", "t", {})).resolves.toBe("x");
    await expect(resolveGuardValue(async (n) => `${n}!`, "t", {})).resolves.toBe("t!");
  });

  it("the guard core is exported from the package entrypoint", () => {
    expect(sdk.runGuardedToolCall).toBe(runGuardedToolCall);
    expect(sdk.jsonStringResultAdapter).toBe(jsonStringResultAdapter);
    expect(sdk.objectResultAdapter).toBe(objectResultAdapter);
    expect(sdk.DEFAULT_GUARD_TOOL_ACTION).toBe("agent.tool.invoke");
  });
});
