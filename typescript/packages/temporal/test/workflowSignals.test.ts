/**
 * Tests for the workflow-side signal helper and bulk-revoke activity.
 *
 * Strategy:
 *   - Stub `@temporalio/workflow` via `vi.mock` (hoisted) to test
 *     `installRevokeHandler` without a real Temporal runtime.
 *   - Stub `@atlasent/sdk-v2-alpha` via `vi.mock` to test the env-key
 *     path of `bulkRevokeAtlaSentPermits` without a real HTTP call.
 *   - `createBulkRevokeActivity` is tested with a plain mock client.
 */

import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";

// ── Hoist: all mock state must come from vi.hoisted ─────────────────

const {
  setHandlerMock,
  proxyActivitiesMock,
  workflowInfoMock,
  defineSignalSentinel,
  bulkRevokeProxy,
  v2BulkRevokeMock,
} = vi.hoisted(() => {
  const bulkRevokeProxy = vi.fn(async () => undefined);
  const proxyObj = { bulkRevokeAtlaSentPermits: bulkRevokeProxy };
  const proxyActivitiesMock = vi.fn(() => proxyObj);
  const setHandlerMock = vi.fn();
  const workflowInfoMock = vi.fn(() => ({
    workflowId: "wf-1",
    runId: "run-abc",
  }));
  const defineSignalSentinel = { __kind: "signal-def" };
  const v2BulkRevokeMock = vi.fn(async () => undefined);
  return {
    setHandlerMock,
    proxyActivitiesMock,
    workflowInfoMock,
    defineSignalSentinel,
    bulkRevokeProxy,
    v2BulkRevokeMock,
  };
});

vi.mock("@temporalio/workflow", () => ({
  defineSignal: vi.fn(() => defineSignalSentinel),
  proxyActivities: proxyActivitiesMock,
  setHandler: setHandlerMock,
  workflowInfo: workflowInfoMock,
}));

vi.mock("@atlasent/sdk-v2-alpha", () => ({
  // Vitest 4 constructs `new V2Client(...)` through the mock, so the
  // implementation must be constructible (a `function`, not an arrow).
  V2Client: vi.fn(function () {
    return { bulkRevoke: v2BulkRevokeMock };
  }),
}));

import {
  bulkRevokeAtlaSentPermits,
  BulkRevokeNotImplementedError,
  createBulkRevokeActivity,
  installRevokeHandler,
  RevokeAtlaSentPermitsSignal,
} from "../src/index.js";

// ── installRevokeHandler ─────────────────────────────────────────────

describe("installRevokeHandler", () => {
  it("registers a handler for RevokeAtlaSentPermitsSignal", () => {
    setHandlerMock.mockClear();
    installRevokeHandler();
    expect(setHandlerMock).toHaveBeenCalledTimes(1);
    expect(setHandlerMock.mock.calls[0]?.[0]).toBe(RevokeAtlaSentPermitsSignal);
    expect(typeof setHandlerMock.mock.calls[0]?.[1]).toBe("function");
  });

  it("uses proxyActivities with a 30s default startToCloseTimeout", () => {
    proxyActivitiesMock.mockClear();
    installRevokeHandler();
    expect(proxyActivitiesMock).toHaveBeenCalledWith({
      startToCloseTimeout: "30s",
    });
  });

  it("respects a custom startToCloseTimeout", () => {
    proxyActivitiesMock.mockClear();
    installRevokeHandler({ startToCloseTimeout: "5m" });
    expect(proxyActivitiesMock).toHaveBeenCalledWith({
      startToCloseTimeout: "5m",
    });
  });

  it("does not call proxyActivities when activities are injected", () => {
    proxyActivitiesMock.mockClear();
    const customActivity = vi.fn(async () => undefined);
    installRevokeHandler({
      activities: { bulkRevokeAtlaSentPermits: customActivity },
    });
    expect(proxyActivitiesMock).not.toHaveBeenCalled();
  });

  it("the handler enriches signal args with workflow + run id", async () => {
    setHandlerMock.mockClear();
    bulkRevokeProxy.mockClear();
    workflowInfoMock.mockReturnValue({
      workflowId: "deploy-wf",
      runId: "run-42",
    });

    installRevokeHandler();
    const handler = setHandlerMock.mock.calls[0]?.[1] as (
      args: { reason: string; revoker_id?: string },
    ) => Promise<void>;

    await handler({ reason: "operator pause", revoker_id: "alice" });

    expect(bulkRevokeProxy).toHaveBeenCalledWith({
      reason: "operator pause",
      revoker_id: "alice",
      workflow_id: "deploy-wf",
      run_id: "run-42",
    });
  });

  it("the handler delegates to a custom activity reference", async () => {
    setHandlerMock.mockClear();
    const customActivity = vi.fn(async () => undefined);
    workflowInfoMock.mockReturnValue({ workflowId: "my-wf", runId: "my-run" });

    installRevokeHandler({
      activities: { bulkRevokeAtlaSentPermits: customActivity },
    });
    const handler = setHandlerMock.mock.calls[0]?.[1] as (
      args: { reason: string },
    ) => Promise<void>;

    await handler({ reason: "ttl" });

    expect(customActivity).toHaveBeenCalledWith({
      reason: "ttl",
      workflow_id: "my-wf",
      run_id: "my-run",
    });
  });
});

// ── bulkRevokeAtlaSentPermits — no API key ───────────────────────────

describe("bulkRevokeAtlaSentPermits without ATLASENT_API_KEY", () => {
  const savedKey = process.env["ATLASENT_API_KEY"];
  const savedV2Key = process.env["ATLASENT_V2_API_KEY"];

  beforeEach(() => {
    delete process.env["ATLASENT_API_KEY"];
    delete process.env["ATLASENT_V2_API_KEY"];
  });

  afterEach(() => {
    if (savedKey !== undefined) process.env["ATLASENT_API_KEY"] = savedKey;
    if (savedV2Key !== undefined) process.env["ATLASENT_V2_API_KEY"] = savedV2Key;
  });

  it("throws BulkRevokeNotImplementedError with workflow context", async () => {
    await expect(
      bulkRevokeAtlaSentPermits({
        reason: "operator pause",
        workflow_id: "wf-1",
        run_id: "run-abc",
      }),
    ).rejects.toThrow(BulkRevokeNotImplementedError);
  });

  it("error message names the workflow + run + reason", async () => {
    await expect(
      bulkRevokeAtlaSentPermits({
        reason: "ttl_expired",
        workflow_id: "wf-x",
        run_id: "run-y",
      }),
    ).rejects.toMatchObject({
      message: expect.stringContaining("wf-x"),
    });
  });

  it("preserves a typed name on the error class", async () => {
    try {
      await bulkRevokeAtlaSentPermits({ reason: "t", workflow_id: "w", run_id: "r" });
    } catch (err) {
      expect(err).toBeInstanceOf(BulkRevokeNotImplementedError);
      expect((err as Error).name).toBe("BulkRevokeNotImplementedError");
    }
  });
});

// ── bulkRevokeAtlaSentPermits — with API key ─────────────────────────

describe("bulkRevokeAtlaSentPermits with ATLASENT_API_KEY set", () => {
  const savedKey = process.env["ATLASENT_API_KEY"];

  beforeEach(() => {
    process.env["ATLASENT_API_KEY"] = "ask_test_key";
    v2BulkRevokeMock.mockClear();
  });

  afterEach(() => {
    if (savedKey !== undefined) {
      process.env["ATLASENT_API_KEY"] = savedKey;
    } else {
      delete process.env["ATLASENT_API_KEY"];
    }
  });

  it("calls V2Client.bulkRevoke with camelCase args", async () => {
    await bulkRevokeAtlaSentPermits({
      workflow_id: "wf-deploy",
      run_id: "run-99",
      reason: "emergency",
      revoker_id: "ops-bot",
    });
    expect(v2BulkRevokeMock).toHaveBeenCalledWith({
      workflowId: "wf-deploy",
      runId: "run-99",
      reason: "emergency",
      revokerId: "ops-bot",
    });
  });

  it("passes undefined revokerId when revoker_id is absent", async () => {
    await bulkRevokeAtlaSentPermits({
      workflow_id: "wf",
      run_id: "run",
      reason: "ttl",
    });
    expect(v2BulkRevokeMock).toHaveBeenCalledWith(
      expect.objectContaining({ revokerId: undefined }),
    );
  });
});

// ── createBulkRevokeActivity ─────────────────────────────────────────

describe("createBulkRevokeActivity", () => {
  it("calls injected client.bulkRevoke with camelCase args", async () => {
    const mockBulkRevoke = vi.fn(async () => ({ revoked_count: 2 }));
    const mockClient = { bulkRevoke: mockBulkRevoke };
    const activity = createBulkRevokeActivity(mockClient);

    await activity({
      workflow_id: "wf-1",
      run_id: "run-1",
      reason: "operator pause",
      revoker_id: "alice",
    });

    expect(mockBulkRevoke).toHaveBeenCalledWith({
      workflowId: "wf-1",
      runId: "run-1",
      reason: "operator pause",
      revokerId: "alice",
    });
  });

  it("passes undefined revokerId when revoker_id is absent", async () => {
    const mockBulkRevoke = vi.fn(async () => undefined);
    const activity = createBulkRevokeActivity({ bulkRevoke: mockBulkRevoke });

    await activity({ workflow_id: "wf", run_id: "run", reason: "ttl" });

    expect(mockBulkRevoke).toHaveBeenCalledWith(
      expect.objectContaining({ revokerId: undefined }),
    );
  });
});
