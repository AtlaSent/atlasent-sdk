import { functionRegionHeaders } from "./functionRegion.js";

export type EnforcementMode = "observe" | "warn" | "enforce";

export interface HealthReport {
  readonly healthy: boolean;
  readonly apiReachable: boolean;
  readonly authenticated: boolean;
  readonly latencyMs: number | null;
  readonly apiVersion: string | null;
  readonly checkedAt: string;
  readonly errors: string[];
}

export interface EnforcementStatus {
  readonly actionClass: string;
  readonly mode: EnforcementMode;
  readonly blockRate: number | null;
  readonly totalEvaluations: number | null;
  readonly lastSeenAt: string | null;
  readonly schemaRegistered: boolean;
}

export interface ProtectedActionEntry {
  readonly actionClass: string;
  readonly firstRegisteredAt: string;
  readonly lastUpdatedAt: string;
  readonly enforcementMode: EnforcementMode;
  readonly schemaId: string | null;
  readonly tags: string[];
}

export interface OrgSummary {
  readonly orgId: string;
  readonly activePolicies: number;
  readonly totalPolicies: number;
  readonly activeOverrides: number;
  readonly pendingEscalations: number;
  readonly evidenceSigningEnabled: boolean;
  readonly shadowModeActions: number;
  readonly enforcedActions: number;
  readonly lastEvaluationAt: string | null;
}

export interface ControlSurfaceConfig {
  apiKey?: string;
  baseUrl?: string;
  timeoutMs?: number;
}

let _config: ControlSurfaceConfig = {};

export function configureControlSurface(config: ControlSurfaceConfig): void {
  _config = { ..._config, ...config };
}

function resolveConfig(opts?: ControlSurfaceConfig): Required<ControlSurfaceConfig> {
  return {
    apiKey: opts?.apiKey ?? _config.apiKey ?? process.env["ATLASENT_API_KEY"] ?? "",
    baseUrl: opts?.baseUrl ?? _config.baseUrl ?? process.env["ATLASENT_BASE_URL"] ?? "https://api.atlasent.ai",
    timeoutMs: opts?.timeoutMs ?? _config.timeoutMs ?? 10_000,
  };
}

async function apiGet<T>(
  path: string,
  config: Required<ControlSurfaceConfig>,
): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), config.timeoutMs);
  try {
    const res = await fetch(`${config.baseUrl}${path}`, {
      method: "GET",
      headers: {
        Authorization: `Bearer ${config.apiKey}`,
        ...functionRegionHeaders(config.baseUrl),
        Accept: "application/json",
      },
      signal: controller.signal,
    });
    if (!res.ok) {
      throw new Error(`HTTP ${res.status}`);
    }
    return res.json() as Promise<T>;
  } finally {
    clearTimeout(timer);
  }
}

async function apiPost<T>(
  path: string,
  body: unknown,
  config: Required<ControlSurfaceConfig>,
): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), config.timeoutMs);
  try {
    const res = await fetch(`${config.baseUrl}${path}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${config.apiKey}`,
        ...functionRegionHeaders(config.baseUrl),
      },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
    if (!res.ok) {
      throw new Error(`HTTP ${res.status}`);
    }
    return res.json() as Promise<T>;
  } finally {
    clearTimeout(timer);
  }
}

export async function checkIntegrationHealth(
  opts?: ControlSurfaceConfig,
): Promise<HealthReport> {
  const config = resolveConfig(opts);
  const errors: string[] = [];
  let apiReachable = false;
  let authenticated = false;
  let latencyMs: number | null = null;
  let apiVersion: string | null = null;

  if (!config.apiKey) {
    errors.push("ATLASENT_API_KEY is not configured");
  }

  const start = Date.now();
  try {
    const data = await apiGet<{ version?: string; status?: string }>("/v1/health", config);
    latencyMs = Date.now() - start;
    apiReachable = true;
    apiVersion = data.version ?? null;
    if (data.status === "ok" || data.status === "healthy") {
      authenticated = true;
    } else {
      errors.push(`API health status: ${data.status ?? "unknown"}`);
    }
  } catch (err) {
    latencyMs = Date.now() - start;
    const message = err instanceof Error ? err.message : String(err);
    if (message.includes("401") || message.includes("403")) {
      apiReachable = true;
      errors.push("API key is invalid or lacks required permissions");
    } else {
      errors.push(`API unreachable: ${message}`);
    }
  }

  return {
    healthy: apiReachable && authenticated && errors.length === 0,
    apiReachable,
    authenticated,
    latencyMs,
    apiVersion,
    checkedAt: new Date().toISOString(),
    errors,
  };
}

export interface ReportProtectedActionOptions extends ControlSurfaceConfig {
  actionClass: string;
  enforcementMode?: EnforcementMode;
  schemaId?: string;
  tags?: string[];
}

export async function reportProtectedAction(
  opts: ReportProtectedActionOptions,
): Promise<ProtectedActionEntry> {
  const config = resolveConfig(opts);
  return apiPost<ProtectedActionEntry>(
    "/v1/control-surface/actions",
    {
      action_class: opts.actionClass,
      enforcement_mode: opts.enforcementMode ?? "observe",
      schema_id: opts.schemaId ?? null,
      tags: opts.tags ?? [],
    },
    config,
  );
}

export interface GetEnforcementStatusOptions extends ControlSurfaceConfig {
  actionClass: string;
}

export async function getEnforcementStatus(
  opts: GetEnforcementStatusOptions,
): Promise<EnforcementStatus> {
  const config = resolveConfig(opts);
  return apiGet<EnforcementStatus>(
    `/v1/control-surface/actions/${encodeURIComponent(opts.actionClass)}/status`,
    config,
  );
}

export async function getOrgSummary(
  opts?: ControlSurfaceConfig,
): Promise<OrgSummary> {
  const config = resolveConfig(opts);
  return apiGet<OrgSummary>("/v1/control-surface/summary", config);
}
