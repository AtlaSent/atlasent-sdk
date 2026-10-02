/**
 * Edge-function region pinning for calls to the AtlaSent runtime.
 *
 * Supabase runs an edge function in the region nearest the CALLER, not the
 * database. The hosted runtime's database is in us-west-1, so a call from
 * elsewhere executes far from its data, and each of the handler's sequential
 * database round trips pays that distance. Measured on 2026-10-02, v1-evaluate
 * p50 was 1.8-2.1 s executing in us-west-1 against 5.2-7.3 s in us-east-*.
 * Supabase supports pinning only per request, through the `x-region` header.
 *
 * This module is the only place that decides whether a request carries that
 * header and with what value. The client resolves it once at construction
 * and spreads the result into every runtime request.
 *
 * Resolution, first match wins:
 *   1. `functionRegion` in the client options
 *   2. the ATLASENT_FUNCTION_REGION environment variable (server runtimes)
 *   3. us-west-1, but only for AtlaSent's hosted runtime, and only outside a
 *      browser
 *   4. nothing (Supabase picks the region, the pre-existing behavior)
 *
 * Step 3 is scoped to the hosted runtime because a self-hosted runtime in
 * another region would be made slower, not faster. It is skipped in browsers
 * because `x-region` is a non-simple header that the runtime's CORS policy
 * does not allow, so a browser preflight would fail.
 *
 * "auto" or null means "send no header". Any other value must be a region id;
 * a malformed value throws at construction, because a silently ignored typo
 * would put every call back on the slow path.
 *
 * Keep in step with atlasent-action's `@atlasent/enforce` functionRegion and
 * the Python SDK's `atlasent._function_region`.
 */

export const FUNCTION_REGION_HEADER = "x-region";
export const FUNCTION_REGION_ENV = "ATLASENT_FUNCTION_REGION";
/** Region of the hosted runtime's database. Change only if the database moves. */
export const DEFAULT_FUNCTION_REGION = "us-west-1";

/** Hosts that serve AtlaSent's hosted runtime (production and staging). */
export const HOSTED_RUNTIME_HOSTS: ReadonlySet<string> = new Set([
  "api.atlasent.io",
  "kttccumlnmdtupgbyfue.supabase.co",
  "lwnqpmnxpeyhpxvastku.supabase.co",
]);

const REGION_ID = /^[a-z]{2}-[a-z]+-[0-9]$/;

export class FunctionRegionConfigError extends Error {
  constructor(value: string) {
    super(
      `Invalid function region "${value}": expected a region id such as ` +
        `"${DEFAULT_FUNCTION_REGION}", or "auto" to let Supabase choose.`,
    );
    this.name = "FunctionRegionConfigError";
  }
}

export interface FunctionRegionEnvironment {
  env: Record<string, string | undefined>;
  isBrowser: boolean;
}

/** The current runtime: process.env where it exists, and whether this is a browser. */
export function currentFunctionRegionEnvironment(): FunctionRegionEnvironment {
  const g = globalThis as Record<string, unknown>;
  const proc = g["process"] as { env?: Record<string, string | undefined> } | undefined;
  return {
    env: proc?.env ?? {},
    isBrowser: typeof g["window"] !== "undefined" && typeof g["document"] !== "undefined",
  };
}

/** Parse a configured value: a region id, or null for "auto". Throws otherwise. */
export function parseFunctionRegion(value: string): string | null {
  const v = value.trim();
  if (v === "auto") return null;
  if (REGION_ID.test(v)) return v;
  throw new FunctionRegionConfigError(value);
}

function isHostedRuntime(url: string): boolean {
  try {
    return HOSTED_RUNTIME_HOSTS.has(new URL(url).hostname.toLowerCase());
  } catch {
    return false;
  }
}

/**
 * The region requests to `baseUrl` should run in, or null for no pinning.
 * `explicit`: undefined or "" defers to the environment and default; "auto"
 * or null means unpinned; a region id pins.
 */
export function resolveFunctionRegion(
  baseUrl: string,
  explicit?: string | null,
  runtime: FunctionRegionEnvironment = currentFunctionRegionEnvironment(),
): string | null {
  if (explicit === null) return null;
  if (explicit !== undefined && explicit.trim() !== "") return parseFunctionRegion(explicit);
  const fromEnv = runtime.env[FUNCTION_REGION_ENV];
  if (fromEnv !== undefined && fromEnv.trim() !== "") return parseFunctionRegion(fromEnv);
  if (runtime.isBrowser) return null;
  return isHostedRuntime(baseUrl) ? DEFAULT_FUNCTION_REGION : null;
}

/** Headers to spread into a runtime request. Empty when unpinned. */
export function functionRegionHeaders(
  baseUrl: string,
  explicit?: string | null,
  runtime: FunctionRegionEnvironment = currentFunctionRegionEnvironment(),
): Record<string, string> {
  const region = resolveFunctionRegion(baseUrl, explicit, runtime);
  return region ? { [FUNCTION_REGION_HEADER]: region } : {};
}
