/**
 * Base-URL resolution for calls to the AtlaSent runtime.
 *
 * The runtime is a set of Supabase edge functions. Supabase's gateway serves
 * functions under `/functions/v1/<name>`, and answers every other path on the
 * host, including `/<name>` at the root, with
 * `404 {"error":"requested path is invalid"}`. A base URL of bare
 * `https://api.atlasent.io` therefore sends `/v1-evaluate` to a path that can
 * never route, and every call fails before it reaches the evaluator.
 *
 * The SDK's paths (`/v1-evaluate`, `/v1-verify-permit`, ...) are function
 * names, so the base URL has to end at `/functions/v1`. This module is the
 * only place that decides that, in two parts:
 *
 *   1. The built-in default is `https://api.atlasent.io/functions/v1`.
 *   2. A caller-supplied base URL whose host is AtlaSent's hosted runtime
 *      (`HOSTED_RUNTIME_HOSTS`) and whose path is empty or `/` gets
 *      `/functions/v1` appended. Earlier releases documented the bare host as
 *      the default, so code copied from those READMEs keeps working.
 *
 * Part 2 is scoped to the hosted hosts on purpose. A self-hosted runtime or a
 * proxy may mount functions anywhere, so any other host is passed through
 * unchanged, as is a hosted host with any explicit path.
 *
 * Keep in step with the Python SDK's `atlasent._base_url`.
 */

import { HOSTED_RUNTIME_HOSTS } from "./functionRegion.js";

/** Path at which Supabase's gateway serves edge functions. */
export const HOSTED_FUNCTIONS_PATH = "/functions/v1";

/** Built-in base URL: the hosted runtime's functions root. */
export const DEFAULT_BASE_URL = `https://api.atlasent.io${HOSTED_FUNCTIONS_PATH}`;

/**
 * Normalize a base URL: strip trailing slashes and, for a hosted-runtime host
 * given with no path, append {@link HOSTED_FUNCTIONS_PATH}.
 *
 * An unparseable value is returned with its trailing slashes stripped and
 * otherwise untouched; the TLS guard that runs before this is what rejects it.
 */
export function resolveBaseUrl(baseUrl: string): string {
  // A loop rather than /\/+$/: that regex backtracks polynomially on input
  // with many slashes, and the base URL is caller-supplied.
  let end = baseUrl.length;
  while (end > 0 && baseUrl.charCodeAt(end - 1) === 47 /* "/" */) end--;
  const trimmed = baseUrl.slice(0, end);
  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    return trimmed;
  }
  const atRoot = parsed.pathname === "" || parsed.pathname === "/";
  if (
    atRoot &&
    parsed.search === "" &&
    parsed.hash === "" &&
    HOSTED_RUNTIME_HOSTS.has(parsed.hostname.toLowerCase())
  ) {
    return `${trimmed}${HOSTED_FUNCTIONS_PATH}`;
  }
  return trimmed;
}
