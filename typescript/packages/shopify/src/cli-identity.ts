/** Server/process configuration only; never pass model, browser or tool input. */
import { createAgentActorIdentityResolver } from "./agent-identity.js";
import type { RefundGuardOptions } from "./guard.js";

export type CliEnvironment = Readonly<Record<string, string | undefined>>;

export function refundCliIdentity(
  config: CliEnvironment,
  apiKey: string,
  legacyActor: string,
): Pick<RefundGuardOptions, "actor" | "resolveActorIdentity"> {
  const mode = config.ATLASENT_ACTOR_IDENTITY;
  if (mode === undefined) {
    if (config.ATLASENT_TENANT_ID !== undefined) {
      throw new Error("ATLASENT_TENANT_ID requires ATLASENT_ACTOR_IDENTITY=agent-key");
    }
    return { actor: legacyActor };
  }
  if (mode !== "agent-key") throw new Error("ATLASENT_ACTOR_IDENTITY must be agent-key when configured");
  const actor = config.ATLASENT_ACTOR, tenantId = config.ATLASENT_TENANT_ID;
  if (!actor || !tenantId) {
    throw new Error("agent-key identity requires ATLASENT_ACTOR=agent:<enrolled UUID> and ATLASENT_TENANT_ID");
  }
  return {
    actor,
    resolveActorIdentity: createAgentActorIdentityResolver({ apiKey, actor, tenantId,
      ...(config.ATLASENT_BASE_URL !== undefined ? { baseUrl: config.ATLASENT_BASE_URL } : {}),
    }),
  };
}
