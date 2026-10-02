export type DeploymentPosture = "saas" | "self_hosted" | "air_gapped";

export interface EnterpriseInquiryRequest {
  company_name: string;
  company_size: string;
  industry: string;
  use_cases: string[];
  contact_name: string;
  contact_email: string;
  deployment_posture: DeploymentPosture;
  notes?: string;
}

export interface EnterpriseInquiryResponse {
  id: string;
  submitted_at: string;
}

/**
 * Submit an enterprise enrollment inquiry without requiring an API key.
 * This is a public endpoint — call it from pre-auth marketing pages or
 * sign-up flows before the customer has been provisioned.
 *
 * @param baseUrl   AtlaSent API base URL (e.g. "https://api.atlasent.io")
 * @param input     Inquiry form data
 */

import { functionRegionHeaders } from "./functionRegion.js";
export async function submitEnterpriseInquiry(
  baseUrl: string,
  input: EnterpriseInquiryRequest,
): Promise<EnterpriseInquiryResponse> {
  const url = `${baseUrl.replace(/\/$/, "")}/v1/enterprise-inquiry`;
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...functionRegionHeaders(url) },
    body: JSON.stringify(input),
    signal: AbortSignal.timeout(10_000),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(
      `EnterpriseInquiry POST failed (${res.status}): ${text}`,
    );
  }
  return res.json() as Promise<EnterpriseInquiryResponse>;
}
