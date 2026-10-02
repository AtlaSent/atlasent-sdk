/**
 * SMS OTP sub-client — send and verify one-time passcodes for
 * session-level operations that require step-up authentication.
 *
 * Wire surface: /v1-sms-otp/* endpoints in atlasent-api.
 * Auth: JWT session only (not API key). Pass the caller's Supabase session
 * JWT via the `sessionJwt` field on each request.
 *
 * Usage:
 *
 * ```ts
 * import { AtlaSentClient } from "@atlasent/sdk";
 *
 * const client = new AtlaSentClient({ apiKey: "..." });
 * const jwt = (await supabase.auth.getSession()).data.session?.access_token;
 *
 * // Send an OTP before a break-glass operation
 * const { otp_id, expires_at } = await client.smsOtp.send({
 *   phone_e164: "+15551234567",
 *   action_context: "break_glass",
 *   sessionJwt: jwt,
 * });
 *
 * // Verify the code the user entered
 * const { valid } = await client.smsOtp.verify({ otp_id, code: "123456", sessionJwt: jwt });
 * ```
 */

import { functionRegionHeaders } from "./functionRegion.js";
import { AtlaSentError } from "./errors.js";

// ── Types ─────────────────────────────────────────────────────────────────────

/** The set of action contexts that can trigger an SMS OTP challenge. */
export type SmsOtpActionContext =
  | "break_glass"
  | "api_key_create"
  | "governance_hold_approve";

/** Request body for `smsOtp.send()`. */
export interface SmsOtpSendRequest {
  /** Destination phone number in E.164 format (e.g. `"+15551234567"`). */
  phone_e164: string;
  /** The high-privilege action being gated behind this OTP. */
  action_context: SmsOtpActionContext;
  /**
   * Supabase JWT session token for the authenticated user.
   * Obtain via `(await supabase.auth.getSession()).data.session?.access_token`.
   * SMS OTP endpoints require a JWT session — API keys are rejected.
   */
  sessionJwt: string;
}

/** Response from `smsOtp.send()`. */
export interface SmsOtpSendResponse {
  /** Opaque identifier for this OTP challenge — pass to `verify()`. */
  otp_id: string;
  /** ISO-8601 timestamp when this OTP expires. */
  expires_at: string;
}

/** Request body for `smsOtp.verify()`. */
export interface SmsOtpVerifyRequest {
  /** The `otp_id` returned by `send()`. */
  otp_id: string;
  /** The code the user entered from their SMS. */
  code: string;
  /**
   * Supabase JWT session token for the authenticated user.
   * Must match the session that called `send()`.
   */
  sessionJwt: string;
}

/** Response from `smsOtp.verify()`. */
export interface SmsOtpVerifyResponse {
  /** `true` when the code matches and has not expired or been consumed. */
  valid: boolean;
}

// ── Sub-client interface ──────────────────────────────────────────────────────

/**
 * Sub-client for SMS OTP step-up authentication.
 * Accessed as `client.smsOtp` on {@link AtlaSentClient}.
 */
export interface SmsOtpSubClient {
  /**
   * Send an OTP to the given phone number for the specified action context.
   *
   * Requires a valid JWT session (not an API key). Pass the session JWT via
   * `sessionJwt`. The OTP is short-lived and single-use.
   *
   * ```ts
   * const { otp_id } = await client.smsOtp.send({
   *   phone_e164: "+15551234567",
   *   action_context: "break_glass",
   *   sessionJwt: jwt,
   * });
   * ```
   */
  send(params: SmsOtpSendRequest): Promise<SmsOtpSendResponse>;

  /**
   * Verify a code against a pending OTP challenge.
   *
   * Returns `{ valid: true }` when the code matches and the OTP has not
   * expired. Returns `{ valid: false }` on mismatch or expiry — never
   * throws on a failed verification. Network or auth errors throw
   * {@link AtlaSentError}.
   *
   * ```ts
   * const { valid } = await client.smsOtp.verify({ otp_id, code, sessionJwt: jwt });
   * ```
   */
  verify(params: SmsOtpVerifyRequest): Promise<SmsOtpVerifyResponse>;
}

// ── Wire types ────────────────────────────────────────────────────────────────

interface SmsOtpSendResponseWire {
  otp_id: string;
  expires_at: string;
}

interface SmsOtpVerifyResponseWire {
  valid: boolean;
}

// ── Factory ───────────────────────────────────────────────────────────────────

/**
 * Factory that returns the SMS OTP sub-client.
 * Uses direct JWT-authenticated fetch — not the API-key transport.
 * Called internally by AtlaSentClient; not part of the public constructor API.
 */
export function makeSmsOtpClient(
  baseUrl: string,
  fetchImpl: typeof fetch,
): SmsOtpSubClient {
  async function jwtPost<T>(path: string, body: unknown, sessionJwt: string): Promise<T> {
    const resp = await fetchImpl(`${baseUrl}${path}`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${sessionJwt}`,
        ...functionRegionHeaders(baseUrl),
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify(body),
    });
    if (!resp.ok) {
      const text = await resp.text().catch(() => "");
      throw new AtlaSentError(`SMS OTP request failed: ${resp.status} ${text}`, {
        code: "network",
      });
    }
    return resp.json() as Promise<T>;
  }

  return {
    async send(params: SmsOtpSendRequest): Promise<SmsOtpSendResponse> {
      const body = await jwtPost<SmsOtpSendResponseWire>(
        "/v1-sms-otp/send",
        { phone_e164: params.phone_e164, action_context: params.action_context },
        params.sessionJwt,
      );
      return { otp_id: body.otp_id, expires_at: body.expires_at };
    },

    async verify(params: SmsOtpVerifyRequest): Promise<SmsOtpVerifyResponse> {
      const body = await jwtPost<SmsOtpVerifyResponseWire>(
        "/v1-sms-otp/verify",
        { otp_id: params.otp_id, code: params.code },
        params.sessionJwt,
      );
      return { valid: body.valid };
    },
  };
}
