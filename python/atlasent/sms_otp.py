"""SMS OTP client for the AtlaSent Python SDK.

Send and verify one-time passcodes for session-level operations that require
step-up authentication.

Wire surface: /v1-sms-otp/* endpoints in atlasent-api.
Auth: JWT session only (not API key).

Usage::

    from atlasent import AtlaSentClient
    from atlasent.sms_otp import SmsOtpClient

    client = AtlaSentClient(api_key="...")
    otp = SmsOtpClient(client)

    result = otp.send(phone_e164="+15551234567", action_context="break_glass")
    otp_id = result["otp_id"]

    verification = otp.verify(otp_id=otp_id, code="123456")
    if not verification["valid"]:
        raise RuntimeError("OTP verification failed")
"""

from __future__ import annotations

import json
import urllib.request as urllib_request
from typing import TYPE_CHECKING, Any, Literal

from ._function_region import function_region_headers
from .exceptions import AtlaSentError

if TYPE_CHECKING:
    from .client import AtlaSentClient

# The set of action contexts that can trigger an SMS OTP challenge.
SmsOtpActionContext = Literal[
    "break_glass",
    "api_key_create",
    "governance_hold_approve",
]


def _post(
    client: AtlaSentClient,
    path: str,
    body: dict[str, Any],
    session_jwt: str,
) -> Any:
    url = f"{client.base_url.rstrip('/')}{path}"
    headers = {
        "Authorization": f"Bearer {session_jwt}",
        **function_region_headers(url),
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    data = json.dumps(body).encode()
    req = urllib_request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib_request.urlopen(req) as resp:
            raw = resp.read()
            return json.loads(raw) if raw else {}
    except Exception as exc:  # noqa: BLE001
        raise AtlaSentError(f"SMS OTP client request failed: {exc}") from exc


class SmsOtpClient:
    """SMS OTP step-up authentication client.

    Obtain via ``SmsOtpClient(atlasent_client)``::

        client = AtlaSentClient(api_key="...")
        otp = SmsOtpClient(client)

        # Obtain a JWT session token from Supabase Auth before calling.
        jwt = supabase.auth.get_session().session.access_token

        result = otp.send(phone_e164="+15551234567", action_context="break_glass",
                          session_jwt=jwt)
        verification = otp.verify(otp_id=result["otp_id"], code="123456",
                                  session_jwt=jwt)
    """

    def __init__(self, client: AtlaSentClient) -> None:
        self._client = client

    def send(
        self,
        *,
        phone_e164: str,
        action_context: SmsOtpActionContext,
        session_jwt: str,
    ) -> dict[str, Any]:
        """Send an OTP to the given phone number for the specified action context.

        Requires a valid JWT session (not an API key). Obtain the JWT from
        ``supabase.auth.get_session().session.access_token``.

        :param phone_e164: Destination phone number in E.164 format (e.g.
            ``"+15551234567"``).
        :param action_context: The high-privilege action being gated behind
            this OTP. One of ``"break_glass"``, ``"api_key_create"``, or
            ``"governance_hold_approve"``.
        :param session_jwt: Supabase session JWT for the authenticated user.
            SMS OTP endpoints reject API keys — a JWT is required.
        :returns: Dict with ``otp_id`` (str) and ``expires_at`` (ISO-8601 str).
        :raises AtlaSentError: On network or auth failure.
        """
        return _post(
            self._client,
            "/v1-sms-otp/send",
            {
                "phone_e164": phone_e164,
                "action_context": action_context,
            },
            session_jwt,
        )

    def verify(
        self,
        *,
        otp_id: str,
        code: str,
        session_jwt: str,
    ) -> dict[str, Any]:
        """Verify a code against a pending OTP challenge.

        Returns a dict with ``valid: bool``. ``valid=False`` on mismatch or
        expiry — this method never raises on a failed OTP; it raises only on
        network or auth failure.

        :param otp_id: The ``otp_id`` returned by :meth:`send`.
        :param code: The code the user entered from their SMS.
        :param session_jwt: Supabase session JWT for the authenticated user.
        :returns: Dict with ``valid`` (bool).
        :raises AtlaSentError: On network or auth failure.
        """
        return _post(
            self._client,
            "/v1-sms-otp/verify",
            {
                "otp_id": otp_id,
                "code": code,
            },
            session_jwt,
        )
