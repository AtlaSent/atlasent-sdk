"""Where a developer without an API key gets one.

Appended to every missing-key error, the first thing most new installers
see. Tagged so a signup that follows is attributed to this SDK's error path.
"""

API_KEY_SIGNUP_URL = (
    "https://console.atlasent.io/auth/sign-up?utm_source=sdk&utm_medium=py-error"
)
MISSING_API_KEY_HINT = f"Get a free API key at {API_KEY_SIGNUP_URL}"
