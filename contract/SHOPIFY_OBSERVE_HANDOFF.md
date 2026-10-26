# Shopify preview observation handoff

This private integration consumes the runtime's existing
`connector-observation.v1` envelope. The new ingress/receipt implementation and
contract of record are API #4727,
`docs/integrations/CONNECTOR_OBSERVE_HANDOFF.md` in atlasent-api.

`POST /v1-connectors/{id}/observations` is fact ingress, independent of the
generic event-ingest enforcer. It requires the existing reserved connector-write
permission; it does not issue a refund decision or any execution capability.
No evaluate/verify request or response wire contract changes here.

The Shopify server fixes the destination in server configuration, re-reads the
verified session's allowlisted shop/order, and checks that key and connector
still match the destination. A browser's expected destination is a comparison
only, never a destination selector. Only the newly generated, non-authorizing
preview enters the envelope; no caller-made authority, identity verification,
refund eligibility or outcome is accepted.

No default key requirement, customer scope expansion, policy activation or
automatic retry is introduced. This is an internal/staging integration slice;
merchant OAuth-to-tenant self-service installation and live acceptance are
separate incomplete work under console #2971 and API #4656.
