// Presentation boundary for the authenticated Shopify read-only operations preview.
// Reject malformed or write-capable responses rather than accidentally rendering
// them as a completed or authorized refund. This file never calls a provider.
const STATUS = Object.freeze({
  routine_candidate: 'Routine candidate — checks still required',
  needs_attention: 'Needs operator review',
  unavailable: 'Source facts unavailable',
});
const NEXT_STEP = Object.freeze({
  verify_business_eligibility: 'Verify the return reason, merchant policy and required authority',
  inspect_payment_history: 'Reconcile payment, refund and dispute history',
  inspect_order_status: 'Confirm fulfillment, delivery and return facts',
  verify_refundable_amount: 'Reconcile the remaining refundable balance',
  obtain_supported_currency: 'Review unsupported or inconsistent currency',
  retry_source_read: 'Reconnect or retry the authenticated Shopify order read',
});

/** Convert a positive decimal dollar string into exact cents, without float rounding. */
export function centsFromAmount(value) {
  if (typeof value !== 'string') return null;
  const match = /^(\\d+)(?:\\.(\\d{1,2}))?$/.exec(value.trim());
  if (!match) return null;
  const whole = Number(match[1]);
  const cents = whole * 100 + Number((match[2] ?? '').padEnd(2, '0'));
  return Number.isSafeInteger(cents) && cents > 0 ? cents : null;
}

/**
 * Accept only the server's explicitly read-only, non-authorizing preview for
 * the exact selected order and amount. A failed check is not a negative
 * refund decision: it is an unavailable preview.
 */
export function parseRefundPreview(payload, expectedOrderId, expectedAmount) {
  const requestedCents = centsFromAmount(expectedAmount);
  if (requestedCents === null || typeof expectedOrderId !== 'string' || !expectedOrderId) return null;
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return null;
  if (payload.schema !== 'atlasent.shopify_refund_operations_preview.v1' ||
      payload.mode !== 'read_only' ||
      payload.authorization !== 'not_evaluated' ||
      payload.execution !== 'not_attempted' ||
      payload.customer_notification !== 'not_sent') return null;
  if (!Object.hasOwn(STATUS, payload.disposition) ||
      !Object.hasOwn(NEXT_STEP, payload.next_step)) return null;
  const observed = payload.observed;
  if (!observed || typeof observed !== 'object' || Array.isArray(observed) ||
      observed.order_id !== expectedOrderId || observed.requested_cents !== requestedCents ||
      typeof observed.currency !== 'string' || typeof observed.order_status !== 'string' ||
      !(observed.refundable_cents === null ||
        (Number.isSafeInteger(observed.refundable_cents) && observed.refundable_cents >= 0))) return null;
  if (typeof payload.read_at !== 'string' || !Number.isFinite(Date.parse(payload.read_at)) ||
      typeof payload.operator_message !== 'string' ||
      payload.operator_message.length === 0 || payload.operator_message.length > 800) return null;
  if (!Array.isArray(payload.missing_proofs) || payload.missing_proofs.length === 0 ||
      payload.missing_proofs.length > 30 ||
      !payload.missing_proofs.every(p => typeof p === 'string' && /^[a-z][a-z0-9_]{0,100}$/.test(p))) return null;
  return {
    disposition: payload.disposition,
    statusLabel: STATUS[payload.disposition],
    nextStepLabel: NEXT_STEP[payload.next_step],
    operatorMessage: payload.operator_message,
    orderId: observed.order_id,
    requestedCents,
    refundableCents: observed.refundable_cents,
    currency: observed.currency,
    orderStatus: observed.order_status,
    readAt: payload.read_at,
    // These are missing requirements, not failed checks or proven violations.
    missingProofLabels: payload.missing_proofs.map(p => p.replaceAll('_', ' ')),
  };
}
