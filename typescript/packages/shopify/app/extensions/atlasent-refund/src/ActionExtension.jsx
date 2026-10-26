// Read-only order preview on the order details page. No refund or resume action.
// React admin UI extension API (api_version 2025-07).

import { useEffect, useRef, useState } from "react";
import { centsFromAmount, parseRefundPreview, parseInboxDestination, parseObservationReceipt } from "./preview-view.js";
import {
  reactExtension,
  useApi,
  AdminAction,
  BlockStack,
  Banner,
  Button,
  Text,
  TextField,
} from "@shopify/ui-extensions-react/admin";

const TARGET = "admin.order-details.action.render";

export default reactExtension(TARGET, () => <OrderPreview />);

function OrderPreview() {
  const { close, data, auth } = useApi(TARGET);
  const orderId = data.selected[0]?.id;
  const [amount, setAmount] = useState("");
  const [inboxDestination, setInboxDestination] = useState(null);
  const [submission, setSubmission] = useState(null);
  const submissionInFlight = useRef(false);
  const [preview, setPreview] = useState(null);
  const [previewError, setPreviewError] = useState(null);
  const [previewBusy, setPreviewBusy] = useState(false);
  const previewSequence = useRef(0);

  const valid = centsFromAmount(amount) !== null;

  // An in-flight response from another order must never appear as this order.
  useEffect(() => {
    previewSequence.current += 1;
    setPreview(null);
    setInboxDestination(null);
    setPreviewError(null);
    setPreviewBusy(false);
  }, [orderId]);

  function changeAmount(value) {
    if (submissionInFlight.current) return;
    previewSequence.current += 1;
    setAmount(value);
    setPreview(null);
    setInboxDestination(null);
    setPreviewError(null);
    setPreviewBusy(false);
  }

  async function loadPreview(handoff = false) {
    if (submissionInFlight.current) return;
    const expectedDestination = inboxDestination;
    if (handoff && !expectedDestination) return;
    const amountCents = centsFromAmount(amount);
    if (!orderId || amountCents === null) return;
    const request = { orderId, amountCents, destination: expectedDestination };
    if (handoff) {
      submissionInFlight.current = true;
      setSubmission({ ...request, state: "pending" });
    }
    const sequence = ++previewSequence.current;
    setPreviewBusy(true);
    setPreview(null);
    setInboxDestination(null);
    setPreviewError(null);
    try {
      const token = await auth.idToken();
      const response = await fetch(handoff ? "/api/operations/refund-preview/inbox" : "/api/operations/refund-preview", {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
        // The server fetches source facts. Never send caller-made eligibility or approval.
        body: JSON.stringify({ orderId, amount: amount.trim(), ...(handoff ? { expected_destination: expectedDestination } : {}) }),
      });
      const body = await response.json().catch(() => null);
      if (!handoff && sequence !== previewSequence.current) return;
      if (handoff) {
        const safe = response.ok && parseRefundPreview(body?.preview, orderId, amount);
        const saved = response.ok && parseObservationReceipt(body?.receipt, expectedDestination);
        if (!safe || !saved) throw new Error("Inbox submission outcome unconfirmed");
        setSubmission({ ...request, state: "recorded", receipt: saved });
        if (sequence === previewSequence.current) setPreview(safe);
        return;
      }
      if (!response.ok) {
        setPreviewError("The authenticated Shopify order read is unavailable. No refund was evaluated.");
        return;
      }
      const safe = parseRefundPreview(body, orderId, amount);
      if (!safe) {
        setPreviewError("The preview could not be verified for this order and amount. No refund was evaluated.");
        return;
      }
      setInboxDestination(parseInboxDestination(body.inbox_destination));
      setPreview(safe);
    } catch {
      if (handoff) {
        setSubmission({ ...request, state: "unconfirmed" });
      } else if (sequence === previewSequence.current) {
        setPreviewError("Could not load the read-only Shopify preview. No refund was evaluated.");
      }
    } finally {
      if (handoff) submissionInFlight.current = false;
      if (sequence === previewSequence.current) setPreviewBusy(false);
    }
  }

  const handoffPending = submission?.state === "pending";
  const sameSubmission = submission && submission.orderId === orderId && submission.amountCents === centsFromAmount(amount) &&
    submission.destination?.organization_id === inboxDestination?.organization_id && submission.destination?.connector_id === inboxDestination?.connector_id;

  return (
    <AdminAction
      title="AtlaSent order preview"
      primaryAction={
        <Button onPress={() => loadPreview(false)} disabled={!orderId || !valid || previewBusy || handoffPending}>
          {previewBusy ? "Reading order…" : "Preview next step (read only)"}
        </Button>
      }
      secondaryAction={<Button onPress={close} disabled={handoffPending}>Close</Button>}
    >
      <BlockStack gap>
        <Text>
          Read the connected order and prepare an operator next step. This preview does not determine
          eligibility, authorize or issue a refund, or notify a customer.
        </Text>
        <TextField label="Amount (USD)" value={amount} onChange={changeAmount} disabled={handoffPending} />
        {preview && inboxDestination && !sameSubmission && !handoffPending && (
          <BlockStack gap>
            <Text>Observation destination: organization {inboxDestination.organization_id}. This does not authorize a refund.</Text>
            <Button onPress={() => loadPreview(true)} disabled={previewBusy}>Add fresh preview to AtlaSent Inbox</Button>
          </BlockStack>
        )}
        {submission && <Banner tone={submission.state === "unconfirmed" ? "warning" : "info"} title={
          submission.state === "pending" ? "Recording observation…" : submission.state === "recorded" ? "Observation recorded in Action Inbox history" : "Inbox submission outcome unconfirmed"
        }>
          <Text>Submitted order: {submission.orderId}; amount: {submission.amountCents} cents; organization: {submission.destination.organization_id}.</Text>
          {submission.receipt && <Text>Event: {submission.receipt.event_id}.</Text>}
          <Text>{submission.state === "unconfirmed" ? "Check Action Inbox History before submitting again." : "Open Action Inbox → History in this organization. Authorization, execution and verification are still separate."}</Text>
        </Banner>}
        {previewError && <Banner tone="warning" title="Preview unavailable"><Text>{previewError}</Text></Banner>}
        {preview && (
          <Banner tone={preview.disposition === "routine_candidate" ? "info" : "warning"} title={`Preview only: ${preview.statusLabel}`}>
            <Text>{preview.operatorMessage}</Text>
            <Text>Operator next step: {preview.nextStepLabel}</Text>
            <Text>Owner: not assigned by this preview.</Text>
            <Text>Shopify order: {preview.orderId}; observed status: {preview.orderStatus}; currency: {preview.currency}.</Text>
            <Text>Server read at: {preview.readAt} (this does not prove the age of Shopify source facts).</Text>
            <Text>Missing requirements: {preview.missingProofLabels.join(", ")}.</Text>
            <Text>Authorization not evaluated. Execution not attempted. No customer message sent.</Text>
          </Banner>
        )}
      </BlockStack>
    </AdminAction>
  );
}
