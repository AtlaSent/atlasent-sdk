// "Refund via AtlaSent": an admin action on the order details page.
//
// The button collects an amount and a reason and sends them to the app
// backend (../../../../src/server.ts, POST /api/refunds) with the staff
// member's session token. The backend runs the AtlaSent gate; this UI only
// shows what came back. It never calls Shopify's refund API itself.
//
// Written against the React admin UI extension API (api_version 2025-07).
// Newer API versions use Preact and web components; port before upgrading.

import { useEffect, useRef, useState } from "react";
import { centsFromAmount, parseRefundPreview } from "./preview-view.js";
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

export default reactExtension(TARGET, () => <RefundViaAtlaSent />);

function RefundViaAtlaSent() {
  const { close, data, auth } = useApi(TARGET);
  const orderId = data.selected[0]?.id;
  const [amount, setAmount] = useState("");
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState(null);
  const [preview, setPreview] = useState(null);
  const [previewError, setPreviewError] = useState(null);
  const [previewBusy, setPreviewBusy] = useState(false);
  const previewSequence = useRef(0);

  const valid = centsFromAmount(amount) !== null;

  // An in-flight response from another order must never appear as this order.
  useEffect(() => {
    previewSequence.current += 1;
    setPreview(null);
    setPreviewError(null);
    setPreviewBusy(false);
  }, [orderId]);

  function changeAmount(value) {
    previewSequence.current += 1;
    setAmount(value);
    setPreview(null);
    setPreviewError(null);
    setPreviewBusy(false);
  }

  async function loadPreview() {
    if (!orderId || centsFromAmount(amount) === null) return;
    const sequence = ++previewSequence.current;
    setPreviewBusy(true);
    setPreview(null);
    setPreviewError(null);
    try {
      const token = await auth.idToken();
      const response = await fetch("/api/operations/refund-preview", {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
        // The server fetches source facts. Never send caller-made eligibility or approval.
        body: JSON.stringify({ orderId, amount: amount.trim() }),
      });
      const body = await response.json().catch(() => null);
      if (sequence !== previewSequence.current) return;
      if (!response.ok) {
        setPreviewError("The authenticated Shopify order read is unavailable. No refund was evaluated.");
        return;
      }
      const safe = parseRefundPreview(body, orderId, amount);
      if (!safe) {
        setPreviewError("The preview could not be verified for this order and amount. No refund was evaluated.");
        return;
      }
      setPreview(safe);
    } catch {
      if (sequence === previewSequence.current) {
        setPreviewError("Could not load the read-only Shopify preview. No refund was evaluated.");
      }
    } finally {
      if (sequence === previewSequence.current) setPreviewBusy(false);
    }
  }

  // `keep` carries the approval id through a failed check, so it can be retried.
  async function post(path, payload, keep = {}) {
    setBusy(true);
    try {
      const token = await auth.idToken();
      // Relative URL: resolves against the app's application_url.
      const res = await fetch(path, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
        body: JSON.stringify(payload),
      });
      const body = await res.json().catch(() => ({}));
      setResult(res.ok ? { ...keep, ...body } : { ...keep, refunded: false, decision: "error", message: body.error ?? `Request failed (${res.status}). No refund was issued.` });
    } catch {
      setResult({ ...keep, refunded: false, decision: "error", message: "Could not reach the refund service. No refund was issued." });
    } finally {
      setBusy(false);
    }
  }

  const submit = () => {
    previewSequence.current += 1;
    setPreviewBusy(false);
    setPreview(null);
    setPreviewError(null);
    setResult(null);
    return post("/api/refunds", { orderId, amount: amount.trim(), reason: reason.trim() });
  };
  // After a manager decides in AtlaSent: issues the refund if approved, exactly as it was requested.
  const checkApproval = () =>
    post("/api/refunds/resume", { approvalRequestId: result.approvalRequestId }, { approvalRequestId: result.approvalRequestId });
  const waiting =
    result && !result.refunded && result.approvalRequestId && ["escalate", "hold", "error"].includes(result.decision);

  const tone = !result ? undefined : result.refunded ? "success" : result.decision === "escalate" ? "warning" : "critical";

  return (
    <AdminAction
      title="Refund via AtlaSent"
      primaryAction={
        waiting ? (
          <Button onPress={checkApproval} disabled={busy}>
            {busy ? "Checking…" : "Check approval"}
          </Button>
        ) : (
          <Button onPress={submit} disabled={!valid || busy || previewBusy || result?.refunded}>
            {busy ? "Checking…" : "Request refund"}
          </Button>
        )
      }
      secondaryAction={<Button onPress={close}>Close</Button>}
    >
      <BlockStack gap>
        <Text>
          Start with a read-only operational preview. It checks the connected order and prepares an operator next step;
          it does not determine eligibility, authorize or issue a refund, or notify a customer.
        </Text>
        <TextField label="Amount (USD)" value={amount} onChange={changeAmount} disabled={busy || result?.refunded || waiting} />
        <Button onPress={loadPreview} disabled={!orderId || !valid || busy || previewBusy || waiting || result?.refunded}>
          {previewBusy ? "Reading order…" : "Preview next step (read only)"}
        </Button>
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
        <Text>
          The separate "Request refund" action below is the existing write-capable demo gate, not a result of this preview.
          It may issue a refund only when the independently configured runtime and Shopify permissions allow it.
        </Text>
        <TextField label="Reason for demo refund request" value={reason} onChange={setReason} disabled={busy || result?.refunded || waiting} />
        {result && (
          <Banner tone={tone} title={result.message}>
            {result.denyCode && <Text>Code: {result.denyCode}</Text>}
            {result.gateRef && <Text>Reference: {result.gateRef}</Text>}
          </Banner>
        )}
      </BlockStack>
    </AdminAction>
  );
}
