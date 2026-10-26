// Read-only order preview on the order details page. No refund or resume action.
// React admin UI extension API (api_version 2025-07).

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

export default reactExtension(TARGET, () => <OrderPreview />);

function OrderPreview() {
  const { close, data, auth } = useApi(TARGET);
  const orderId = data.selected[0]?.id;
  const [amount, setAmount] = useState("");
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

  return (
    <AdminAction
      title="AtlaSent order preview"
      primaryAction={
        <Button onPress={loadPreview} disabled={!orderId || !valid || previewBusy}>
          {previewBusy ? "Reading order…" : "Preview next step (read only)"}
        </Button>
      }
      secondaryAction={<Button onPress={close}>Close</Button>}
    >
      <BlockStack gap>
        <Text>
          Read the connected order and prepare an operator next step. This preview does not determine
          eligibility, authorize or issue a refund, or notify a customer.
        </Text>
        <TextField label="Amount (USD)" value={amount} onChange={changeAmount} />
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
