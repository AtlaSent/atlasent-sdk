// "Refund via AtlaSent": an admin action on the order details page.
//
// The button collects an amount and a reason and sends them to the app
// backend (../../../../src/server.ts, POST /api/refunds) with the staff
// member's session token. The backend runs the AtlaSent gate; this UI only
// shows what came back. It never calls Shopify's refund API itself.
//
// Written against the React admin UI extension API (api_version 2025-07).
// Newer API versions use Preact and web components; port before upgrading.

import { useState } from "react";
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

  const valid = /^\d+(\.\d{1,2})?$/.test(amount.trim()) && Number(amount) > 0;

  async function submit() {
    setBusy(true);
    setResult(null);
    try {
      const token = await auth.idToken();
      // Relative URL: resolves against the app's application_url.
      const res = await fetch("/api/refunds", {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
        body: JSON.stringify({ orderId, amount: amount.trim(), reason: reason.trim() }),
      });
      const body = await res.json().catch(() => ({}));
      setResult(res.ok ? body : { refunded: false, message: body.error ?? `Request failed (${res.status}). No refund was issued.` });
    } catch {
      setResult({ refunded: false, message: "Could not reach the refund service. No refund was issued." });
    } finally {
      setBusy(false);
    }
  }

  const tone = !result ? undefined : result.refunded ? "success" : result.decision === "escalate" ? "warning" : "critical";

  return (
    <AdminAction
      title="Refund via AtlaSent"
      primaryAction={
        <Button onPress={submit} disabled={!valid || busy || result?.refunded}>
          {busy ? "Checking…" : "Request refund"}
        </Button>
      }
      secondaryAction={<Button onPress={close}>Close</Button>}
    >
      <BlockStack gap>
        <Text>
          Refunds under $50 on delivered orders, within 30 days of delivery, are issued straight away. Larger refunds go
          to a manager.
        </Text>
        <TextField label="Amount (USD)" value={amount} onChange={setAmount} disabled={busy || result?.refunded} />
        <TextField label="Reason" value={reason} onChange={setReason} disabled={busy || result?.refunded} />
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
