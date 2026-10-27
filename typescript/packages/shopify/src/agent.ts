/**
 * A Claude support agent for the demo store whose only way to move money is
 * the gated refund. The model can ask for a refund; AtlaSent decides.
 *
 * Two controls sit outside the model:
 *   - `issue_refund` calls `deps.refund`, which is guardedShopifyRefund. The
 *     agent has no other tool that touches payments.
 *   - Both tools check the order belongs to `customerEmail`, the customer the
 *     store's own login authenticated. A chat message cannot change it, so a
 *     customer cannot refund someone else's order by typing its number.
 *
 * Manual tool loop, bounded by `maxTurns`.
 */

import type Anthropic from "@anthropic-ai/sdk";
import type { ShopifyOrder } from "./admin.js";
import { centsToMoney, deriveRefundFacts, moneyToCents } from "./facts.js";
import type { RefundRequest, RefundResult } from "./guard.js";
import { describeResult } from "./describe.js";

export const SUPPORT_AGENT_MODEL = "claude-opus-5-5";

type MessageParam = Anthropic.Beta.BetaMessageParam;
type ToolResult = Anthropic.Beta.BetaToolResultBlockParam;

export interface SupportAgentDeps {
  anthropic: Pick<Anthropic, "beta">;
  /** Authenticated by the store, never taken from the conversation. */
  customerEmail: string;
  /** Stable support operation ID supplied by the host, never by model tool arguments. */
  businessRequestId?: string;
  /** Must return the order WITH its email (`getOrder(id, { includeEmail: true })`); without one, every order is refused. */
  lookupOrder: (orderId: string) => Promise<ShopifyOrder | null>;
  /** guardedShopifyRefund bound to this agent's actor, ledger and shop. */
  refund: (request: RefundRequest) => Promise<RefundResult>;
  now?: () => Date;
  model?: string;
  maxTurns?: number;
}

export interface SupportAgentTurn {
  reply: string;
  /** Full history including this turn; pass it back for the next message. */
  messages: MessageParam[];
  refunds: RefundResult[];
}

const SYSTEM = `You are the customer support assistant for Pinecone Pet Supply, an online pet store.

You can look up the customer's orders and request refunds. Refunds are approved or declined by the store's authorization system, not by you. When you request one, tell the customer exactly what the issue_refund result says: refunded, sent to a manager for review, or declined and why. Never say a refund has been issued unless the result says refunded: true.

Store refund policy, for explaining decisions: refunds under $50 are issued automatically when the order has been delivered and it is within 30 days of delivery. Larger refunds go to a manager. Ask for the order number and what went wrong if the customer has not said. Keep replies short and friendly.`;

const TOOLS: Anthropic.Beta.BetaTool[] = [
  {
    name: "lookup_order",
    description: "Look up one of the signed-in customer's orders: delivery status, days since delivery, and how much can still be refunded.",
    strict: true,
    input_schema: {
      type: "object",
      properties: { order_id: { type: "string", description: "Shopify order id, numeric or gid://shopify/Order/<id>" } },
      required: ["order_id"],
      additionalProperties: false,
    },
  },
  {
    name: "issue_refund",
    description:
      "Request a refund on one of the signed-in customer's orders. The store's authorization system decides; the result says whether it was refunded, sent to a manager, or declined.",
    strict: true,
    input_schema: {
      type: "object",
      properties: {
        order_id: { type: "string", description: "Shopify order id" },
        amount: { type: "string", description: "Refund amount in USD, e.g. \"18.99\"" },
        reason: { type: "string", description: "Short reason, recorded on the refund" },
      },
      required: ["order_id", "amount", "reason"],
      additionalProperties: false,
    },
  },
];

const sameEmail = (a: string | null | undefined, b: string) =>
  typeof a === "string" && a.trim().length > 0 && a.trim().toLowerCase() === b.trim().toLowerCase();

/** Runs one tool. Exported for tests. */
export async function runSupportTool(
  name: string,
  input: unknown,
  deps: SupportAgentDeps,
  refunds: RefundResult[],
): Promise<{ content: string; isError: boolean }> {
  const args = (input ?? {}) as Record<string, unknown>;
  const orderId = args.order_id;
  if (typeof orderId !== "string" || orderId.length === 0) return { content: "order_id is required", isError: true };

  // Same answer for "no such order" and "someone else's order".
  const order = await deps.lookupOrder(orderId);
  if (order === null || !sameEmail(order.email, deps.customerEmail)) {
    return { content: "No order with that number was found for this customer.", isError: true };
  }

  if (name === "lookup_order") {
    const f = deriveRefundFacts(order, (deps.now ?? (() => new Date()))());
    return {
      content: JSON.stringify({
        order: f.order_name,
        status: f.order_status,
        ...(f.days_since_delivery !== undefined ? { days_since_delivery: f.days_since_delivery } : {}),
        refundable: `$${centsToMoney(f.refundable_cents)}`,
      }),
      isError: false,
    };
  }

  if (name === "issue_refund") {
    if (typeof deps.businessRequestId !== "string" || !/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(deps.businessRequestId)) {
      return { content: "A stable support case operation ID is required before requesting a refund.", isError: true };
    }
    if (typeof args.amount !== "string") return { content: "amount is required, e.g. \"18.99\"", isError: true };
    let amountCents: number;
    try {
      amountCents = moneyToCents(args.amount);
    } catch {
      return { content: "amount must look like 18.99", isError: true };
    }
    const reason = typeof args.reason === "string" ? args.reason.slice(0, 200) : "";
    const result = await deps.refund({ orderId: order.id, amountCents, businessRequestId: deps.businessRequestId, ...(reason ? { reason } : {}) });
    refunds.push(result);
    return { content: JSON.stringify(describeResult(result)), isError: false };
  }

  return { content: `unknown tool ${name}`, isError: true };
}

function textOf(content: Anthropic.Beta.BetaContentBlock[]): string {
  return content
    .filter((b): b is Anthropic.Beta.BetaTextBlock => b.type === "text")
    .map((b) => b.text)
    .join("\n")
    .trim();
}

/** Answers the latest user message in `history`. */
export async function runSupportAgent(deps: SupportAgentDeps, history: MessageParam[]): Promise<SupportAgentTurn> {
  const messages: MessageParam[] = [...history];
  const refunds: RefundResult[] = [];
  const maxTurns = deps.maxTurns ?? 8;

  for (let turn = 0; turn < maxTurns; turn++) {
    const response = await deps.anthropic.beta.messages.create({
      model: deps.model ?? SUPPORT_AGENT_MODEL,
      max_tokens: 16000,
      // On a safety decline, the API re-runs the request on a fallback model.
      betas: ["server-side-fallback-2026-07-01"],
      fallbacks: "default",
      output_config: { effort: "medium" },
      system: SYSTEM,
      tools: TOOLS,
      messages,
    });

    if (response.stop_reason === "refusal") {
      return { reply: "Sorry, I can't help with that here. A member of our team will follow up.", messages, refunds };
    }
    messages.push({ role: "assistant", content: response.content });

    if (response.stop_reason === "tool_use") {
      const results: ToolResult[] = [];
      for (const block of response.content) {
        if (block.type !== "tool_use") continue;
        let out: { content: string; isError: boolean };
        try {
          out = await runSupportTool(block.name, block.input, deps, refunds);
        } catch (err) {
          out = { content: `tool failed: ${err instanceof Error ? err.message : String(err)}`, isError: true };
        }
        results.push({ type: "tool_result", tool_use_id: block.id, content: out.content, ...(out.isError ? { is_error: true } : {}) });
      }
      messages.push({ role: "user", content: results });
      continue;
    }
    if (response.stop_reason === "pause_turn") continue;

    return { reply: textOf(response.content), messages, refunds };
  }

  return { reply: "Sorry, I couldn't finish that. A member of our team will follow up.", messages, refunds };
}

