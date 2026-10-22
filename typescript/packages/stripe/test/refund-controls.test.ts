import { describe, expect, it } from "vitest";
import { deriveStripeRefundFacts, staticDeliveryFacts } from "../src/facts.js";
import { guardedStripeRefund } from "../src/guard.js";
import { InMemoryLedger } from "../src/ledger.js";
import { createStripeClient, type StripeRefund } from "../src/stripe.js";
import { delivered, FakeStripe, fakeRuntime, makePaymentIntent, NOW } from "./fakes.js";

const existing = (status = "pending"): StripeRefund => ({
  id: "re_existing", payment_intent: "pi_1", charge: "ch_1", amount: 100,
  currency: "usd", status, metadata: {},
});
function setup() {
  const stripe = new FakeStripe([makePaymentIntent({id:"pi_1",captured:10000,orderRef:"o1"})]);
  const runtime = fakeRuntime();
  const options = {actor:"agent:test", environment:"test",account:"acct_test",ledger:new InMemoryLedger(),delivery:staticDeliveryFacts({o1:delivered(1)}),now:()=>NOW};
  return {stripe,runtime,options,run:()=>guardedStripeRefund(stripe,runtime.client,{paymentIntentId:"pi_1",amountCents:4000},options)};
}
describe("refund payment evidence safety", () => {
  it.each(["succeeded", "pending", "requires_action"])("reports provider completion separately: %s", async status => {
    const s=setup();s.stripe.refundStatus=status;
    expect(await s.run()).toMatchObject({refunded:true,completion:status});
  });
  it("does not certify a mismatched provider response", async () => {
    const s=setup();const original=s.stripe.createRefund.bind(s.stripe);
    s.stripe.createRefund=async (input,key)=>({...await original(input,key),amount:1});
    const result=await s.run();
    expect(result.refunded).toBe(false);
    expect(result.refunded ? '' : result.reason).toContain("reconcile before retrying");
  });
  it.each(["pending", "requires_action", "unrecognized"])("blocks an existing %s refund before evaluation", async status => {
    const s=setup();s.stripe.existingRefunds=[existing(status)];
    expect((await s.run()).refunded).toBe(false);
    expect(s.runtime.evaluateBodies).toHaveLength(0);
    expect(s.stripe.refunds).toHaveLength(0);
  });
  it.each(["failed","canceled","succeeded"])("accepts a terminal %s history entry for further evaluation", async status => {
    const s=setup();s.stripe.existingRefunds=[existing(status)];
    if (status === "succeeded") s.stripe.pis.get("pi_1")!.latest_charge!.amount_refunded = 100;
    expect((await s.run()).refunded).toBe(true);
  });
  it("blocks a stale charge balance inconsistent with completed refunds", async () => {
    const s=setup();s.stripe.existingRefunds=[existing("succeeded")];
    expect((await s.run()).refunded).toBe(false);
    expect(s.stripe.refunds).toHaveLength(0);
  });
  it("rechecks pending history after approval", async () => {
    const s=setup(); let reads=0;
    s.stripe.listRefunds=async()=>++reads===1?[]:[existing()];
    expect((await s.run()).refunded).toBe(false);
    expect(s.stripe.refunds).toHaveLength(0);
  });
  it("blocks unreadable history", async () => {
    const s=setup();s.stripe.listRefunds=async()=>{throw new Error("unavailable")};
    expect((await s.run()).refunded).toBe(false);
    expect(s.stripe.refunds).toHaveLength(0);
  });
  it("blocks a mismatched history charge", async () => {
    const s=setup();s.stripe.existingRefunds=[{...existing("succeeded"),charge:"ch_other"}];
    expect((await s.run()).refunded).toBe(false);
  });
  it("blocks changed currency at the final read", async () => {
    const s=setup();
    s.stripe.onRead=(n,f)=>{if(n===1){f.pis.get("pi_1")!.currency="eur";f.pis.get("pi_1")!.latest_charge!.currency="eur";}};
    expect((await s.run()).refunded).toBe(false);
    expect(s.stripe.refunds).toHaveLength(0);
  });
  it("blocks a provider response for another payment", async () => {
    const s=setup();s.stripe.getPaymentIntent=async()=>makePaymentIntent({id:"pi_other",captured:10000});
    expect((await s.run()).refunded).toBe(false);
  });
  it("refuses missing dispute data and malformed financial amounts", () => {
    for (const patch of [
      {disputed:undefined},{disputed:"false"},{amount_captured:NaN},{amount_refunded:undefined},
      {amount_captured:1.5},{amount_refunded:-1},{amount_refunded:101},{currency:"eur"},
    ]) {
      const pi=makePaymentIntent({id:"pi_1",captured:100});
      Object.assign(pi.latest_charge!,patch);
      expect(()=>deriveStripeRefundFacts(pi,delivered(1),"o1",NOW)).toThrow();
    }
  });
});
describe("complete refund history", () => {
  it("follows pagination, including a pending refund beyond the first page", async () => {
    const urls:string[]=[];
    const pages=[{data:[existing("succeeded")],has_more:true},{data:[{...existing(),id:"re_second"}],has_more:false}];
    const client=createStripeClient({secretKey:"rk_test_fake",fetch:async input=>{
      urls.push(String(input));return new Response(JSON.stringify(pages.shift()),{status:200});
    }});
    expect(await client.listRefunds("pi_1")).toHaveLength(2);
    expect(urls[1]).toContain("starting_after=re_existing");
  });
  it.each([
    {data:[],has_more:true}, {data:[]}, {data:null,has_more:false},
    {data:[existing(),existing()],has_more:false},
  ])("refuses incomplete or repeated pagination", async body => {
    const client=createStripeClient({secretKey:"rk_test_fake",fetch:async()=>new Response(JSON.stringify(body),{status:200})});
    await expect(client.listRefunds("pi_1")).rejects.toThrow();
  });
});
