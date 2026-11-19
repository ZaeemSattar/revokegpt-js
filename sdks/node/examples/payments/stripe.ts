// Screen a card payment with RevokeGPT around a Stripe-style charge. Local minimal types: no gateway
// SDK dependency. Test card data only (4242...).
//
// Stripe: `card.last4` is on the PaymentMethod's card hash. The PaymentMethod card hash has no
// IIN/BIN field (it has brand, country, funding, fingerprint, last4, ...), so this example sends the
// last four only and the service scores what it has. If your own card form exposes the BIN, pass it
// as `bin`. Verified 2026-11-15 against https://docs.stripe.com/api/payment_methods/object
// (`card.last4`; no BIN field). The decline code goes in `transactionEvent.reason`.
import { type Client, cardFields, RevokeGPTError } from '@revokegpt/node';

type PaymentMethod = { card?: { last4?: string; iin?: string } };
type ChargeResult = { ok: true } | { ok: false; declineCode: string };
type Gateway = {
  retrievePaymentMethod(id: string): Promise<PaymentMethod>;
  charge(input: {
    paymentMethodId: string;
    amount: number;
    currency: string;
  }): Promise<ChargeResult>;
};
type Order = {
  id: string;
  amount: number;
  currency: string;
  paymentMethodId: string;
  token: string;
};

/** Block at or above this risk; step up (ask for more proof) at or above `STEP_UP`. */
const BLOCK = 0.7;
const STEP_UP = 0.4;

export async function chargeWithScreening(
  revokegpt: Client,
  gateway: Gateway,
  order: Order,
): Promise<'paid' | 'declined' | 'blocked' | 'step-up'> {
  const pm = await gateway.retrievePaymentMethod(order.paymentMethodId);
  // 1. Assess before the charge. cardFields refuses anything that is not a BIN and a last four.
  const assessment = await revokegpt.createAssessment({
    token: order.token,
    expectedAction: 'checkout',
    fraudPrevention: 'ENABLED',
    transactionData: {
      transactionId: order.id,
      paymentMethod: 'credit-card',
      ...cardFields({
        ...(pm.card?.iin !== undefined ? { bin: pm.card.iin } : {}),
        ...(pm.card?.last4 !== undefined ? { last4: pm.card.last4 } : {}),
      }),
      currencyCode: order.currency,
      value: order.amount,
    },
  });
  const risk = assessment.fraudPreventionAssessment?.transactionRisk ?? 0.5; // unscored: step up
  if (risk >= BLOCK) return 'blocked';
  if (risk >= STEP_UP) return 'step-up';

  // 2. Charge, then tell RevokeGPT what the gateway answered, with the gateway's own code.
  const result = await gateway.charge({
    paymentMethodId: order.paymentMethodId,
    amount: order.amount,
    currency: order.currency,
  });
  await annotateQuietly(revokegpt, assessment.name, {
    reasons: [result.ok ? 'TRANSACTION_ACCEPTED' : 'TRANSACTION_DECLINED'],
    transactionEvent: result.ok
      ? { eventType: 'AUTHORIZATION' }
      : { eventType: 'AUTHORIZATION_DECLINE', reason: result.declineCode },
  });
  return result.ok ? 'paid' : 'declined';
}

/** On a chargeback webhook for a payment you screened (within 30 days of the assessment). */
export async function onChargebackFraud(revokegpt: Client, assessmentName: string): Promise<void> {
  await revokegpt.annotate(assessmentName, {
    annotation: 'FRAUDULENT',
    reasons: ['CHARGEBACK_FRAUD'],
    transactionEvent: { eventType: 'CHARGEBACK' },
  });
}

/** An annotation failure must never fail the payment. */
async function annotateQuietly(
  revokegpt: Client,
  name: string,
  input: Parameters<Client['annotate']>[1],
): Promise<void> {
  try {
    await revokegpt.annotate(name, input);
  } catch (e) {
    if (!(e instanceof RevokeGPTError)) throw e;
  }
}
