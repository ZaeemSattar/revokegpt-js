// Screen a card payment with RevokeGPT around a Braintree-style sale. Local minimal types. Test
// card data only (4242...).
//
// Braintree: a credit card has `bin` (first 6 digits) and `last_4` (`last4` in the SDKs); a
// declined transaction has `processor_response_code`. Verified 2026-11-15 against
// https://developer.paypal.com/braintree/docs/reference/response/credit-card and
// https://developer.paypal.com/braintree/docs/reference/response/transaction/ (the snake_case names
// are the API's; the Node SDK uses camelCase).
import { type Client, cardFields, RevokeGPTError } from '@revokegpt/node';

type CreditCard = { bin?: string; last4?: string };
type SaleResult = { success: boolean; processorResponseCode?: string };
type Braintree = {
  findPaymentMethod(token: string): Promise<{ creditCard: CreditCard }>;
  sale(input: { paymentMethodToken: string; amount: number }): Promise<SaleResult>;
};
type Order = {
  id: string;
  amount: number;
  currency: string;
  paymentMethodToken: string;
  token: string;
};

export async function saleWithScreening(
  revokegpt: Client,
  gateway: Braintree,
  order: Order,
): Promise<'paid' | 'declined' | 'blocked' | 'step-up'> {
  const { creditCard } = await gateway.findPaymentMethod(order.paymentMethodToken);
  const assessment = await revokegpt.createAssessment({
    token: order.token,
    expectedAction: 'checkout',
    fraudPrevention: 'ENABLED',
    transactionData: {
      transactionId: order.id,
      paymentMethod: 'credit-card',
      ...cardFields({
        ...(creditCard.bin !== undefined ? { bin: creditCard.bin } : {}),
        ...(creditCard.last4 !== undefined ? { last4: creditCard.last4 } : {}),
      }),
      currencyCode: order.currency,
      value: order.amount,
    },
  });
  // Unscored answers 0.5, inside the step-up band.
  const risk = assessment.fraudPreventionAssessment?.transactionRisk ?? 0.5;
  if (risk >= 0.7) return 'blocked';
  if (risk >= 0.4) return 'step-up';

  const res = await gateway.sale({
    paymentMethodToken: order.paymentMethodToken,
    amount: order.amount,
  });
  try {
    await revokegpt.annotate(assessment.name, {
      reasons: [res.success ? 'TRANSACTION_ACCEPTED' : 'TRANSACTION_DECLINED'],
      transactionEvent: res.success
        ? { eventType: 'AUTHORIZATION' }
        : {
            eventType: 'AUTHORIZATION_DECLINE',
            ...(res.processorResponseCode !== undefined
              ? { reason: res.processorResponseCode }
              : {}),
          },
    });
  } catch (e) {
    if (!(e instanceof RevokeGPTError)) throw e;
  }
  return res.success ? 'paid' : 'declined';
}

/** On a dispute webhook for a payment you screened (within 30 days of the assessment). */
export async function onChargebackFraud(revokegpt: Client, assessmentName: string): Promise<void> {
  await revokegpt.annotate(assessmentName, {
    annotation: 'FRAUDULENT',
    reasons: ['CHARGEBACK_FRAUD'],
    transactionEvent: { eventType: 'CHARGEBACK' },
  });
}
