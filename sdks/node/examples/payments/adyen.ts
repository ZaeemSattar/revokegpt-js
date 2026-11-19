// Screen a card payment with RevokeGPT around an Adyen-style authorisation. Local minimal types.
// Test card data only (4242...).
//
// Adyen: the /payments response carries `additionalData.cardSummary` (last four) and, once you
// enable "Card bin details" under Developers > Additional data in the Customer Area,
// `additionalData.cardBin`; a refusal carries `refusalReason`. They arrive after authorisation, so
// for a first attempt take the BIN and last four from the card form's own non-sensitive fields (a
// tokenised field exposes them) and use these response fields when you annotate or retry.
// Verified 2026-11-15 against https://docs.adyen.com/api-explorer/Checkout/latest/post/payments and
// https://docs.adyen.com/payment-methods/cards/android-component/earlier-versions (cardSummary
// sample); cardBin format is not specified there, so cardFields validates it (6 or 8 digits).
import { type Client, cardFields, RevokeGPTError } from '@revokegpt/node';

type AdyenResponse = {
  resultCode: 'Authorised' | 'Refused' | 'Error' | (string & {});
  refusalReason?: string;
  additionalData?: { cardBin?: string; cardSummary?: string };
};
type Adyen = {
  authorise(input: { reference: string; amount: number; currency: string }): Promise<AdyenResponse>;
};
type Order = {
  id: string;
  amount: number;
  currency: string;
  token: string;
  /** From the card form's tokenised, non-sensitive fields. */
  bin: string;
  last4: string;
};

export async function authoriseWithScreening(
  revokegpt: Client,
  adyen: Adyen,
  order: Order,
): Promise<'authorised' | 'refused' | 'blocked' | 'step-up'> {
  const assessment = await revokegpt.createAssessment({
    token: order.token,
    expectedAction: 'checkout',
    fraudPrevention: 'ENABLED',
    transactionData: {
      transactionId: order.id,
      paymentMethod: 'credit-card',
      ...cardFields({ bin: order.bin, last4: order.last4 }),
      currencyCode: order.currency,
      value: order.amount,
    },
  });
  // Unscored answers 0.5, inside the step-up band.
  const risk = assessment.fraudPreventionAssessment?.transactionRisk ?? 0.5;
  if (risk >= 0.7) return 'blocked';
  if (risk >= 0.4) return 'step-up';

  const res = await adyen.authorise({
    reference: order.id,
    amount: order.amount,
    currency: order.currency,
  });
  const ok = res.resultCode === 'Authorised';
  try {
    await revokegpt.annotate(assessment.name, {
      reasons: [ok ? 'TRANSACTION_ACCEPTED' : 'TRANSACTION_DECLINED'],
      transactionEvent: ok
        ? { eventType: 'AUTHORIZATION' }
        : {
            eventType: 'AUTHORIZATION_DECLINE',
            ...(res.refusalReason !== undefined ? { reason: res.refusalReason } : {}),
          },
    });
  } catch (e) {
    if (!(e instanceof RevokeGPTError)) throw e;
  }
  return ok ? 'authorised' : 'refused';
}

/** Adyen's response fields, mapped to the card fields (for an annotation-time or retry check). */
export function adyenCardFields(res: AdyenResponse) {
  return cardFields({
    ...(res.additionalData?.cardBin !== undefined ? { bin: res.additionalData.cardBin } : {}),
    ...(res.additionalData?.cardSummary !== undefined
      ? { last4: res.additionalData.cardSummary }
      : {}),
  });
}

/** On a chargeback notification for a payment you screened (within 30 days of the assessment). */
export async function onChargebackFraud(revokegpt: Client, assessmentName: string): Promise<void> {
  await revokegpt.annotate(assessmentName, {
    annotation: 'FRAUDULENT',
    reasons: ['CHARGEBACK_FRAUD'],
    transactionEvent: { eventType: 'CHARGEBACK' },
  });
}
