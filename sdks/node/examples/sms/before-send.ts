// Gate an SMS on the SMS toll-fraud verdict. RevokeGPT never sends the message; you do. Fictitious
// numbers only (Ofcom drama range).
import type { Client } from '@revokegpt/node';

/** Send only below this risk. Unscored (every risk 0.5) is not a pass. */
const SEND_BELOW = 0.4;

type SmsSender = { send(to: string, body: string): Promise<void> };

export async function sendCodeIfSafe(
  revokegpt: Client,
  sms: SmsSender,
  input: { token: string; phoneNumber: string; code: string },
): Promise<'sent' | 'withheld'> {
  const a = await revokegpt.createAssessment({
    token: input.token,
    expectedAction: 'send_sms',
    fraudPrevention: 'ENABLED',
    userInfo: { userIds: [{ phoneNumber: input.phoneNumber }] },
  });
  const verdict = a.phoneFraudAssessment?.smsTollFraudVerdict;
  // No verdict, or an unscored one: do not send.
  if (verdict === undefined || verdict.unscored === true || verdict.risk >= SEND_BELOW)
    return 'withheld';
  await sms.send(input.phoneNumber, `Your code is ${input.code}`);
  return 'sent';
}

// Example call: sendCodeIfSafe(revokegpt, sms, { token, phoneNumber: '+447700900123', code: '123456' });
