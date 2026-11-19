# @revokegpt/node

The RevokeGPT server SDK for Node.js 26 or later. It sends a response token to siteverify and applies every
relying-party check of protocol v1 section 7: `success` must be the boolean `true`, the hostname must match
exactly, the action must match exactly, and a score must meet your threshold.

## Usage

```js
import { createClient } from '@revokegpt/node';

// Create the client once. The secret is checked here (a typo throws `TypeError('invalid secret key')`,
// which never includes the key) and is then held privately: logging or serializing the client never shows it.
const revokegpt = createClient({
  secret: process.env.REVOKEGPT_SECRET, // rgsk_...
  endpoint: 'https://<api host>/v1/siteverify', // the full siteverify URL
});

// In the signup handler (`token` is the widget's response field; `clientIp` is the end user's address):
const outcome = await revokegpt.verify(token, {
  expectedHostname: 'shop.example', // the hostname your page is served from, lowercase
  expectedAction: 'signup', // the action your page passed to the widget
  minScore: 0.5, // required: every verified result carries a score
  remoteip: clientIp, // optional: the end user's IP address (see below)
});
if (!outcome.ok) return reject(outcome.reason); // `reason` exists only when `ok` is false
```

Gate on `outcome.ok` alone. The outcome is `{ ok: true, result }` or `{ ok: false, reason, result }`; in
TypeScript, `reason` is available after checking `ok`. `outcome.result` is the parsed siteverify result (`score`,
`action`, `hostname`, `errorCodes`, `reasons`, ...), for logging.

The SDK form-encodes the request body (`URLSearchParams`). If you call siteverify yourself, never build the body
by concatenation or templating (`"secret=" + secret + "&response=" + token`): an unencoded value injects fields.
The secret is sent only in the POST body, never in the URL or a header.

### Options

`createClient({ secret, endpoint, timeoutMs?, fetch? })`

- `secret`: your site's secret key (`rgsk_...`). A management key (`rgmk_...`) is refused.
- `endpoint`: the full siteverify URL. It must be `https:`, or `http:` only on `localhost` or `127.0.0.1` (local
  development), with no username, password, query or fragment. There is no default.
- `timeoutMs`: an integer from 1 to 60000; default 5000.
- `fetch`: a `fetch` implementation; default the global `fetch`. It must be WHATWG-compatible: its response
  `body` must be a web `ReadableStream` (Node's built-in `fetch` and undici are). A node-fetch v2 style
  implementation, whose body is a Node stream, is not supported: every verification fails closed as
  `network-error`.

`verify(token, { expectedHostname | expectedApp, expectedAction?, minScore?, remoteip?, sitekey? })`

- Give exactly one of `expectedHostname` and `expectedApp`. Both, or neither, is `invalid-expectation`.
- `expectedHostname` is compared exactly with the token's hostname, so it must be canonical
  (lowercase, no trailing dot, no port). For web tokens.
- `expectedApp` (`{ platform: 'android' | 'ios', id }`) is compared exactly with the app the token was issued
  to. For mobile app tokens; see [Mobile apps](#mobile-apps).
- `expectedAction`: leave it out only if you use no actions; then a token that carries an action is refused.
- `minScore`: a number in [0, 1]. A result with a score is refused without one, and a result without a score is
  refused with one. **Every verified RevokeGPT result carries a score** (from M2, in both `invisible` and `score`
  mode), so always pass `minScore`: without it every verification fails with `threshold-missing`. The edge issues a
  token whatever the score, and this threshold is what refuses a low one. Scores are in steps of 0.1; 0.5 is a
  sensible start.
- `remoteip`: the end user's IPv4 or IPv6 address. Behind a proxy or load balancer, pass the client IP from your
  trusted proxy's header (for example the address your proxy appends to `X-Forwarded-For`), not
  `req.socket.remoteAddress`, which is then the proxy's address. An address with a zone id, such as
  `fe80::1%eth0`, is invalid: omit `remoteip` then.
- `sitekey`: the site key the token must belong to.
- `remoteip` and `sitekey` are sent only when given and not the empty string. A value that is given is checked
  before sending (`invalid-options`).

`verify` never throws or rejects. Redirects are not followed, and at most 64 KiB of response is read.

### Mobile apps

A token minted by the RevokeGPT Android or iOS SDK carries the app instead of a hostname. Verify it with
`expectedApp`:

```ts
const outcome = await rg.verify(token, {
  expectedApp: { platform: 'android', id: 'com.example.app' }, // the applicationId
  expectedAction: 'login',
  minScore: 0.6, // above 0.5: an app token with no attestation evidence scores at most 0.5
});
// iOS: { platform: 'ios', id: 'com.example.App' }, the bare bundle id (no Team ID)
if (!outcome.ok) return deny(); // gate on outcome.ok alone
```

On Android `id` is the package name (`apk_package_name` in the siteverify result); on iOS it is the bundle id
(`ios_bundle_id`). A web token never matches an app expectation, nor a hostname expectation an app token, and
an Android token never matches an iOS expectation: each is `app-mismatch` or `hostname-mismatch`.

Choose `minScore` 0.6 or higher for app tokens. 0.5 is the cap for an app token with no attestation evidence: a
Simulator or emulator, a device without Google Play, a Google outage, or any script that simply claims one of
these. It is not the same footing as the web, where a client that sends no signals scores about 0.2: treat 0.5 on
an app token as "no evidence".

Never choose between the hostname and the app expectation from anything the client controls (a header, a body
field, the user agent, the token itself): a bot would pick the weaker check. Use one endpoint per platform (web,
Android, iOS), or decide from what your server already knows about the request, such as the route it came in on.

### Reasons

When `ok` is false, `reason` says why:

- `invalid-expectation`: the expectation is invalid (no options object, both or neither of `expectedHostname`
  and `expectedApp`, a non-canonical `expectedHostname`, an `expectedApp` that is not a well-formed
  `{ platform, id }`, a non-string `expectedAction`, or `minScore` not a number in [0, 1]). Nothing was sent.
  Fix your code.
- `invalid-options`: a given `remoteip` or `sitekey` is invalid (not a string, not an IP address, or not a site
  key). Nothing was sent. Fix your code.
- `invalid-token-format`: the token is not 1 to 2048 characters of `A-Z a-z 0-9 - _`. Nothing was sent.
- `network-error`: the request failed or timed out.
- `http-error`: siteverify answered with a status other than 200 (redirects included), or a body over 64 KiB.
- `not-verified`: siteverify did not verify the token (an invalid, expired or already used token), or its body
  was malformed. `result.errorCodes` says why, for example `timeout-or-duplicate`.
- `hostname-mismatch`: the token was issued for another hostname.
- `app-mismatch`: the token was issued to another app, or to a web page or the other platform.
- `action-mismatch`: the token was issued for another action, or carries an action when you expect none.
- `score-missing`: you set `minScore`, and the result has no score.
- `threshold-missing`: the result has a score, and you set no `minScore`.
- `score-below-threshold`: the score is below `minScore`.
- `score-invalid`: the result's score is not a number in [0, 1] (not reachable from a parsed body).

If more than one of the first three applies, the first in this order wins: `invalid-expectation`,
`invalid-options`, `invalid-token-format`.

Treat every reason as "do not accept". A token is single use, and after `network-error` or `http-error` it may
already have been spent, so a retry needs a new token from the widget.

## Assessments

`createAssessment` and `annotate` call the assessment endpoints (protocol v1 section 14). They are off for a site
until its flags are set, and they derive their URL from `endpoint` (`.../v1/siteverify` becomes
`.../v1/assessments`), so `endpoint` must end in `/siteverify`. Both send `Authorization: Bearer <secret>` (the
secret is never in a URL or body) and, unlike `verify`, **throw** a `RevokeGPTError` on failure.

```ts
const rg = createClient({
  secret: process.env.REVOKEGPT_SECRET,
  endpoint: 'https://<api host>/v1/siteverify',
});

const a = await rg.createAssessment({ token, expectedAction: 'login' });
if (a.tokenProperties.valid && a.riskAnalysis.score >= 0.5) allow();
// a.name is `assessments/<aid>`; keep it to annotate later.

await rg.annotate(a.name, { annotation: 'FRAUDULENT', reasons: ['CHARGEBACK'] }); // or pass the bare aid
```

- `createAssessment({ token?, expectedAction?, express?, userIpAddress?, userAgent?, headers?, userInfo?, accountVerification? })`
  returns the assessment. A token assessment spends the token (one verification, by this or siteverify). An invalid
  token is still a 200 with `tokenProperties.valid: false`, an `invalidReason` and score 0: check `valid`.
- Express (`express: true`, no token) scores the IP address alone: `userIpAddress` must be the real end-user
  address. Behind a proxy (for example Express), do not pass `req.socket.remoteAddress`, which is the proxy's:
  set `app.set('trust proxy', ...)` for your proxy and pass `req.ip`.
- `annotate(aidOrName, { annotation?, reasons? })` resolves with nothing on success. The aid (42 characters of
  `A-Za-z0-9_-`) is checked locally. Annotate with ground truth you learn later (a chargeback, a confirmed
  fraudulent signup, a legitimate purchase), not guesses: these labels train the model. A different label
  replaces the earlier one; an assessment older than 30 days is `expired`.
- `RevokeGPTError` has `code` (`unauthorized`, `feature-disabled`, `not-found`, `expired`, `rate-limited`,
  `payload-too-large`, `unsupported-media-type`, `service-unavailable`, ..., or `network-error` for a timeout or
  failed request, `invalid-response` for a body that is not a valid assessment), `status` (0 when no response),
  `requestId`, and `retryAfterSeconds` for a 429.

## Account protection, MFA and erase

Protocol v1 sections 15 and 17. Each is off for a site until its flag is set (a closed flag is a `403
feature-disabled`). Every call throws `RevokeGPTError`; a 503 throws its subclass `RevokeGPTUnavailable`.

```ts
const a = await rg.createAssessment({
  token,
  userInfo: { accountId: user.id, createAccountTime: user.createdAt },
  accountVerification: { endpoints: [{ emailAddress: user.email }], languageCode: 'en' },
});
a.accountDefenderAssessment?.labels; // open enum: tolerate unknown labels
if (a.requiresMfa) {
  const [first] = a.accountVerification?.endpoints ?? [];
  // hand first.requestToken to the widget's challengeAccount; it returns a token for the next assessment
}

await rg.annotate(a.name, { annotation: 'LEGITIMATE', accountId: user.id });
await rg.eraseAccount({ accountId: user.id }); // or { hashedAccountId }
```

- `userInfo` takes `accountId` (1 to 256 UTF-8 bytes) or `hashedAccountId` (base64 of 32 bytes), never both, plus an
  optional `createAccountTime`. The service hashes it per site; send the same form everywhere (assess, annotate,
  erase), because the two forms are different accounts. Without account protection or MFA on for the site, `userInfo` is accepted and ignored.
- `accountVerification` needs a named account in `userInfo`. A `phoneNumber` endpoint passes the types but SMS is not
  supported yet: the service answers 403 and sends nothing.
- Treat the verification result `ERROR_RECIPIENT_ABUSE_LIMIT_EXHAUSTED` (too many codes to that mailbox, possibly from others) as "offer another verification path", never as a lock-out. `eraseAccount` needs only the secret: no flag, and no switch-off stops it.

## Payments and SMS

Score a payment before you charge it and an SMS before you send it (protocol v1 sections 20 and 21; both need
the site's flags on). Payments take only the card's BIN (first 6 or 8 digits) and last four: build them with
`cardFields`, which throws `RevokeGPTError('bad-request', 0)` (status 0: no request was made) for anything else, so a
card number never leaves your server. Every string of `transactionData` is also scanned for a card number
before sending.

```js
const a = await revokegpt.createAssessment({
  token,
  fraudPrevention: 'ENABLED',
  transactionData: {
    ...cardFields({ bin: '424242', last4: '4242' }),
    currencyCode: 'USD',
    value: 59.9,
  },
  userInfo: { userIds: [{ phoneNumber: '+447700900123' }] }, // scored for SMS toll fraud
});
a.fraudPreventionAssessment?.transactionRisk; // 0 to 1; 0.5 with `unscored: true` when it could not be scored
a.phoneFraudAssessment?.smsTollFraudVerdict.risk;
// After the gateway answers, teach the scorer with the gateway's own code:
await revokegpt.annotate(a.name, {
  reasons: ['TRANSACTION_DECLINED'],
  transactionEvent: { eventType: 'AUTHORIZATION_DECLINE', reason: gatewayCode },
});
```

Suggested thresholds: block at risk 0.7 or more, step up at 0.4 or more; nothing is enforced for you. Examples
(local minimal types, no gateway SDK needed; they compile under `tsconfig.examples.json`):

- [examples/payments/stripe.ts](examples/payments/stripe.ts): assess, charge, annotate accepted or declined, annotate a chargeback.
- [examples/payments/adyen.ts](examples/payments/adyen.ts): the same with `additionalData.cardBin` and `cardSummary`.
- [examples/payments/braintree.ts](examples/payments/braintree.ts): the same with `creditCard.bin` and `last4`.
- [examples/sms/before-send.ts](examples/sms/before-send.ts): gate an SMS on `smsTollFraudVerdict` (`risk < 0.4`; unscored means do not send). RevokeGPT never sends the SMS.

## License

MIT

## Other languages

The same checks, the same shared vectors and the same behaviour exist for these servers. They are built and tested in
the source repository and are not published to their registries yet, so install them from source until the first
release (each README has the steps):

- [Python](../python/README.md) (3.9 or later) and its [firewall](../integrations/python/README.md)
- [PHP](../php/README.md) (8.1 or later) and the [Laravel firewall](../integrations/php/README.md)
- [Go](../go/README.md) (1.26 or later) and the [firewall](../integrations/go/README.md)
- [Java](../java/README.md) (11 or later) and the [Spring firewall](../integrations/java/README.md)
- [WordPress plugin](../wordpress/README.md)
