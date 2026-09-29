// Runs the client side against a running server, as Natrium will: it blinds the PIN with @noble/curves, calls
// POST /v1/evaluate with a PIN token of natrium-token-exchange and finalizes the answer. It prints the status, the key version and a
// fingerprint of the output. With the same PIN, user and key version the fingerprint is the same in every run.
//
//   NATRIUM_PIN_URL=https://pin.example NATRIUM_PIN_TOKEN=<PIN token> \
//     node evaluate.mjs <pin> [keyVersion]
import { createHash } from 'node:crypto';
import { p256_oprf } from '@noble/curves/nist.js';

const [pin, keyVersion] = process.argv.slice(2);
const url = process.env.NATRIUM_PIN_URL;
const token = process.env.NATRIUM_PIN_TOKEN;
if (!pin || !url || !token) {
  console.error('usage: NATRIUM_PIN_URL=... NATRIUM_PIN_TOKEN=... node evaluate.mjs <pin> [keyVersion]');
  process.exit(2);
}

const { oprf } = p256_oprf;
const input = new TextEncoder().encode(pin.normalize('NFC'));
const { blind, blinded } = oprf.blind(input);
const body = { blindedElement: Buffer.from(blinded).toString('base64') };
if (keyVersion) body.keyVersion = Number(keyVersion);

const response = await fetch(new URL('/v1/evaluate', url), {
  method: 'POST',
  headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
  body: JSON.stringify(body),
});
const answer = await response.json();
if (!response.ok) {
  const retryAfter = response.headers.get('Retry-After');
  console.log(`${response.status} ${answer.error}${retryAfter ? `, retry after ${retryAfter} s` : ''}`);
  process.exit(1);
}
const output = oprf.finalize(input, blind, new Uint8Array(Buffer.from(answer.evaluatedElement, 'base64')));
const fingerprint = createHash('sha256').update(output).digest('hex').slice(0, 16);
console.log(`${response.status} keyVersion ${answer.keyVersion}, output fingerprint ${fingerprint}`);
