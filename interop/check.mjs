// Recomputes the client side of the fixed values in internal/evaluator/testdata/interop.json with @noble/curves, the
// library Natrium uses, and checks that it arrives at the same values as the server:
//
//   - the info string from domain, user ID and epoch,
//   - the input: the PIN in NFC as UTF-8,
//   - the user's key from master and info (DeriveKeyPair),
//   - the blinded element from input and blind,
//   - the evaluated element (BlindEvaluate) and the output (Finalize), also with a random blind.
//
// Run with: npm ci && node check.mjs
import { readFileSync } from 'node:fs';
import { p256_hasher, p256_oprf } from '@noble/curves/nist.js';

const { oprf } = p256_oprf;
const utf8 = (s) => new TextEncoder().encode(s);
const hex = (b) => Buffer.from(b).toString('hex');
const fromHex = (s) => new Uint8Array(Buffer.from(s, 'hex'));
const base64 = (b) => Buffer.from(b).toString('base64');
const fromBase64 = (s) => new Uint8Array(Buffer.from(s, 'base64'));
// DST of HashToGroup for mode OPRF (0x00) and suite P256-SHA256, RFC 9497 section 4.3.
const hashToGroupDST = new Uint8Array([...utf8('HashToGroup-OPRFV1-'), 0x00, ...utf8('-P256-SHA256')]);

const vectors = JSON.parse(readFileSync(new URL('../internal/evaluator/testdata/interop.json', import.meta.url)));
let failures = 0;
const check = (name, what, got, want) => {
  if (got !== want) {
    failures++;
    console.error(`FAIL ${name}: ${what}\n  got  ${got}\n  want ${want}`);
  }
};

for (const v of vectors) {
  const info = `natrium-recovery-v1|${v.domain}|${v.userId}|${v.epoch}`;
  check(v.name, 'info', info, v.info);

  const input = utf8(v.pin.normalize('NFC'));
  check(v.name, 'input', hex(input), v.input);

  const { secretKey } = oprf.deriveKeyPair(fromHex(v.master), utf8(info));
  check(v.name, 'secret key', hex(secretKey), v.secretKey);

  const inputPoint = p256_hasher.hashToCurve(input, { DST: hashToGroupDST });
  const blinded = inputPoint.multiply(BigInt('0x' + v.blind)).toBytes(true);
  check(v.name, 'blinded element', base64(blinded), v.blindedElement);

  const evaluated = oprf.blindEvaluate(secretKey, fromBase64(v.blindedElement));
  check(v.name, 'evaluated element', base64(evaluated), v.evaluatedElement);

  const output = oprf.finalize(input, fromHex(v.blind), fromBase64(v.evaluatedElement));
  check(v.name, 'output', hex(output), v.output);

  const random = oprf.blind(input);
  const randomOutput = oprf.finalize(input, random.blind, oprf.blindEvaluate(secretKey, random.blinded));
  check(v.name, 'output with a random blind', hex(randomOutput), v.output);
}

if (failures > 0) {
  console.error(`${failures} of the values differ`);
  process.exit(1);
}
console.log(`OK: ${vectors.length} vectors match @noble/curves`);
