# Protocol

A Natrium installation keeps a secret from which it derives all its keys. The user can export that secret as an
encrypted key file and restore the installation from it. The key of the key file is derived from a short PIN and a
secret of this service, through an oblivious pseudorandom function (OPRF). As a result:

- Every guess at the PIN needs a request to the service, and the service limits the requests per Wire user.
- The service sees neither the PIN nor the result.
- A client that opened or made a key file sends a receipt, signed with a key that only the key file's secret yields.
  The service then gives the attempt back. A wrong guess stays counted: without the right PIN there is no signature.
  The service thereby learns that a restore or an export succeeded, but not the PIN.

## OPRF

RFC 9497, mode OPRF (`modeOPRF`, 0x00), suite `P256-SHA256`. The verifiable modes (VOPRF, POPRF) are not used. They
let the client check an answer against a public key, which the client would have to obtain and trust for each user. A
wrong answer here shows as a failed decryption of the key file; a dishonest server could achieve the same by not
answering at all.

| Step | Party | RFC 9497 |
|---|---|---|
| blind the input | client | `Blind` |
| evaluate the blinded element | server | `BlindEvaluate` |
| finalize | client | `Finalize` |

The server uses CIRCL (`github.com/cloudflare/circl/oprf`). Natrium uses `@noble/curves` (`p256_oprf` from
`@noble/curves/nist.js`). `internal/evaluator/testdata/interop.json` holds fixed values of whole exchanges, which the
server's tests and `interop/check.mjs` with `@noble/curves` both reproduce.

## Keys

The server keeps one or more master keys of 32 bytes, each with a version from 1. The key of a key file is not
stored. It is derived for each request:

```
key = DeriveKeyPair(seed = master[keyVersion], info)          RFC 9497, section 3.2.1
info = "natrium-recovery-v2|" + domain + "|" + userId + "|" + epoch + "|" + base64(refundKey)
```

- `domain` and `userId` are the user's qualified ID, taken from `sub` of the token (see Authentication), which
  natrium-token-exchange takes from `qualified_id` of Wire's `GET /self`. The domain is in lowercase, the user ID a
  lowercase UUID in the form 8-4-4-4-12.
- `epoch` is written in decimal without leading zeros. It is always `0`: key files cannot be revoked yet. A later
  version can revoke all key files of a user by raising the epoch.
- `refundKey` is the public Ed25519 key of the key file's receipts (see Receipts), 32 bytes, in standard base64 with
  padding as in the request, 44 characters. It binds the key to one key file: an answer for one refund key is of no
  use for a key file with another.
- The info string is encoded as UTF-8; all its characters are ASCII.

Example:

```
natrium-recovery-v2|wire.example|39b7f597-dfd1-4dff-86f5-fe1b79cb70a0|0|11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=
```

This encoding is part of the contract. A change makes every existing key file unreadable. The tests hold fixed
values for it.

## API

### `POST /v1/evaluate`

```
POST /v1/evaluate
Authorization: Bearer <PIN token of natrium-token-exchange>
Content-Type: application/json

{"keyVersion": 1, "refundKey": "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=", "blindedElement": "A3I6HlwJuLnBjR3LyinoAH6V8U9HMtk0bUkP/BlREDaN"}
```

| Field | Meaning |
|---|---|
| `keyVersion` | Optional, a number from 1. Omitted when a new key file is made: the server then uses its current version. When a key file is opened, the version from the file. |
| `refundKey` | Required. The public Ed25519 key of the key file's receipts, 32 bytes in standard base64 with padding. A new key file: the key the client derived from its secret (see Client side); an existing one: the key from its header. It must be a point of the curve and not of small order. |
| `blindedElement` | `SerializeElement` of RFC 9497: the compressed SEC1 point of P-256, 33 bytes, in standard base64 (RFC 4648, section 4) with padding. For 33 bytes that is 44 characters without `=`. |

Answer `200`:

```json
{"keyVersion": 1, "evaluatedElement": "A+s+e/Kb3gwtURsqks/88WVfTfP1IEmKmXHTxwFg1Xu4", "attemptsRemaining": 4, "attemptId": "9mY0r1bKQwS2c1v3Zk8hJA=="}
```

`keyVersion` is the version used, which the client writes into a new key file. `evaluatedElement` is encoded like
`blindedElement`. `attemptsRemaining` is how many more attempts the user has after this one before a limit is
reached: the smallest number over all limits. A client whose decryption fails shows this number. `attemptId` names
the attempt for a receipt, 16 random bytes in standard base64 with padding; it is valid for 15 minutes.

Answers carry `Cache-Control: no-store`.

### Errors

The body is always `{"error": "<code>"}`.

| Status | Code | When | Counted |
|---|---|---|---|
| 400 | `bad_request` | The body is larger than 1 KiB, is not exactly one JSON object, has unknown fields, `keyVersion` is not a number from 1, `refundKey` is missing, is not standard base64 with padding, is not 32 bytes or is not a usable Ed25519 public key, `blindedElement` is missing, is not standard base64 with padding, is not 33 bytes, is not a point of P-256 or is the identity. | no |
| 401 | `unauthorized` | The header `Authorization: Bearer <token>` is missing, or the token is not accepted (see Authentication). The answer carries `WWW-Authenticate: Bearer`. | no |
| 410 | `key_version_unavailable` | The key version is not one of the active versions. | no |
| 429 | `too_many_attempts` | The user has reached a limit. `Retry-After` gives the seconds until the attempt would be allowed, rounded up: until the end of the last window whose limit is reached. | no |
| 503 | `unavailable` | The master keys are not loaded yet, there is no current key set of the exchange, or the database cannot be reached. | no |
| 500 | `internal` | An error in the server. | only if it occurs in the evaluation |
| 405 | – | Another method than `POST`. | no |

The server checks in this order:

1. master keys loaded,
2. token (verified offline),
3. body, refund key and blinded element,
4. key version,
5. limits: count the attempt if it is within all limits,
6. evaluate.

Only a request that passes the first four checks and is within all limits is counted, and only a counted request is
evaluated.

### `POST /v1/refund`

```
POST /v1/refund
Authorization: Bearer <PIN token of natrium-token-exchange>
Content-Type: application/json

{"attemptId": "9mY0r1bKQwS2c1v3Zk8hJA==", "signature": "<64 bytes in standard base64 with padding>"}
```

The receipt for an attempt whose key file the client could open, or whose key file it made. `signature` is the
Ed25519 signature (RFC 8032) with the private key of the attempt's refund key over the UTF-8 bytes of

```
"natrium-pin-refund-v1|" + domain + "|" + userId + "|" + attemptId
```

with `domain` and `userId` as in the info string and `attemptId` exactly as the service returned it.

Answer `200`: `{"attemptsRemaining": 5}`, the attempts left after the refund.

| Status | Code | When |
|---|---|---|
| 400 | `bad_request` | The body is larger than 1 KiB, is not exactly one JSON object, has unknown fields, or `attemptId` or `signature` is missing or not standard base64 with padding of 16 or 64 bytes. |
| 401 | `unauthorized` | As for `/v1/evaluate`. |
| 404 | `unknown_attempt` | No attempt of this user with this ID that has not been refunded and is younger than 15 minutes. |
| 403 | `invalid_signature` | The signature does not verify with the attempt's refund key. |
| 503, 500 | `unavailable`, `internal` | As for `/v1/evaluate`. |

Refunds are not limited and not counted. The answers carry `Cache-Control: no-store`, and CORS is as for
`/v1/evaluate`.

### Authentication

The token is a JSON Web Token of natrium-token-exchange for the audience `pin`. The client gets it from the exchange
with its Wire access token; the exchange admits only the users its lists allow. The service verifies the token
offline and accepts it only if:

1. the header's `alg` is `EdDSA`; other algorithms, `none` in particular, are refused;
2. the exchange's key set contains the header's `kid`, and the signature verifies with that key;
3. `iss` is the configured issuer and `aud` contains the configured audience, this service's name;
4. `exp` is present, and `exp`, `nbf` and `iat` hold with an allowance of 30 seconds for clock skew;
5. `sub` is a qualified ID, `<uuid>@<domain>`; it is read in lowercase.

The service takes the user from `sub`. It does not look at `cnf` or `team`.

The key set is loaded from the configured https URL at start, with backoff until it succeeds; until then the service
is not ready. It is fetched again when its `max-age` has passed, at most every five minutes, and a token with an
unknown `kid` makes the service fetch it again at once, at most once per minute. A failed fetch keeps the previous key
set for up to an hour after it was loaded; after that the service answers `503` until a fetch succeeds. Redirects are
not followed.

The service never sees a Wire access token. Tokens for the storage server carry another audience and are refused.

### CORS

Pages of any origin may call the API. The server answers the preflights (`OPTIONS /v1/evaluate`,
`OPTIONS /v1/refund`) with `Access-Control-Allow-Origin: *`, `Access-Control-Allow-Methods: POST` and
`Access-Control-Allow-Headers: Authorization, Content-Type`, and answers requests with `Access-Control-Allow-Origin: *`
and `Access-Control-Expose-Headers: Retry-After`. It does not allow credentials.

A list of allowed origins would protect nothing here. CORS protects credentials that the browser adds by itself, such
as cookies. The API has none: the client sets the token in the `Authorization` header. A page without the token
gets no further than 401, and whoever has a token can call the API from outside a browser, where CORS does not
apply.

## Attempts

- Attempts are counted per Wire user against several limits, each with a fixed window of its own. By default a user
  has 5 attempts per hour and 12 per day. A window starts with the first attempt after the previous window of the
  same limit ended.
- An attempt is allowed only if it is within every limit. Then it is counted in every window. An attempt that a limit
  refuses is not counted in any window, so trying again during the wait does not use up the day.
- Every allowed attempt counts: a restore with a wrong PIN, a restore with the right PIN, and the export of a new key
  file. A receipt gives an attempt back (see Receipts); without one it stays counted.
- After a limit the user waits until its window ends; `Retry-After` gives the time. Nothing is deleted: otherwise
  anyone with access to a user's Wire account could destroy the user's key files.
- The windows are fixed, not sliding. At the end of one hour window and the start of the next, up to 10 attempts are
  possible within a short time. A day window never has more than 12, so over a longer time the average is at most
  12 per day.
- All instances of the service share the counts through PostgreSQL; deciding and counting are one transaction.
  `Retry-After` is computed from the database's clock.

## Receipts

Each key file has a key pair for receipts. The client derives it from the secret in the key file:

```
refundSeed = HKDF-SHA256(ikm = secret, salt = empty, info = "natrium-pin-refund-v1|" + domain + "|" + userId)
```

`refundSeed` (32 bytes) is the private Ed25519 key in the form of RFC 8032; its public key is `refundKey`. The public
key is written into the key file's header in plaintext.

- The client sends `refundKey` with every evaluation. The service derives the key of the evaluation from it (see
  Keys) and stores it with the attempt, with the windows the attempt was counted in.
- After decrypting the key file, or after making it, the client signs the attempt's receipt with the private key and
  sends it to `/v1/refund`. The service checks the user, the age of at most 15 minutes and the signature, takes the
  attempt off every window it was counted in that has not ended yet, and deletes it. An attempt is refunded at most
  once.
- Whoever has the key file but not the PIN cannot sign: the private key comes from the secret. Sending a refund key
  of one's own gives signable attempts, but their answers belong to another key and open no other key file. Wrong
  guesses against a key file therefore always stay counted.
- The key of the receipts is derived from the secret, not from the key of the key file: that key comes from the PIN
  and the OPRF, so a public key derived from it would let the operator, who knows the master keys, test PINs offline.
- The service learns the refund key of each key file and when a restore or export succeeded. It learns nothing about
  the PIN.

## Client side

This part is implemented in Rust by the client library that Natrium builds on; Natrium only takes the PIN from the
user and keeps the resulting bytes. The service must match it. The library checks the fixed values in
`internal/evaluator/testdata/interop.json` in its own tests.

**Export** (installation with intact storage, logged in):

1. PIN: Unicode NFC, then UTF-8. At least 6 characters.
2. A PIN token from natrium-token-exchange (`{"audience": "pin"}`) with the current Wire access token.
3. Derive `refundKey` from the secret (see Receipts).
4. `Blind(pin)`, `POST /v1/evaluate` with `refundKey` and without `keyVersion`, `Finalize` gives `o` (32 bytes).
5. `a = Argon2id(pin, salt, m = 64 MiB, t = 3, p = 1)` with a random salt. Argon2id stays: should the master keys
   leak, each guess is still expensive.
6. `key = HKDF-SHA256(ikm = o || a, info = "sodium/v1/recovery-data")`.
7. The secret is encrypted with AES-256-GCM. The header, in plaintext, holds the format version, `keyVersion`,
   `refundKey`, the Argon2 parameters, the salt, the nonce and the user's qualified ID; it is the associated data.
8. `POST /v1/refund` for the attempt: an export uses up no attempt.

**Restore** (empty browser):

1. Log in to Wire, only to get tokens, without registering a client. The login comes before decrypting, because the
   PIN token needs a Wire access token.
2. Compare the qualified ID in the header with the logged-in user; bytes of another user are refused before the
   service is asked, so they cost no attempt.
3. A PIN token from natrium-token-exchange (`{"audience": "pin"}`), without a key: the key comes out of the bytes.
4. PIN, `POST /v1/evaluate` with `keyVersion` and `refundKey` from the header, derive the key, decrypt.
5. If AES-GCM fails, the PIN was wrong. The attempt stays counted; `attemptsRemaining` of the answer says how many are
   left.
6. If it succeeds, derive the key pair of the receipts from the decrypted secret. Its public key must equal
   `refundKey` in the header; otherwise the file is damaged. `POST /v1/refund` for the attempt: a successful restore
   uses up no attempt. A failed refund, e.g. after 15 minutes, only leaves the attempt counted.
7. `429` becomes a result of its own with the waiting time, `410` means the bytes can no longer be opened. A `401`
   after the PIN token expired (10 minutes by default) is answered with a new PIN token, not a new Wire login.
