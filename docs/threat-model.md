# Threat model

The key file holds the secret of a Natrium installation, encrypted with a key derived from the user's PIN, a master
key of this service and Argon2id (see [protocol.md](protocol.md)). With the key file and the remote storage, an empty
browser restores the installation. Both this service and the remote storage admit a user only with a token of
natrium-token-exchange, which needs a Wire access token of the user.

## What an attacker gains

| The attacker has | Result |
|---|---|
| only the key file | Nothing. Each guess at the PIN needs a request with a PIN token of the user, which only natrium-token-exchange issues, for a Wire access token of the user; and the guesses are limited. |
| the key file and access to the user's Wire account | 5 guesses per hour and 12 per day. A 6-digit PIN lasts about 114 years on average (500,000 guesses at 12 per day). Receipts do not help: signing one needs the secret in the key file. |
| a receipt key of the attacker's own | Attempts the attacker can give back, but the service answers them with a key derived from that receipt key; the answers open no key file with another. |
| the service's database | The counts of attempts and the receipt keys of attempts not yet given back, nothing else. |
| a master key, e.g. from the memory of the running service | Alone, nothing. With a key file of that version, the attacker can guess offline against Argon2id; a 6-digit PIN then falls within hours. The data in the remote storage stay protected by the token it requires. |
| access to a user's Wire account | The attacker can use up the user's attempts. The user waits until the window ends, but loses nothing. |
| a PIN token of a user, e.g. copied from a proxy log | Guesses for that user within the user's limits, until the token expires (10 minutes by default), and only with the user's key file. |
| a token for the storage server | Nothing: its audience is not this service's. |
| a web page the user visits | Nothing. The page may call the API (CORS allows any origin), but the browser does not add the user's token; without it the page gets 401. |
| the blinded and evaluated elements of a request, e.g. from a log of a proxy | Nothing about the PIN: the blinded element is a uniformly random point. |
| control of the Wire backend, or its token signing key | Wire tokens for any user, with them PIN tokens, and so 12 guesses per user and day. The Wire backend is trusted. |
| control of natrium-token-exchange, or one of its signing keys | PIN tokens for any user, and so 12 guesses per user and day, until the signing key is replaced. The exchange is trusted. |
| control of the running service | The master keys, and the PIN tokens of the users who make requests, which are accepted nowhere else and expire after 10 minutes. No Wire access token. |

The service sees neither the PIN nor the output of the OPRF. Through receipts it learns when a restore or an export
succeeded, and the public receipt key of each key file, by which it can tell a user's key files apart.

## Reaction to a leaked master key

- Create a new version and remove the leaked one from `NATRIUM_PIN_MASTER_KEYS` (see
  [operations.md](operations.md#a-leaked-master-key)).
- Users with an intact installation export a new key file.
- Key files of the leaked version then give `410`.

## Limits

- **Receipts.** A restore or export gives its attempt back only if the client sends the receipt within 15 minutes. A
  client that stops before, e.g. because the page was closed, leaves the attempt counted. Until the receipt arrives,
  the attempt counts against the limits.
- **Receipt key from the secret.** The receipt key is derived from the secret in the key file, not from the key that
  decrypts it. That key comes from the PIN and the OPRF; a public key derived from it would let the operator, who
  knows the master keys, test PINs offline against it.
- **Window boundary.** The windows are fixed. At the end of one hour window and the start of the next, up to 10
  guesses are possible in a short time. A day window never has more than 12, so the rate over a longer time does
  not change.
- **Revocation.** Key files cannot be revoked yet. The info string already contains an epoch for all key files of a
  user, and the receipt key would allow revoking a single key file. Revoking must not be possible with only a Wire
  token, since then anyone with access to a user's Wire account could destroy the user's key files.
- **Tokens of blocked users.** The exchange asks Wire when it issues a PIN token; this service verifies the token
  offline. A user blocked in Wire, or removed from the exchange's lists, keeps a PIN token already issued until it
  expires, 10 minutes by default.
- **Key set.** The service trusts the key set at the configured https URL. Whoever controls that URL can issue tokens
  this service accepts. When the key set cannot be fetched, the service keeps using the last one for up to an hour,
  so removing a leaked signing key takes up to an hour to take effect while the exchange is unreachable.
- **Memory.** The master keys are in the memory of the running service, protected as described in
  [operations.md](operations.md#memory-protection). Copies made during requests are neither locked nor wiped.
- **Timing.** The scalar multiplication of the evaluation runs in constant time (P-256 of the Go standard library).
  The derivation of a user's key reduces a hash of master key and info string with `math/big` in CIRCL, which does
  not run in constant time. Each derivation uses another hash output, and no practical attack on this is known, but
  it is not constant time.
- **Availability.** Without the service, key files cannot be opened. The service depends on the KMS at start, on the
  key set of natrium-token-exchange and on its database; clients also need the exchange for their tokens.
