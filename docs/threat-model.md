# Threat model

The key file holds the seed of a Natrium installation, encrypted with a key derived from the user's PIN, a master key
of this service and Argon2id (see [protocol.md](protocol.md)). With the key file and the remote storage, an empty
browser restores the installation. The remote storage additionally requires a Wire access token of the user.

## What an attacker gains

| The attacker has | Result |
|---|---|
| only the key file | Nothing. Each guess at the PIN needs a request with a Wire access token of the user, and these are limited. |
| the key file and access to the user's Wire account | 5 guesses per hour and 12 per day. A 6-digit PIN lasts about 114 years on average (500,000 guesses at 12 per day). |
| the service's database | The counts of attempts, nothing else. |
| a master key, e.g. from the memory of the running service | Alone, nothing. With a key file of that version, the attacker can guess offline against Argon2id; a 6-digit PIN then falls within hours. The data in the remote storage stay protected by the Wire token it requires. |
| access to a user's Wire account | The attacker can use up the user's attempts. The user waits until the window ends, but loses nothing. |
| a web page the user visits | Nothing. The page may call the API (CORS allows any origin), but the browser does not add the user's Wire token; without it the page gets 401. |
| the blinded and evaluated elements of a request, e.g. from a log of a proxy | Nothing about the PIN: the blinded element is a uniformly random point. |
| control of the Wire backend, or its token signing key | Tokens for any user, and with them 12 guesses per user and day. The Wire backend is trusted. |
| control of the running service | The master keys, and the Wire access tokens of the users who make requests, each valid for up to 15 minutes. |

The service sees neither the PIN nor the output of the OPRF, and it does not learn whether a guess was right.

## Reaction to a leaked master key

- Create a new version and remove the leaked one from `NATRIUM_RECOVERY_MASTER_KEYS` (see
  [operations.md](operations.md#a-leaked-master-key)).
- Users with an intact installation export a new key file.
- Key files of the leaked version then give `410`.

## Limits

- **Attempts are counted, not failures.** The service cannot tell a right from a wrong PIN, so every allowed request
  is an attempt, exports included. A user who exports a key file and later restores it uses the same budget.
- **Window boundary.** The windows are fixed. At the end of one hour window and the start of the next, up to 10
  guesses are possible in a short time. A day window never has more than 12, so the rate over a longer time does
  not change.
- **Revocation.** Key files cannot be revoked yet. The info string already contains an epoch for it. Revoking must not
  be possible with only a Wire token, since then anyone with access to a user's Wire account could destroy the
  user's key files.
- **Tokens of blocked users.** The service asks Wire for every request and does not cache the answer. It relies on
  Wire's decision about a token.
- **Memory.** The master keys are in the memory of the running service, protected as described in
  [operations.md](operations.md#memory-protection). Copies made during requests are neither locked nor wiped.
- **Timing.** The scalar multiplication of the evaluation runs in constant time (P-256 of the Go standard library).
  The derivation of a user's key reduces a hash of master key and info string with `math/big` in CIRCL, which does
  not run in constant time. Each derivation uses another hash output, and no practical attack on this is known, but
  it is not constant time.
- **Availability.** Without the service, key files cannot be opened. The service depends on the KMS at start, on Wire
  and on its database.
