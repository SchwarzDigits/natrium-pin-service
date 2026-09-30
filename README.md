# natrium-pin-service

The PIN service of [Natrium](https://github.com/SchwarzDigits/natrium). Natrium protects a user's key file with a short
PIN. The key of the file is derived from the PIN and a secret of this service, through an oblivious pseudorandom
function (OPRF, RFC 9497, `P256-SHA256`). Every guess at the PIN needs a request to this service, the service limits
the requests per Wire user, and it sees neither the PIN nor the result.

Status: works and is tested, not yet in production use. Versions are 0.x: the API can still change, but not the
derivation of the keys, which existing key files depend on.

## Why

A Natrium client in the browser keeps its keys in a key file, so that it can come back after the browser cleared its
storage. The file must be safe to download, to store anywhere and to lose. A PIN of six characters is easy to type,
but on its own it would fall to an offline search within seconds.

This service makes every guess at the PIN a request to a server that counts:

- **No offline search.** The key of a file depends on a secret of this service. Whoever has the file still needs the
  service for every guess, and gets 5 guesses per hour and 12 per day and user by default.
- **Blind.** The client blinds the PIN before sending it (OPRF). The service sees neither the PIN nor the key, and does
  not learn whether a guess was right.
- **Per user.** The service derives a key of its own for every Wire user from its master key. A file of one user
  cannot be guessed at with another user's token.
- **No Wire token here.** Clients authenticate with a short-lived token of
  [natrium-token-exchange](https://github.com/SchwarzDigits/natrium-token-exchange), which the service verifies
  offline. It never holds a Wire access token, which would act for the user at Wire.
- **Master keys in the KMS.** The master keys are stored only encrypted by the STACKIT KMS, and kept in locked memory
  while the service runs.

## How it works

```mermaid
sequenceDiagram
    participant C as Client (browser)
    participant T as natrium-token-exchange
    participant P as natrium-pin-service
    participant D as PostgreSQL
    C->>T: POST /v1/token (Wire token, audience "pin")
    T-->>C: PIN token (10 minutes)
    C->>C: blind the PIN
    C->>P: POST /v1/evaluate (PIN token, blinded element)
    P->>P: verify the token with the exchange's key set
    P->>D: count the attempt for the user
    P->>P: evaluate with the user's key
    P-->>C: evaluated element
    C->>C: finalize, combine with Argon2id(PIN), derive the key
```

To make a key file, the client does this once and encrypts its secret with the file key. To open one after the browser
lost its storage, it logs in to Wire, does the same with the key version from the file, and decrypts. A wrong PIN
shows as a failed decryption, and the attempt has been counted.

The [documents](docs/README.md) describe the [protocol](docs/protocol.md), [operations](docs/operations.md) and the
[threat model](docs/threat-model.md).

## API

```
POST /v1/evaluate
Authorization: Bearer <PIN token of natrium-token-exchange>
Content-Type: application/json

{"keyVersion": 1, "blindedElement": "<base64>"}
```

`blindedElement` is a serialized element of P-256 (33 bytes, compressed) in standard base64 with padding.
`keyVersion` is omitted when a new key file is made; the server then uses its current version. When a key file is
opened, it is the version from the file. The answer is
`{"keyVersion": 1, "evaluatedElement": "<base64>", "attemptsRemaining": 4}`: `attemptsRemaining` is how many more
attempts the user has before a limit is reached, so a client whose PIN turns out to be wrong can show it.

Errors have the body `{"error": "<code>"}`:

| Status | Code | When | Counted |
|---|---|---|---|
| 400 | `bad_request` | not one JSON object with known fields, more than 1 KiB, no valid element | no |
| 401 | `unauthorized` | no Bearer token, or the token is not accepted: wrong signature, issuer or audience, expired | no |
| 410 | `key_version_unavailable` | the key version is not active | no |
| 429 | `too_many_attempts` | a limit is reached; `Retry-After` gives the seconds until the attempt would be allowed | no |
| 503 | `unavailable` | the master keys or the exchange's key set are not loaded, or the database cannot be reached | no |
| 500 | `internal` | an error in the server | only if it occurs in the evaluation |

The server checks in this order: master keys loaded, token, body and element, key version, limits, evaluate. By
default a user has 5 attempts per hour and 12 per day. Only an attempt within all limits is counted and evaluated.
Pages of any origin may call the API (CORS with `*`, without credentials): the token is set by the client in the
header, not added by the browser.

The token is a JWT of natrium-token-exchange for the audience `pin`. The server verifies it offline with the
exchange's key set: EdDSA, `iss`, `aud`, `exp`, `nbf` and `iat`. The user is the qualified ID in `sub`.

The key of a user is derived from the master key with `DeriveKeyPair` of RFC 9497 and the info string
`natrium-recovery-v1|<domain>|<user ID>|0`, from the user's qualified ID. The info string keeps its first name: it is
part of the derivation, and changing it would make every key file unreadable.

## Running

The server needs PostgreSQL, a key of the STACKIT KMS (purpose `symmetric_encrypt_decrypt`, algorithm `aes_256_gcm`)
with a service account that may use it, and a natrium-token-exchange that issues tokens for the audience `pin`.

```sh
go install github.com/SchwarzDigits/natrium-pin-service/cmd/...@latest

# The NATRIUM_PIN_KMS_* variables name the KMS key and hold the service account key (see below).
new-master-key -key-version 1 -kms-version 1   # prints 1:1:<ciphertext>

docker run -d --rm -p 15433:5432 -e POSTGRES_PASSWORD=nrs -e POSTGRES_USER=nrs -e POSTGRES_DB=nrs postgres:17-alpine
NATRIUM_PIN_DATABASE_URL='postgres://nrs:nrs@127.0.0.1:15433/nrs?sslmode=disable' \
NATRIUM_PIN_TOKEN_JWKS_URL=https://token.example/.well-known/jwks.json \
NATRIUM_PIN_TOKEN_ISSUER=https://token.example NATRIUM_PIN_TOKEN_AUDIENCE=https://pin.example \
NATRIUM_PIN_MASTER_KEYS='1:1:<ciphertext>' NATRIUM_PIN_CURRENT_KEY_VERSION=1 natrium-pin-service
```

The server listens on one port and serves:

| Path | Purpose |
|---|---|
| `/v1/evaluate` | the API |
| `/.well-known/live` | liveness probe, always 200 |
| `/.well-known/ready` | readiness probe, 200 once the master keys and the exchange's key set are loaded and while the database answers within one second |
| `/metrics` | Prometheus metrics: requests by result, duration of the token check, loaded master key versions |

Do not expose the probes and the metrics through a reverse proxy. The server logs JSON to stdout and shuts down on
SIGINT and SIGTERM after running requests have finished. The migrations run at start under a session lock, so several
instances can start at once.

At start the server decrypts each master key once with the KMS, and retries with backoff while the KMS fails. The
keys are then kept outside the Go heap; on Linux in memory that is locked against swapping and excluded from core
dumps, and the process is made not dumpable. If a master key does not decrypt to a master key of its version, the
server stops with an error.

### Configuration

| Variable | Required | Default | Meaning |
|---|---|---|---|
| `NATRIUM_PIN_PORT` | no | `8080` | port for the API, the probes and the metrics |
| `NATRIUM_PIN_TOKEN_JWKS_URL` | yes | | the key set of natrium-token-exchange, e.g. `https://token.example/.well-known/jwks.json`. Must be https |
| `NATRIUM_PIN_TOKEN_ISSUER` | yes | | the `iss` the tokens must carry: the exchange's issuer, e.g. `https://token.example` |
| `NATRIUM_PIN_TOKEN_AUDIENCE` | yes | | the `aud` the tokens must carry: this service's name, e.g. `https://pin.example`. The exchange's `PIN_AUDIENCE` must be the same |
| `NATRIUM_PIN_DATABASE_URL` | yes | | PostgreSQL connection string. There is no store in memory |
| `NATRIUM_PIN_LIMITS` | no | `5/1h,12/24h` | attempts per user and window, comma-separated `<attempts>/<window>`. An attempt must be within every limit. Windows of at least `1s` |
| `NATRIUM_PIN_KMS_PROJECT_ID`, `_KMS_REGION`, `_KMS_KEY_RING_ID`, `_KMS_KEY_ID` | yes | | the STACKIT KMS key that encrypts the master keys, e.g. region `eu01` |
| `NATRIUM_PIN_KMS_SERVICE_ACCOUNT_KEY` | yes | | the JSON key of a service account that may use the KMS key, including its private key. The value, not a path: the JSON itself or the JSON in base64, for platforms that cannot keep a JSON or multi-line value |
| `NATRIUM_PIN_MASTER_KEYS` | yes | | the active master keys, comma-separated, each `<keyVersion>:<kmsVersion>:<base64 ciphertext>` as printed by `new-master-key` |
| `NATRIUM_PIN_CURRENT_KEY_VERSION` | yes | | the version for new key files, one of `MASTER_KEYS` |
| `NATRIUM_PIN_LOG_LEVEL` | no | `info` | `debug`, `info`, `warn` or `error` |

An invalid value stops the start with a message that names the variable.

### Embedding

Programs that read their configuration differently, for example from the variables of a deployment platform, build
a `server.Config` and call `server.Run`:

```go
masterKeys, err := server.ParseMasterKeys(masterKeyEntries) // "1:1:<base64>,2:1:<base64>"
if err != nil {
	return err
}
cfg := server.DefaultConfig()
cfg.Addr = ":8080"
cfg.TokenJWKSURL = "https://token.example/.well-known/jwks.json"
cfg.TokenIssuer, cfg.TokenAudience = "https://token.example", "https://pin.example"
cfg.DatabaseURL = databaseURL
cfg.KMSProjectID, cfg.KMSRegion, cfg.KMSKeyRingID, cfg.KMSKeyID = projectID, "eu01", keyRingID, keyID
cfg.KMSServiceAccountKey = serviceAccountKey
cfg.MasterKeys = masterKeys
cfg.CurrentKeyVersion = 2
err = server.Run(ctx, cfg, logger) // returns after ctx is canceled and the server has shut down
```

`Config.Validate` reports an invalid field as a `*server.ConfigError` with the Go field name, so the caller can name
its own setting in the message.

## Development

| | |
|---|---|
| Tests | `go test -race ./...`. The PostgreSQL tests also need `NATRIUM_PIN_TEST_DATABASE_URL`, e.g. `postgres://nrs:nrs@localhost:15433/nrs`, and are skipped without it |
| Lint | `golangci-lint run` |
| Interop | `cd interop && npm ci && node check.mjs` recomputes the client side of the fixed values in `internal/evaluator/testdata/interop.json` with `@noble/curves`, an independent implementation. `go test ./internal/evaluator -run TestInteropVectors` checks that the server still produces these values. Not part of CI |
| Against a server | `NATRIUM_PIN_URL=… NATRIUM_PIN_TOKEN=<PIN token> node interop/evaluate.mjs <pin>` runs the client side against a running server |

## Layout

| Path | Content |
|---|---|
| `cmd/natrium-pin-service` | the command: reads the environment and calls `server.Run` |
| `cmd/new-master-key` | creates a master key and prints only its KMS ciphertext |
| `server` | `Config`, `Validate` and `Run`, the public API |
| `config` | the environment variables of the command. `LoadFrom` and `LoadKMSFrom` read them through a function, for programs that receive the settings under other names |
| `internal/httpapi` | `POST /v1/evaluate`: order of the checks, error codes, CORS, logs and metrics |
| `internal/attempts` | the attempt counter in PostgreSQL and its migrations |
| `internal/masterkey` | the master keys: KMS, loading with backoff, locked memory |
| `internal/evaluator` | the OPRF: key derivation from the master key and the info string, evaluation |
| `internal/tokenauth` | the check of the exchange's tokens against its key set |
| `internal/platform` | logging, probes, metrics, panic recovery, graceful shutdown |

## License

Apache License 2.0, see [`LICENSE`](LICENSE).
