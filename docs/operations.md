# Operations

## Requirements

- **PostgreSQL** for the attempt counter. The server applies its migrations at start under a session lock, so several
  instances can start at once. Its connections commit with `synchronous_commit = on`.
- **A key of the STACKIT KMS** with purpose `symmetric_encrypt_decrypt` and algorithm `aes_256_gcm`, and a service
  account that may use it. Protection `hsm` is a private preview of STACKIT and was not available in `eu01`;
  `software` works the same for this service.
- **natrium-token-exchange** with a PIN audience (`NATRIUM_TOKEN_EXCHANGE_PIN_AUDIENCE`) equal to this service's
  `NATRIUM_PIN_TOKEN_AUDIENCE`. Its key set must be reachable over https from the service; its `iss` is this
  service's `NATRIUM_PIN_TOKEN_ISSUER`.

KMS permissions in STACKIT apply to a whole project, not to one key. A service account that may decrypt in a project
may decrypt with every key of that project. Put the key of this service in a project of its own, so that no other
service can use it.

The server holds no state but the database and the master keys in memory. Instances can be added and removed at any
time.

## Access to the KMS

The server authenticates with the JSON key of the service account, in `NATRIUM_PIN_KMS_SERVICE_ACCOUNT_KEY` (the
value, not a path). The key must contain its private key, as a key created by STACKIT does. The server passes this
private key to the STACKIT SDK explicitly; otherwise the SDK would prefer `STACKIT_PRIVATE_KEY`,
`STACKIT_PRIVATE_KEY_PATH` or `~/.stackit/credentials.json`. The SDK still reads `STACKIT_TOKEN_BASEURL` if it is set.

The running server only decrypts. `new-master-key` also encrypts.

STACKIT publishes no rate limits for the KMS. The server calls it once per master key version at start.

## Master keys

A master key is 32 random bytes. It is configured only encrypted by the KMS, as an entry
`<keyVersion>:<kmsVersion>:<base64 ciphertext>` in `NATRIUM_PIN_MASTER_KEYS`:

- `keyVersion` is the version that key files name, from 1.
- `kmsVersion` is the version of the KMS key that encrypted the entry. The KMS needs it to decrypt.
- The ciphertext encrypts `natrium-recovery-master-v1`, the key version as 4 bytes (big endian) and the 32 bytes of
  the master key. The KMS cannot bind associated data to a ciphertext, so the version is inside. An entry whose key
  version was changed, or two swapped entries, stop the server at start with an error instead of yielding wrong keys.

### Creating a master key

```sh
go install github.com/SchwarzDigits/natrium-pin-service/cmd/new-master-key@latest

NATRIUM_PIN_KMS_PROJECT_ID=… NATRIUM_PIN_KMS_REGION=eu01 \
NATRIUM_PIN_KMS_KEY_RING_ID=… NATRIUM_PIN_KMS_KEY_ID=… \
NATRIUM_PIN_KMS_SERVICE_ACCOUNT_KEY="$(cat service-account-key.json)" \
new-master-key -key-version 1 -kms-version 1
```

The command creates the key with `crypto/rand`, has the KMS encrypt it, decrypts the result again to check it, and
prints only the entry. The key in plaintext never leaves the command's memory.

### Adding a version

1. Create version `n + 1` with `new-master-key`.
2. Append the entry to `NATRIUM_PIN_MASTER_KEYS` and deploy. The server now opens key files of both versions.
3. Set `NATRIUM_PIN_CURRENT_KEY_VERSION` to `n + 1` and deploy. New key files use the new version.

Key files of the old version keep working as long as its entry stays in `NATRIUM_PIN_MASTER_KEYS`. Removing the
entry makes them unreadable: the server answers `410 key_version_unavailable`. Users with an intact installation can
export a new key file before.

### A leaked master key

1. Create a new version and make it the current one, as above.
2. Remove the leaked version from `NATRIUM_PIN_MASTER_KEYS`.
3. Users with an intact installation export a new key file. Key files of the leaked version give `410`.

### Versions of the KMS key

An entry names the KMS key version that encrypted it. Do not disable or destroy a KMS key version while an entry
names it: the server could then no longer decrypt that master key at start. The server has no command to re-encrypt
an entry under another KMS version; to leave a KMS version, create a new master key version under the new KMS version
and retire the old master key version as above.

## Behavior on failures

| Failure | Behavior |
|---|---|
| KMS unreachable or failing at start | The server serves, but is not ready (`/.well-known/ready` 503) and answers requests with `503 unavailable`. It retries each master key with backoff from 1 s up to 1 min and logs every failure. |
| KMS unreachable later | No effect: the master keys are in memory. |
| An entry of `MASTER_KEYS` decrypts, but not to a master key of its version | The server stops with an error. Retrying would not help. |
| Key set of the exchange unreachable at start | Not ready, and `503 unavailable` for requests. The server retries with backoff from 1 s up to 1 min and logs every failure. |
| Key set of the exchange unreachable later | No effect for an hour: the last key set stays in use. After an hour without a successful fetch, not ready and `503 unavailable` until a fetch succeeds. |
| Database unreachable at start | The server stops with an error. |
| Database unreachable later | Not ready, and `503 unavailable` for requests that pass the checks before counting. |

## Memory protection

- The master keys are kept outside the Go heap. On Linux, this memory is excluded from core dumps (`MADV_DONTDUMP`)
  and locked against swapping (`mlock`). If the memory lock limit (`RLIMIT_MEMLOCK`) does not allow it, the server
  logs a warning and runs without the lock. One page is needed.
- At start the process makes itself not dumpable (`PR_SET_DUMPABLE` 0), so another process of the same user cannot
  attach a debugger or read its memory through `/proc`, and turns off core dumps (`RLIMIT_CORE` 0).
- Limits: for each request, CIRCL copies the master key into an ordinary buffer to derive the user's key, and the
  user's key lives on the Go heap until the garbage collector reuses the memory. The KMS answer at start passes
  through the STACKIT SDK as a base64 string that cannot be overwritten. These copies are in the process's memory
  like the rest of it; they are not locked or wiped.

On platforms other than Linux, which the service is not deployed on, none of this is done.

## Logs

JSON on stdout. One line per request to `/v1/evaluate`, with `msg` `evaluate` and:

| Field | Content |
|---|---|
| `result` | `ok`, `limited`, `bad_request`, `unauthorized`, `key_version_unavailable`, `unavailable` or `internal` |
| `user` | the qualified ID, `<uuid>@<domain>`, once the token is checked |
| `key_version` | the key version, once the body is read |
| `error` | the cause, for `unavailable` and `internal` |

Tokens, blinded and evaluated elements, master keys and users' keys never appear in logs, errors or metrics.

## Metrics

On `/metrics`, besides the Go runtime and process metrics:

| Metric | Type | Meaning |
|---|---|---|
| `natrium_pin_evaluate_requests_total{result}` | counter | requests by result, as in the log |
| `natrium_pin_token_check_duration_seconds` | histogram | duration of the token check, including a fetch of the key set for an unknown `kid` |
| `natrium_pin_master_key_versions` | gauge | loaded master key versions; 0 until the keys are loaded |

## Probes and network

- `/.well-known/live` always answers 200. `/.well-known/ready` answers 200 once the master keys are loaded, while
  there is a current key set of the exchange, and while the database answers within one second.
- Only `/v1/evaluate` belongs behind the public ingress. The probes and `/metrics` should be reachable only inside the
  cluster.
- The server speaks plain HTTP; TLS ends at the ingress.
- Tokens are verified offline; a request causes no request to Wire or to the exchange, except a fetch of the key set
  for an unknown `kid`, at most once per minute. A rate limit per client address at the ingress still keeps floods
  away from the database.

## Database

One table, `attempts`, with one row per user and limit: domain, user ID, length of the window, end of the window and
count. Rows of ended windows are deleted every hour. The table holds no keys and no secrets.

Changing `NATRIUM_PIN_LIMITS` takes effect with the next attempt. Rows of a window length that is no longer
configured are ignored and deleted once their window has ended.
