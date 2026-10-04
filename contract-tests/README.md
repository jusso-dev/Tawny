# Tawny HTTP contract suite

Black-box checks against a running API. Python 3 stdlib only. No pip packages.

The suite does not reset the database. Hostnames, rule names, nonces, and tokens are unique per run. Run the whole file in one process so the enrollment rate-limit test stays last.

Wait at least one minute between full runs. `POST /api/agents/enroll` allows 10 requests per minute per client IP. The last test spends that window on purpose.

## Run

```bash
cd contract-tests
python3 suite.py
```

From the repo root:

```bash
python3 contract-tests/suite.py
```

## Environment

| Variable | Default | Meaning |
| --- | --- | --- |
| `TAWNY_BASE_URL` | `http://127.0.0.1:5080` | API origin. A trailing slash is stripped |
| `TAWNY_CONTRACT_AUTH` | `hmac` | `hmac` for the current .NET API. `session` for Zig |
| `TAWNY_HMAC_SECRET` | `test-hmac-secret` | HMAC key. Must match the API `Tawny:WebUserHmacSecret` |
| `TAWNY_TENANT_ID` | `00000000-0000-0000-0000-000000000001` | Signed tenant |
| `TAWNY_ADMIN_USER_ID` | `00000000-0000-0000-0000-0000000000aa` | Signed admin user id |
| `TAWNY_SESSION_COOKIE` | empty | Session mode. Full `Cookie` header value |
| `TAWNY_SESSION_BEARER` | empty | Session mode. `Authorization: Bearer` on web calls |
| `TAWNY_CSRF_TOKEN` | empty | Session mode. `X-CSRF-Token` on web writes |

`hmac` signs web calls with `WebUserCanonical` v2 (HMAC-SHA256, lowercase hex). Headers: `X-User-Id`, `X-User-Role`, `X-Tenant-Id`, `X-Timestamp`, `X-Nonce`, `X-Signature`.

`session` does not sign. It sends `X-User-Id`, `X-User-Role`, and `X-Tenant-Id`, plus the cookie, bearer, and CSRF envs when set. Zig's target is an HttpOnly session cookie and no HMAC hop. Signature rejection tests are skipped in this mode.

The default HMAC secret is 16 bytes. .NET production startup rejects a web HMAC secret shorter than 32 bytes. Use this default only on a Development (or otherwise check-disabled) host configured with the same value. Point `TAWNY_HMAC_SECRET` at the real secret if the API uses a longer one.

Agent calls use the enroll JWT (`Authorization: Bearer`). Automation calls use the plaintext API token returned by `POST /api/api-tokens`. Neither of those is the web HMAC.

`COVERAGE.md` maps every xUnit method. Rows name a `suite.py` function only when that behavior is driven over HTTP.
