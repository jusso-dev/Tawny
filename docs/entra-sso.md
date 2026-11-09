# Sign-in with Microsoft Entra ID

Tawny signs users in with Microsoft Entra ID using OpenID Connect: the authorisation code flow with PKCE (S256). Nothing in this repository registers an app or holds a real secret. These are the steps to do it for a deployment.

## How it works

1. The sign-in page shows **Sign in with Microsoft Entra ID** when the tenant has it on. It links to `GET /api/auth/oidc/start?tenant=<tawny tenant id>`.
2. Tawny reads the tenant's discovery document (`<authority>/.well-known/openid-configuration`, cached), stores a random `state`, `nonce` and PKCE verifier in `oauth_states` for 10 minutes, and redirects to Entra.
3. Entra redirects back to `GET /api/auth/oidc/callback?code=…&state=…`. Tawny deletes the state row as it reads it, so a state works once.
4. Tawny exchanges the code at the token endpoint with the client secret and the PKCE verifier.
5. Tawny checks the ID token before it reads anything else in it:
   - RS256 signature against the JWKS (cached for 24 hours, fetched again once when the `kid` is unknown), using the RS256 code in `server/src/crypto/jwt.zig`;
   - `iss` equals the discovery issuer, `https://login.microsoftonline.com/<directory id>/v2.0`;
   - `aud` is the client id;
   - `exp` and `nbf`, with 2 minutes of clock skew;
   - `nonce` equals the stored one;
   - `tid` equals the configured directory (tenant) id.
6. The user is found by `tid` and `oid`, never by email. If there is no such user, one is created. Email is kept for display only.
7. The role comes from the `groups` claim and the group map. The highest mapped role wins. No mapped group means no access, and the refusal is written to the audit log. The role is set again on every sign-in, so removing someone from a group takes effect at their next sign-in. Existing sessions last until they expire (8 hours idle, 7 days at most).

Provider endpoints must be `https` to a public host.

## Register the app in Entra ID

Do this in the Microsoft Entra admin centre for the directory your users are in.

1. **App registrations > New registration.**
   - Name: `Tawny`.
   - Supported account types: **Accounts in this organisational directory only** (single tenant).
   - Redirect URI: platform **Web**, value `<TAWNY_PUBLIC_URL>/api/auth/oidc/callback`, for example `https://tawny.example.com.au/api/auth/oidc/callback`. It must match `TAWNY_PUBLIC_URL` exactly.
2. Note the **Application (client) ID** and the **Directory (tenant) ID** from the overview page.
3. **Certificates & secrets > Client secrets > New client secret.** Pick an expiry your organisation allows and put a reminder in the calendar before it. Copy the value once; it is not shown again. Do not paste it into tickets, chat or this repository.
4. **Token configuration > Add groups claim.** Choose **Security groups** (or **Groups assigned to the application**), and for the ID token pick **Group ID**. Tawny maps group object ids, not names.
   - Users in more than 200 groups get an overage claim instead of the list, and Tawny refuses them. Use **Groups assigned to the application** and assign only the Tawny groups to keep the list short.
5. **API permissions:** `openid`, `profile` and `email` (Microsoft Graph, delegated) are enough. Grant admin consent if your directory needs it.
6. **Enterprise applications > Tawny > Properties:** set **Assignment required** to **Yes** if only assigned users and groups should be able to try.
7. Create three security groups, or reuse existing ones, for example `Tawny admins`, `Tawny analysts` and `Tawny viewers`. Note each group's **Object ID**.

## Configure Tawny

The server needs `TAWNY_INTEGRATION_ENCRYPTION_KEY` set. The client secret is stored encrypted with it (AES-256-GCM, the same scheme as other integration secrets). Keep the key with your database backups: a new key cannot decrypt old rows.

As an admin, send:

```http
PUT /api/settings/oidc
Content-Type: application/json
X-CSRF-Token: <from GET /api/auth/session>

{
  "enabled": true,
  "entra_tenant_id": "<Directory (tenant) ID>",
  "client_id": "<Application (client) ID>",
  "client_secret": "<secret value>",
  "allowed_domains": ["example.com.au"],
  "group_roles": {
    "<Tawny admins object id>": "admin",
    "<Tawny analysts object id>": "analyst",
    "<Tawny viewers object id>": "viewer"
  }
}
```

- `authority` is optional and defaults to `https://login.microsoftonline.com/<entra_tenant_id>/v2.0`. Leave it unset for Entra.
- `allowed_domains` limits sign-in to those email domains. An empty list allows any account in the directory.
- Leave `client_secret` out of a later `PUT` to keep the stored one. `GET /api/settings/oidc` never returns it, only `client_secret_set`.
- Changing the configuration clears the cached discovery document and keys.

Then sign out and use **Sign in with Microsoft Entra ID** with a test account in each group.

## Keep a break-glass admin

Entra ID can be unavailable, or misconfigured. Keep at least one admin who can sign in with a password:

1. The bootstrap admin is marked break-glass when it is created. To mark another, `PUT /api/users/{id}` with `{"break_glass": true}`. Only admins with a password can be marked.
2. Store the break-glass password offline, the way your organisation stores other emergency credentials.
3. To stop everyone else using passwords: `PUT /api/settings/tenant` with `{"password_login": "break_glass"}`. Tawny refuses this while no active break-glass admin with a password exists. Other users then get 403 from `POST /api/auth/login` and are told to use Entra ID.
4. To undo: `{"password_login": "all"}`.

Test the break-glass sign-in after any change, and after rotating the password.

## Rotate the client secret

1. In Entra, add a new client secret before the old one expires.
2. `PUT /api/settings/oidc` with the same settings and the new `client_secret`.
3. Sign in with Entra ID to check it.
4. Delete the old secret in Entra.

## Testing without Entra

`contract-tests/mock_oidc.py` is a small provider the contract suite starts on `127.0.0.1`. It makes an RSA key with `openssl genrsa` at start-up and deletes it on exit, serves discovery and JWKS, checks the client secret and PKCE verifier at the token endpoint, and signs RS256 ID tokens. The suite signs in through it and checks the group mapping, the `tid` and `oid` match, refusals for a missing group, a wrong domain, a wrong `nonce`, `aud`, `iss` or an expired token, a reused `state`, and the break-glass setting.

The server only talks to a plain `http://127.0.0.1` provider when `TAWNY_OIDC_ALLOW_LOOPBACK=1`. CI sets it for the contract job. Never set it in production.

## Troubleshooting

| Symptom | Check |
|---|---|
| "Entra ID sign-in is not configured." | `enabled` is true in `/api/settings/oidc` for this tenant, and the sign-in link has the right `?tenant=`. |
| "Entra ID discovery failed." | The server can reach `login.microsoftonline.com` over HTTPS, and `entra_tenant_id` is right. |
| "Entra ID token exchange failed." | The client secret has not expired, and the redirect URI in Entra matches `TAWNY_PUBLIC_URL` exactly. |
| "Entra ID token was not valid." | The server log line `oidc: id token refused: <reason>` names the failed check. `BadTenant` means the account is from another directory. Clock drift beyond 2 minutes gives `Expired` or `NotYetValid`. |
| "Your Entra ID groups do not grant access to Tawny." | The groups claim is configured with Group ID, the user is in a mapped group, and the object ids in `group_roles` are right. |
| "This account's domain is not allowed." | `allowed_domains`. |
