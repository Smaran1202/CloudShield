# The login lock

This is a lock for showing the project. It is not a multi-user system. A server that holds your AWS
credentials should still not be exposed to the internet, with or without it.

It is off by default. With `AUTH_ENABLED` unset or false, the API and the dashboard work exactly as
before, with no login page.

## What it does

- One shared password for the **owner**, and an optional second password for a **viewer**. The
  person logging in picks the role and types the password for it.
- A login sets one cookie. It is `HttpOnly` (scripts on the page cannot read it), `SameSite=Strict`
  (the browser sends it only from the dashboard's own site), and `Secure` when `COOKIE_SECURE` is
  true. It holds a signed token with the role and the time it ends, nothing else.
- When the login is on, every `/api` route except `/api/health`, `/api/auth/login`,
  `/api/auth/logout` and `/api/auth/me` needs a valid session. Without one the API answers 401 and
  the dashboard shows the login page.
- The owner can do everything. A **viewer** may only read: any POST, PATCH or DELETE (scans, fixes,
  imports, dismissals) answers 403 "Viewing only." In the dashboard those controls are disabled
  for a viewer, with the tooltip "Viewing only".
- The interactive API docs (`/docs`, `/redoc`, `/openapi.json`) are switched off while the login
  is on, because they list every route.
- A wrong login always gives the same message ("The role or password is wrong.") and status, for
  either role. After 5 wrong tries from one address in 5 minutes the API answers 429 and says how
  many seconds to wait; a right password does not get in during that wait.
- Passwords are never stored or logged. Only a salted scrypt hash is kept, compared in constant
  time. Tokens, cookies and passwords are not written to any log.

## What it does not do

- There is one account for each role. There is no sign-up, no list of users, no per-user data and
  no audit of who did what.
- There is no password reset. To change a password, make a new hash and restart the server.
- Logging out clears the cookie in that browser. A token that was copied before stays valid until
  it ends (`SESSION_HOURS`), because the server keeps no list of sessions. Change `SESSION_SECRET`
  to end every session at once.
- The rate limit lives in the memory of one server process and counts by client address. Run one
  API process.
- It protects the CloudShield API. It does not protect the machine, the database file, your `.env`
  or your AWS credentials.
- Over plain HTTP anyone on the network can read the password and the cookie. When the dashboard is
  served over HTTPS, set `COOKIE_SECURE=true`. Never expose the plain HTTP server.

## Settings

Set these in `.env` (names are in `.env.example`) or in the environment of the server.

| Name | Meaning |
| --- | --- |
| `AUTH_ENABLED` | `true` turns the login on. Default false. |
| `OWNER_PASSWORD_HASH` | The owner's hash (below). Required when the login is on. |
| `VIEWER_PASSWORD_HASH` | The viewer's hash. Optional. Without it nobody can log in as a viewer. |
| `SESSION_SECRET` | Random, at least 32 bytes. Signs the cookie. Required when the login is on. |
| `SESSION_HOURS` | How long a login lasts. Default 8. Between 1 and 168. |
| `COOKIE_SECURE` | `true` when the dashboard is served over HTTPS. Default false. |
| `TRUST_FORWARDED_FOR` | `true` only behind a reverse proxy that you run. The rate limit then uses the last address in `X-Forwarded-For`. Default false. |

With the login on, the server refuses to start, with a plain message, if the owner hash or the
secret is missing, is in the wrong format, or is too weak. The message never shows the value.

## Make the hashes and the secret

In PowerShell, from the repository root, with the virtual environment active:

```powershell
python -m cloudshield.auth hash-password
python -m cloudshield.auth secret
```

`hash-password` asks for the password twice without showing it (at least 12 characters) and prints
one line: the hash. `secret` prints a random value. Copy each line into `.env`:

```
AUTH_ENABLED=true
OWNER_PASSWORD_HASH=<the line from hash-password>
VIEWER_PASSWORD_HASH=<a hash of a different password, or leave it out>
SESSION_SECRET=<the line from secret>
```

No quotes are needed. Use different passwords for the two roles, and run `hash-password` once for
each. The hash looks like `scrypt:32768:8:1:<salt>:<key>`: the scrypt cost settings, then the salt
and the key in URL-safe base64. The cost settings are stored with the hash, so they can be raised
later. Treat the hash as a secret too: it can be attacked offline.

## The dashboard and the API are different origins

The dashboard (`http://localhost:5173`) and the API (`http://localhost:8000` by default) have
different ports, so the browser treats them as different origins. For the cookie to work:

- The API allows credentials for the one address in `FRONTEND_ORIGIN`, never for every origin.
- The dashboard sends the cookie with every request (`credentials: "include"` in `web/src/api.ts`).
- The dashboard has no proxy: it calls the API address in `VITE_API_URL`, which defaults to
  `http://localhost:8000`. The cookie is `SameSite=Strict`, and a port does not change the
  "site", so `localhost:5173` and `localhost:8000` count as the same site.
- **Use `localhost` for both.** `http://127.0.0.1:8000` with a dashboard at `localhost:5173` are
  different sites, and the browser will not send a Strict cookie, so every login would appear to
  fail. The same holds when hosted: put the dashboard and the API under the same domain, for
  example `app.example.com` and `api.example.com`.
- The existing check that refuses a POST, PATCH or DELETE from another origin stays on. It also
  covers the login.

## Test it

- `pytest -q` covers the login, the roles, the rate limit, the tokens, the cookie flags, CORS and
  the settings checks.
- `npm test` in `web/` covers the login page, the redirect on a 401 and the viewer's disabled
  controls.
- `npm run e2e:auth` in `web/` starts its own API with the login on, a throwaway database with one
  made-up finding, and made-up passwords, then logs in as a viewer in your installed Chrome or
  Edge. It checks that the action controls are disabled and that no request except the login and
  logout is a write. It calls no AWS, Gemini or Docker.
