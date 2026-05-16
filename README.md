[![Licensed under the MIT License](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/report-uri/dbsc-php/blob/main/LICENSE)
[![PHP 8.1+](https://img.shields.io/badge/PHP-8.1+-green.svg)](https://php.net)

# dbsc-php
*A small, framework-agnostic PHP server library for Device Bound Session Credentials (DBSC).*

[DBSC](https://github.com/w3c/webappsec-dbsc) cryptographically binds an authenticated session to a hardware-backed device key (TPM / secure enclave). A stolen session cookie can no longer be replayed from another device: the short-lived bound cookie expires every few minutes and is only refreshable by signing a server challenge with a private key that never leaves the device.

It is pure HTTP headers — **no JavaScript, no frontend assets, no database tables required**. Non-DBSC browsers simply ignore the registration header and continue on normal cookie auth, so enabling it cannot lock anyone out.

This library is extracted from [Report URI](https://report-uri.com)'s production DBSC integration ([report-uri/passkeys-php](https://github.com/report-uri/passkeys-php) is its passkeys sibling). It carries the wire-protocol corrections that only surface when integrating against a real browser — see [Wire-protocol notes](#wire-protocol-notes).

## Design

- **Zero dependencies** beyond `ext-openssl` / `ext-json`. ~700 lines, auditable in one sitting.
- **Framework-agnostic.** The library never reads superglobals, sends a header, or sets a cookie. Every operation takes a `RequestContext` you build from your framework's request and returns a `DbscResponse` you apply to your framework's response.
- **Storage is yours.** You implement `StoreInterface` (Redis, a table, …). An `InMemoryStore` is bundled for tests and the demo.
- **The crypto is deliberately minimal** — ES256 only, signature + single-use challenge nonce. See the class docblock on `JwtVerifier` for why `iat`/`exp`/`iss`/`aud` are intentionally *not* checked.

## Installation

```bash
composer require report-uri/dbsc-php
```

Autoloads under PSR-4 as `ReportUri\Dbsc\`. The entry point is `ReportUri\Dbsc\DbscServer`.

```php
use ReportUri\Dbsc\{Config, DbscServer};

$dbsc = new DbscServer(new Config(cookieName: '__Host-myapp_dbsc'), $myStore);
```

## Flow

```
        BROWSER (DBSC-capable)              YOUR APP
   ----------------------------------------------------------------
   GET  /login  (full auth done) ----->  buildRegistrationHeaderResponse()
                                <-----   Secure-Session-Registration: (ES256); ...
   POST /dbsc/register (signed JWT) -->  register()
                                <-----   200 + Set-Cookie __Host-…_dbsc + Sec-Secure-Session-Id
                                          + session-instructions JSON
   ... every ~few minutes ...
   POST /dbsc/refresh (no body)  ----->  issueRefreshChallenge()
                                <-----   403 + Secure-Session-Challenge="…"; id="…"
   POST /dbsc/refresh (signed JWT) -->  refresh()
                                <-----   200 + rotated Set-Cookie + new challenge
   GET  /account (every request) ----->  enforcement gate (see below)
   GET  /logout                  ----->  revoke()
```

A complete reference front controller is in [`_test/server.php`](_test/server.php). DBSC is browser-native (no JS API to script), so exercise it with a DBSC-capable browser over HTTPS.

## Enforcement gate

The library exposes the primitives but does **not** run the gate itself — *where* you enforce depends on your routing. The recommended policy (also in `_test/server.php`):

```php
$binding = $dbsc->getBinding($ctx);

if ($binding === null) {
    // Never registered: unsupported browser, or not yet. Degrade to normal cookie auth.
    // (Do NOT block here — this is what makes locking out a Firefox user impossible.)
}

$mustCheck = $dbsc->isDocumentRequest($ctx) || !$dbsc->isWithinRegistrationGrace($binding);
if ($mustCheck && !$dbsc->boundCookieMatches($binding, $ctx)) {
    // Bound session, bad/absent device cookie -> revoke + log the user out, redirect to login.
    $resp = $dbsc->revoke($ctx, enforcementTerminated: true);
}
```

Enforce on document loads **and** on subresources past the registration grace — *not* document-only, which would let a stolen cookie exfiltrate via XHR within the cookie lifetime. Skip the gate on the `/dbsc/*` endpoints themselves.

## Storage

Key DBSC state by your **stable session id**, in a **dedicated key space** — never in a read-modify-written shared session blob.

> This is the one non-obvious correctness requirement. Report URI shipped DBSC with state in the PHP session blob; the post-login navigation races the `/dbsc/register` POST, both rewrite the whole blob last-writer-wins, the binding is clobbered, and enforcement silently no-ops — leaving exactly the stolen-cookie hole DBSC exists to close. `StoreInterface` documents the requirements; back it with Redis or a table keyed by session id.

Pending registrations expire on the challenge TTL; bindings expire with the session lifetime.

## Wire-protocol notes

Baked into this library from integration testing against real Chrome — change with care:

- **Registration is single-phase; refresh is two-phase** (403 + challenge, then 200). This is the opposite of how the spec reads at first glance.
- **No `Secure-Session-Challenge` on the registration response** — Chrome reports a Challenge Error. The first refresh-flow 403 issues the challenge; the binding seeds an internal one only to stay valid until then.
- **Both the cookie value and the challenge must rotate on every refresh.** Re-emitting the existing cookie value makes Chrome treat it as "no refresh happened" and terminate.
- **`Secure-Session-Challenge` must carry the `id` sf-parameter** naming the session.
- **`challengeTtl` must exceed `cookieMaxAge`** (the `Config` constructor enforces this) so a challenge the browser cached just before cookie expiry is still valid when it is used.
- **The bound cookie uses `__Host-`**, so `include_site` is `false` (no subdomain span).

## Tests

```bash
php _test/run-tests.php
```

A self-contained harness (no PHPUnit): it generates a real EC P-256 device key, builds the JWTs exactly as Chrome does, and drives the full register/refresh/enforce/revoke flow plus the attack cases (wrong device key, wrong/expired challenge, stale cookie, `alg=none`).

## License

MIT — see [LICENSE](LICENSE). © 2026 Report-URI Ltd.
