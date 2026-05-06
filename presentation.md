# Authentication Methods — Passwords, MFA, Passkeys & WebAuthn

**Establishing who the user is, before any authorisation happens.**

*The complement to the OAuth/OIDC series: how the user actually proves they are the user.*

```
know + have + are -> phishing-resistant
```

Hash · Verify · Strengthen · Replace

---

## Table of Contents

1. [Topics](#slide-01--topics)
2. [AuthN vs AuthZ — Where This Deck Sits](#slide-02--authn-vs-authz--where-this-deck-sits)
3. [Password Hashing](#slide-03--password-hashing)
4. [Password Policy — What Actually Helps](#slide-04--password-policy--what-actually-helps)
5. [Rate-Limiting, Lockout & Credential Stuffing](#slide-05--rate-limiting-lockout--credential-stuffing)
6. [The Three Factor Classes](#slide-06--the-three-factor-classes)
7. [TOTP & HOTP](#slide-07--totp--hotp)
8. [SMS, Email & Push](#slide-08--sms-email--push)
9. [WebAuthn / FIDO2 / Passkeys](#slide-09--webauthn--fido2--passkeys)
10. [Authenticator Types](#slide-10--authenticator-types)
11. [Discoverable Credentials & Conditional UI](#slide-11--discoverable-credentials--conditional-ui)
12. [Attestation, AAGUIDs & FIDO MDS](#slide-12--attestation-aaguids--fido-mds)
13. [Account Recovery — The Unsolved Problem](#slide-13--account-recovery--the-unsolved-problem)
14. [Risk-Based Auth, Step-Up & CAEP](#slide-14--risk-based-auth-step-up--caep)
15. [Anti-Bot & Abuse Detection](#slide-15--anti-bot--abuse-detection)
16. [Choosing a Stack](#slide-16--choosing-a-stack)
17. [Summary & References](#slide-17--summary--references)

---

## Slide 01 — Topics

### Passwords (and how to stop using them)
- Hashing — bcrypt, Argon2id, scrypt, PBKDF2
- Password policies that actually help
- Breach-detection (HIBP) and credential stuffing
- Account-lockout, rate-limiting, abuse signals

### Multi-factor authentication
- The three factor classes
- TOTP (RFC 6238) and HOTP (RFC 4226)
- SMS / email codes — and why they're the weakest
- Push, hardware OTP, smart cards

### Phishing-resistant — WebAuthn / FIDO2 / Passkeys
- Three names for the same thing
- Authenticator types — platform vs roaming
- Discoverable credentials & conditional UI
- Synced passkeys vs device-bound
- Attestation, AAGUIDs, FIDO MDS

### Operational
- Account recovery — the unsolved problem
- Risk-based / adaptive auth, step-up, CAEP
- Anti-bot & abuse detection
- Choosing a stack

---

## Slide 02 — AuthN vs AuthZ — Where This Deck Sits

OAuth/OIDC cover **authorisation** ("what may an app do on a user's behalf?") and **identity assertions** ("a JWT saying this is Alice"). Neither tells you *how* the user proved they were Alice in the first place. **That is this deck.**

```
[ User ] → [ Authentication: passwords / MFA / passkeys ]
                 │ proves identity
                 ▼
        [ Identity Tokens: OIDC ID, SAML ]
                 │ asserts identity to apps
                 ▼
        [ Authorisation: OAuth / RBAC / ABAC ]
```

"Sign in with Google" packages all three; in your own systems they are separate concerns with separate failure modes.

---

## Slide 03 — Password Hashing

If you ever store a password in plaintext, reverse-encrypted, or with a fast hash (MD5, SHA-256), you have lost. Use a **memory-hard** password-hashing function with a per-user salt and tuned cost.

| Function | Year | Type | Status 2026 | Why |
|---|---|---|---|---|
| MD5 / SHA-1 / SHA-256 (raw) | 1992+ | Fast hash | **Forbidden** | Crackable at billions/sec on a single GPU. |
| PBKDF2-HMAC-SHA256 | 2000 | Iterated hash | Acceptable for FIPS-only | CPU-only, GPU-friendly. ≥ 600k iterations (OWASP 2023). |
| bcrypt | 1999 | Adaptive | Acceptable | Memory-light (4 KB) — modern GPUs/FPGAs eat it. Cost ≥ 12. |
| scrypt | 2009 | Memory-hard | Acceptable | Memory ≥ 64 MB, parallelism 1 — niche. |
| **Argon2id** | 2015 | Memory-hard | **Recommended** (RFC 9106, PHC winner) | Tunable memory + parallelism + time. OWASP default: m=46 MiB, t=1, p=1. |

### Storage record (Argon2id)

```
$argon2id$v=19$m=47104,t=1,p=1$
   c2FsdHNhbHRzYWx0c2FsdA$
   QthRKhMKM7wG2pfjzvVXsBcEfBLk8qUZcM…
```

### Tuning

Pick parameters so a single hash takes **~250–500 ms** on production hardware. Update parameters as hardware improves; rehash on next successful login.

### Pepper if you can

Server-side secret (in HSM/KMS/Vault) HMAC'd onto the password before hashing. Stolen DB → attacker still needs the pepper. Trade-off: rotation needs rehash on login.

### Common mistakes

- Using `password.equals(stored)` — timing leak. Use constant-time compare.
- Truncating passwords. Allow ≥ 64 chars.
- Salting per-app instead of per-user.

---

## Slide 04 — Password Policy — What Actually Helps

NIST SP 800-63B (current) and BS 8484 agree on a much shorter list than the legacy "must contain a number, a symbol, the chief executive's mother's maiden name".

### Do

- Minimum length **8** for low-risk; **12+** for normal accounts; **15+** for admin.
- Allow length up to ≥ **64** characters; allow all printable Unicode + spaces.
- Block known-breached passwords (HIBP API; k-anonymity prefix lookup).
- Block trivial dictionary words and the username itself.
- Strength meter (`zxcvbn`) tied to the same logic the server uses.

### Don't

- Force scheduled rotation. Rotate on suspicion of compromise; otherwise leave alone.
- Force composition rules — they reduce entropy in practice.
- Block paste — that's how password managers work.
- Truncate or strip "special" characters silently.
- Send the password back via email "for confirmation".

### HIBP integration in five lines

```js
const sha = sha1(password).toUpperCase();
const prefix = sha.slice(0, 5);
const suffix = sha.slice(5);
const list = await fetch(
  `https://api.pwnedpasswords.com/range/${prefix}`).then(r => r.text());
if (list.split('\n').some(l => l.startsWith(suffix))) reject();
```

Server only ever sees the first 5 chars of a SHA-1 hash; API returns ~500 candidates; you check locally.

---

## Slide 05 — Rate-Limiting, Lockout & Credential Stuffing

The single most consequential authentication API is `/login`. Every credential-stuffing campaign first finds it.

### Three signals to rate-limit on

- **Per-account** — exponential back-off after N failures for the same username.
- **Per-IP** — caps brute-force from a single client. Easily defeated by botnets but raises cost.
- **Per-network / ASN** — catches botnets concentrated on a hosting provider.

### Lockout — the trade-off

- Soft lockout — auto-unlock after N minutes. Default for consumer apps.
- Hard lockout — admin re-enable. For high-value accounts; doubles as a self-serve DoS surface.
- Always notify the user *after* the fact, never block silently.

### Credential stuffing — what it actually looks like

- Attacker has a list of *(email, password)* pairs from another site's breach.
- Tries each one against your `/login` at low rate per IP, high diversity of IPs.
- Per-IP limits don't catch it. Per-account limits do — but only if you accept users locked out by accident.
- Best defence: HIBP-block known-breached passwords *at signup and at login*, plus risk-based MFA.

### Username enumeration

- "Wrong password" vs "user not found" leaks valid emails. Same string, same response time.
- Same on signup ("email already registered") — use a generic "we've sent you a link".
- Same on password-reset.

---

## Slide 06 — The Three Factor Classes

### Something you *know*
Password / passphrase / PIN / "security questions". Cheap, universal, **phishable**.

### Something you *have*
Phone (TOTP app, push, SMS) / hardware token (YubiKey, Titan, Feitian) / smart card / paper recovery codes. Adds a physical constraint. Susceptible to SIM-swap (SMS) and theft.

### Something you *are*
Fingerprint, face, voice, behavioural. Convenient, **not** a primary remote factor — biometric data leaks and you can't rotate your face. Used as a *local* unlock for a stronger factor.

### "MFA" really means "two factors from *different* classes"

Password + security questions = one factor (both "know"). Password + TOTP = two factors. Password + face-unlock-of-passkey = two factors (the face unlocks the *have*).

### NIST AAL ladder (SP 800-63B)

- **AAL1** — single factor. Passwords alone live here.
- **AAL2** — two factors, one cryptographic. TOTP / push / hardware token + password.
- **AAL3** — hardware-bound cryptographic authenticator + verifier impersonation resistance. **FIDO2 / PIV.**

---

## Slide 07 — TOTP & HOTP

**HOTP** (RFC 4226, 2005): HMAC-based one-time password from a counter.
**TOTP** (RFC 6238, 2011): use the current Unix time / 30 s window as the counter. The server and the app share a per-user secret only.

### The whole algorithm

```
function totp(secret, t = floor(time()/30)) {
  let h = hmac_sha1(secret, int_to_8bytes(t));
  let off = h[19] & 0x0f;
  let bin = ((h[off]&0x7f)<<24)|(h[off+1]<<16)|(h[off+2]<<8)|h[off+3];
  return (bin % 1_000_000).toString().padStart(6,'0');
}
```

Server checks current + previous + next windows for ~30 s clock skew tolerance.

### Enrolment QR

```
otpauth://totp/Acme:alice@example.com?
  secret=JBSWY3DPEHPK3PXP&issuer=Acme&algorithm=SHA1&digits=6&period=30
```

### Implementation notes

- 160-bit (20-byte) random secret.
- Encrypt at rest; treat as more sensitive than the password hash.
- Burn just-used codes (replay protection).
- Generate 10 single-use recovery codes at enrolment, stored hashed.

### Why TOTP is no longer enough on its own

- **Phishable** — a fake login site asks for the code, attacker forwards in 30 s.
- Modern phishing kits (EvilProxy, Tycoon) automate exactly this.
- Useful as a step *up* from password-only, but the future is FIDO2/passkeys.

---

## Slide 08 — SMS, Email & Push

### SMS one-time codes

- **SIM-swap** attacks shift the user's number.
- SS7 / SMS gateway interception is well-documented.
- Phishable identically to TOTP.
- NIST 800-63B-3 deprecated SMS in 2017.
- Still the most-deployed second factor in the world.

### Email magic links

- Strength = "control of the inbox" — usually one password away.
- Acceptable as *passwordless* first factor for low-stakes apps; not as MFA for anything serious.

### Push notifications

- App receives "did you just try to log in?".
- Better UX than typing a code.
- Vulnerable to **MFA fatigue** — bombard the user until they hit Approve.
- Mitigation: **number matching** — show a 2-digit code on the login page; user types it into the push.

### A reasonable 2026 ladder

1. **Passkey / FIDO2 hardware key** — phishing-resistant, gold standard.
2. **TOTP / push-with-number-matching** — when the user can't enrol a passkey.
3. **SMS** — last resort.

Always offer two methods so loss of one doesn't lock the user out (recovery codes count).

---

## Slide 09 — WebAuthn / FIDO2 / Passkeys

Three names, one thing.

### The vocabulary, untangled

- **FIDO2** = umbrella spec from the FIDO Alliance (since 2018).
- **WebAuthn** = the W3C browser API half of FIDO2.
- **CTAP2** = the FIDO protocol between the browser and the authenticator (USB / NFC / BLE).
- **Passkey** = marketing term (Apple/Google/Microsoft, 2022) for a FIDO2 credential that's *discoverable* and (usually) *synced*.

### Why it matters

- **Phishing-resistant by design** — authenticator only signs for the actual origin it was registered for.
- No shared secret to steal from your DB; you store only the user's *public* key.
- No code to type, no SMS to intercept.
- Cross-platform: same API on every modern browser.

### How the cryptography binds to the origin

```
# registration (one-off)
public_key, credential_id = authenticator.create({
  rp: { id: "acme.com", name: "Acme" },
  user: { id, name, displayName },
  challenge: random_bytes(32),
  pubKeyCredParams: [{type:"public-key", alg:-7}]
})

# login
signed = authenticator.get({
  rpId: "acme.com",
  challenge: random_bytes(32),
  allowCredentials: [{ id: credential_id }]
})
# server verifies: signature, origin = "https://acme.com",
#                  rpIdHash matches, sign_count increased
```

### The phishing-resistance proof

The `clientDataJSON` the authenticator signs over includes the *actual origin* of the page making the request. A phish at `acme.evil.com` can never produce a signature the real `acme.com` would accept.

---

## Slide 10 — Authenticator Types

|  | Platform | Roaming |
|---|---|---|
| What it is | Built into the device (Touch ID, Face ID, Windows Hello) | Plugged in / tapped (YubiKey, Titan, Feitian) |
| Transport | Internal — Secure Enclave, TPM, StrongBox | USB-A/C, NFC, BLE |
| User experience | Touch the sensor / look at the camera | Tap the key, enter PIN if set |
| Where the key lives | On *this* device only (or synced — see below) | On the physical token, never leaves |
| Best for | Everyday consumer login, low-friction MFA | High-assurance, shared devices, hardware-attested compliance |

### Synced passkeys

- Apple iCloud Keychain, Google Password Manager, 1Password, Bitwarden, Microsoft.
- Private key replicated, end-to-end encrypted with the user's account password / device PIN, across devices.
- Lose your phone? Sign in on a new one with iCloud / Google account, your passkeys are there.
- The *default* passkey type for consumer apps in 2026.

### Device-bound credentials

- Stay on a single device; cannot be exported.
- Hardware tokens are always device-bound.
- Required by some regulators (eIDAS High, FIDO L3, defence).
- Operationally heavier: every device needs its own enrolment.

### The synced-vs-bound debate

Consumer security: "synced is fine, the real risk is account takeover, and synced passkeys still beat passwords by an order of magnitude". Regulated security: "if it can leave the device, it doesn't satisfy hardware-bound assurance". *Both are right for their threat models.*

---

## Slide 11 — Discoverable Credentials & Conditional UI

### Discoverable credentials (a.k.a. resident keys)

- Old (non-discoverable): server hands the authenticator the *credential ID* first; user types a username.
- New (discoverable): the credential carries the *username* with it. Login page asks "any passkey for this site?".
- Enables *username-less* sign-in.

### Conditional UI (autofill)

```html
<input type="text" name="username"
       autocomplete="username webauthn">
```

```js
navigator.credentials.get({
  mediation: "conditional",
  publicKey: { challenge, rpId, userVerification: "preferred" }
});
```

Browser shows passkeys in the same dropdown as saved passwords. User taps one → done.

### A 2026-grade login UX

1. Page renders empty username field with `autocomplete="username webauthn"`.
2. Conditional `navigator.credentials.get()` fires in background.
3. If the user has a synced passkey for this site, it appears in the autofill bubble.
4. One tap (Touch ID / Face ID) and they're in. *No username, no password, no MFA prompt.*
5. If no passkey: form falls back to password + (TOTP / push) flow.

### Best practice

Always present passkey path *and* a fall-back. Don't force migration; nudge it: "We just signed you in with your password. Want to add a passkey for next time?"

---

## Slide 12 — Attestation, AAGUIDs & FIDO MDS

For regulated deployments you need to know *what kind of authenticator* the user enrolled.

### Attestation in one paragraph

During registration the authenticator can include a signed *attestation statement* proving its make/model. Attached is the **AAGUID** — a 128-bit identifier for the authenticator model.

```
{
  "fmt": "packed",
  "attStmt": { "alg": -7, "sig": "…", "x5c": ["MIIEx…device-cert"] },
  "authData": { "aaguid": "ee882879-…", "credentialPublicKey": … }
}
```

### The FIDO Metadata Service (MDS)

- FIDO Alliance publishes a signed JSON list of every certified authenticator AAGUID with its capabilities, certifications and revocation status.
- Lets you say *"only accept FIDO L2 hardware authenticators for admin enrolment"*.

### Attestation conveyance

| `attestation` | Meaning |
|---|---|
| `none` | RP doesn't want it; default for consumer apps. Privacy-preserving. |
| `indirect` | Browser may anonymise / batch-attest. |
| `direct` | Real attestation; required for regulated/enterprise enrolment. |
| `enterprise` | Per-device serial-number attestation; only for whitelisted RPs. |

### Privacy trade-off

Direct attestation can let the RP track *which physical YubiKey* the user used across services. Browsers may rewrite attestation to prevent this; consumer apps should just use `none`.

---

## Slide 13 — Account Recovery — The Unsolved Problem

The strongest authenticator in the world is undone by the recovery flow. *Whatever path the legitimate user takes when they lose access is the same path an attacker takes when they don't have any.*

### Common recovery paths, ranked by safety

1. **A second registered authenticator** — second YubiKey, second device's passkey.
2. **Single-use printed recovery codes**, generated at enrolment, stored offline.
3. **In-person verification** at a retail counter (banks). Slow, expensive, hard to phish.
4. Synced-credential recovery (iCloud / Google) — strong if the underlying account is locked down.
5. Email + previous-password challenge — moderate.
6. "Identity verification" (passport photo, selfie) — phishable; vendor-quality dependent.
7. Security questions — please no.

### Patterns that work in practice

- **Encourage two passkeys** at enrolment. Most users won't, but the prompt halves recovery volume.
- **Cool-down on recovery** — recovered accounts spend 24–72 h in a low-trust mode (no high-value actions, alerts to original email).
- **Notify aggressively** — recovery initiated, recovery completed, all to every channel on file.
- **Make the recovery path obvious** — hidden recovery becomes social-engineering scope for support staff.

### If you do nothing else

Decide upfront whether your security model is "we never recover an account, lost = lost" (e.g. crypto wallets) or "we always recover, with friction proportional to risk" (every consumer app). Trying to do both produces the worst of each.

---

## Slide 14 — Risk-Based Auth, Step-Up & CAEP

### Risk-based auth — the idea

Don't ask the user for MFA on every login. Score each session for risk and step up only when the score warrants.

- New device / fingerprint?
- New IP geolocation, ASN, or impossible-travel from the previous session?
- Time of day vs the user's pattern?
- Browser / OS user-agent shift?
- Logins for many distinct accounts from the same IP (credential stuffing)?
- HIBP-flagged password just attempted (yes, even if correct)?

### Step-up — what to ask for

- Low risk: nothing.
- Medium: extra factor for this session only.
- High: re-auth + email confirmation; lock account on second failure.

If you're using OIDC, request the step-up via `acr_values` + `prompt=login`; verify the returned `acr` and `amr`.

### CAEP & SSF — Continuous Access Evaluation

- **SSF** = Shared Signals Framework (OpenID Foundation): publish/subscribe channel for security events between IdPs and SPs.
- **CAEP** = SSF profile for "this user just changed their password / had their session revoked / failed step-up".
- Already deployed by Google, Microsoft, Okta, Cisco; growing in 2025–2026.

### Practical pattern

Subscribe high-value SaaS apps to the workforce IdP's CAEP stream. When the IdP sees a suspicious sign-in, fires `token-claims-change` or `session-revoked`; downstream apps drop the session within seconds, not hours.

---

## Slide 15 — Anti-Bot & Abuse Detection

Authentication endpoints are the primary surface for non-credential attacks: account creation abuse, scraping, low-and-slow stuffing.

### Tools that work

- **Privacy-preserving CAPTCHAs** — Cloudflare Turnstile, hCaptcha, reCAPTCHA Enterprise. Invisible by default.
- **Private Access Tokens** (Apple, Cloudflare, Fastly) — device attestation without per-site tracking.
- **Rate-limit at the edge** (Cloudflare, Akamai, Fastly) — drop the obvious botnet traffic before origin.
- **JS challenges** — cheap puzzles that headless browsers find expensive.

### Fingerprinting (with caution)

- Device fingerprint (canvas, WebGL, fonts, audio context) is useful for risk scoring but ages quickly and conflicts with privacy regulation.
- Browser-issued *device tokens* (FedCM, Private Access Tokens) are the privacy-preserving replacement.

### Don't

- Use IP address as a primary identity signal — mobile carriers, CGNAT, corporate VPNs make this unreliable.
- Block a country/region without an audited business reason — you'll quietly lock out diaspora users.
- Show a different page based on User-Agent — every scraper rotates UAs.

---

## Slide 16 — Choosing a Stack

| If you're... | Likely best | Why |
|---|---|---|
| A startup, B2C, want a passkey-first UX in two weeks | **Stytch / Clerk / Auth0** | Hosted passkey + magic-link + social out of the box; iterate on passkey UX faster than you will. |
| A B2B SaaS that needs to sell to enterprise | **WorkOS** + your own login UI | Adds SSO/SCIM the moment a big customer asks; passkeys for end users on top. |
| An enterprise with existing AD / Entra | **Microsoft Entra ID + Authenticator** | Conditional access policies, Authenticator app, FIDO2 keys all in one tenant. |
| Self-hosting, mature ops | **Keycloak** + WebAuthn extension, or **ZITADEL** | Full control; both ship modern WebAuthn / passkey support, FAPI-conformant. |
| A government / eIDAS-regulated portal | National eID + national IdP | End users already have the credential (BankID, eID card, EUDI Wallet); reuse, don't reissue. |
| A tiny internal tool / homelab | **Authelia** or **Authentik** + a hardware key | Light, OIDC-aware reverse-proxy auth; covers WebAuthn for everything behind the proxy. |
| A high-security workload, no off-the-shelf | Build on libraries: `passport-fido2-webauthn` · `SimpleWebAuthn` · `fido2-net-lib` · `webauthn-rs` | Each is well-maintained and conformant. Don't write the protocol yourself. |

---

## Slide 17 — Summary & References

### What we covered

- AuthN's place relative to OAuth/OIDC
- Password hashing (Argon2id default), peppering, common mistakes
- NIST 800-63B password policy — what to do, what to drop
- Rate-limiting, lockout trade-offs, credential stuffing, username enumeration
- Three factor classes and the AAL ladder
- TOTP/HOTP in detail; SMS / email / push pros and cons
- WebAuthn / FIDO2 / Passkeys — three names, one phishing-resistant primitive
- Platform vs roaming; synced vs device-bound
- Discoverable credentials + conditional UI = 2026 login UX
- Attestation, AAGUIDs, FIDO MDS
- Account recovery — patterns that work
- Risk-based auth, step-up, CAEP / SSF
- Anti-bot & abuse
- Build vs buy

### Three take-aways

1. **Argon2id with per-user salt + server pepper** is the only acceptable password storage in 2026.
2. **All non-WebAuthn second factors are phishable.** They're a step up from password-only, but the destination is FIDO2 / passkeys.
3. **Recovery is the security model.** Whatever the legitimate-user-who-lost-everything path is, that is also the attacker path.

### One-line takeaway

Stop treating "MFA" as the goal. The goal is *phishing-resistant authentication*; passkeys are the realistic path there for the next decade.

### References

NIST SP 800-63B-3 · OWASP ASVS v4 §2 · OWASP Password Storage Cheat Sheet · RFC 9106 (Argon2) · RFC 4226 (HOTP) · RFC 6238 (TOTP) · W3C WebAuthn Level 3 · FIDO Alliance · FIDO Metadata Service v3 · haveibeenpwned.com / Pwned Passwords · OpenID SSF / CAEP · passkeys.dev
