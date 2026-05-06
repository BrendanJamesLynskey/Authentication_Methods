# 🛂 Authentication Methods — Passwords, MFA, Passkeys & WebAuthn

An interactive Reveal.js presentation covering **how the user actually proves they are the user** — the AuthN half of the Identity & Access series. Password hashing, MFA factors, TOTP/HOTP, the SMS/email/push trade-offs, and the WebAuthn / FIDO2 / Passkeys stack.

## ▶ [Open the Presentation](https://brendanjameslynskey.github.io/Authentication_Methods/)

## 📄 [Markdown Version](presentation.md)

## 📚 Companion decks — [OAuth Primer](https://brendanjameslynskey.github.io/OAuth_Primer/) · [Introduction to OpenID Connect](https://brendanjameslynskey.github.io/Introduction_to_OpenID_Connect/) · [Authorization Models](https://brendanjameslynskey.github.io/Authorization_Models/)

---

## Contents

| # | Topic | Description |
|---|-------|-------------|
| 01 | Title | Hash → Verify → Strengthen → Replace |
| 02 | Topics | Map of passwords, MFA, passkeys, operational |
| 03 | AuthN vs AuthZ | Where this deck sits relative to the OAuth/OIDC series |
| 04 | Password Hashing | bcrypt / Argon2id / scrypt / PBKDF2 — and why never raw SHA-256 |
| 05 | Password Policy | NIST 800-63B "do" and "don't"; the HIBP integration in five lines |
| 06 | Rate-Limiting & Lockout | Per-account / per-IP / per-ASN, credential-stuffing, enumeration |
| 07 | The Three Factor Classes | know / have / are; AAL1–3 |
| 08 | TOTP & HOTP | The whole RFC 6238 algorithm, the otpauth URI, why TOTP is no longer enough |
| 09 | SMS, Email, Push | The weakest "strong" factors; MFA fatigue and number matching |
| 10 | WebAuthn / FIDO2 / Passkeys | Three names, one phishing-resistant primitive |
| 11 | Authenticator Types | Platform vs roaming; synced vs device-bound |
| 12 | Discoverable Credentials & Conditional UI | The 2026 username-less login UX |
| 13 | Attestation, AAGUIDs & FIDO MDS | Knowing what kind of authenticator the user enrolled |
| 14 | Account Recovery | Recovery patterns ranked; the "recovery is the security model" rule |
| 15 | Risk-Based Auth & CAEP | Adaptive authentication and Continuous Access Evaluation |
| 16 | Anti-Bot & Abuse | Privacy-preserving CAPTCHAs, Private Access Tokens, fingerprinting |
| 17 | Build vs Buy | Choosing a stack by use-case |
| 18 | Summary | Take-aways and references |

---

## Slide Controls

| Action | Key |
|--------|-----|
| Next / Previous | `→` `←` or swipe |
| Overview | `Esc` |
| Fullscreen | `F` |
| Export to PDF | Append `?print-pdf` to URL, then print |

## Technology

[Reveal.js 4.6](https://revealjs.com) · [highlight.js](https://highlightjs.org) · Playfair Display + DM Sans + JetBrains Mono · inline SVG diagrams.

Single self-contained `index.html` — no build step, no npm, no dependencies to install.

## See also

- [OAuth — A Gentle Primer](https://github.com/BrendanJamesLynskey/OAuth_Primer) · [Introduction to OAuth](https://github.com/BrendanJamesLynskey/Introduction_to_OAuth) · [OAuth for MCP Servers](https://github.com/BrendanJamesLynskey/OAuth_for_MCP)
- [Introduction to OpenID Connect](https://github.com/BrendanJamesLynskey/Introduction_to_OpenID_Connect) · [Advanced OpenID Connect](https://github.com/BrendanJamesLynskey/Advanced_OpenID_Connect)
- [SAML 2.0 & SCIM](https://github.com/BrendanJamesLynskey/SAML_and_SCIM) — the parallel enterprise stack.
- [Authorization Models](https://github.com/BrendanJamesLynskey/Authorization_Models) — what to do *after* the user is authenticated.

## References

NIST SP 800-63B-3 · OWASP ASVS v4 · OWASP Password Storage Cheat Sheet · RFC 9106 (Argon2) · RFC 4226 (HOTP) · RFC 6238 (TOTP) · W3C WebAuthn Level 3 · FIDO Alliance · FIDO Metadata Service v3 · haveibeenpwned.com / Pwned Passwords API · OpenID SSF / CAEP · passkeys.dev

## License

Educational use. Code examples provided as-is.
