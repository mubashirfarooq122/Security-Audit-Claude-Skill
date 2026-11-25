# Base reference: shared audit rules

## 1. Pillars (audit all four)

1. **Security & Auth/Crypto**: injection, broken access control / IDOR / BOLA / BFLA, authn/session/token flaws, SSRF, insecure deserialization, hardcoded secrets, weak crypto, unsafe network/TLS config.
2. **Code Quality, Concurrency & Logic**: business-logic flaws (price/quantity tampering, workflow skipping, replay, missing idempotency), race conditions/TOCTOU/state desync, swallowed exceptions and fail-open error handling, resource/memory/handle leaks, high cyclomatic complexity, dead code, misleading comments.
3. **Dependencies, Config & Supply Chain**: outdated or risky dependencies (judge from manifests/lockfiles only; do not invent CVEs), unpinned or unverified build steps, insecure CI/IaC/Docker config, debug flags enabled, missing logging/auditability, secrets in repo.
4. **Accessibility & Platform Compliance**: semantic/a11y attributes in code, manifest/privacy/permission hygiene, store-policy requirements.

## 2. Evidence gate (every Confirmed finding must pass all five)

1. **Location**: exact `path:line` (or `path:startLine-endLine`), or exact config/manifest/build key (e.g. `AndroidManifest.xml: <activity android:name=".Pay" android:exported="true">`). Lines come from a Read/Grep output in this session.
2. **Trace**: the code path from attacker/user-controlled input (or failure trigger) to the unsafe sink/outcome, stated in 1-3 sentences, with checks you verified are absent.
3. **Impact**: concrete exploitability or failure mode: who can do what, with what precondition, result. No generic "could lead to compromise".
4. **Fix**: minimal, idiomatic patch in the project's language/framework/style, as a unified diff or before/after snippet. Must compile logically against the surrounding code you read.
5. **Standard ref**: at least one control ID (see section 5). Add CWE where clear.

Fail any item -> not Confirmed. Reclassify as Needs Verification (with what is missing) or drop.

## 3. Triage classes

| Class | Definition | Examples |
|---|---|---|
| **Confirmed** | Verified in the code you read; no mitigation on the path | Raw SQL concatenating `req.query.id`; `exported="true"` activity with no permission that acts on intent extras |
| **Needs Runtime/Dynamic Verification** | Plausible but depends on something not visible: server-side middleware outside scope, infra/WAF/CDN config, runtime behavior, pinning bypass, Frida/MASTG tests, live API behavior, secrets-manager contents | Client calls `/orders/{id}` but server authz not in repo; cert pinning present but bypass untested |
| **Out of Scope / N/A** | Not applicable to this stack or excluded by target; list briefly with reason | No WebView in app -> WebView checks N/A; generated code; test fixtures |

**False-positive discipline**
- Ignore by default: `node_modules/`, `vendor/`, `Pods/`, `Carthage/`, `build/`, `dist/`, `.gradle/`, `DerivedData/`, generated code (`*.g.dart`, `*_pb.*`, `R.java`, `BuildConfig.java`), minified bundles, lockfile contents beyond version review. Only audit tests/fixtures for leaked real secrets.
- Test/mock/sample credentials clearly marked (e.g. `example`, `changeme`, in `test/`) -> Info at most, unless they match a real provider key format *and* appear in prod config.
- Check framework defaults before flagging (e.g. React escapes by default; Django ORM parameterizes; ATS is on by default in iOS; Android `exported` defaults depend on intent-filter presence and targetSdk).
- Check build variants: `debug`-only config (debuggable, cleartext, logging) is lower severity than `release`/main config. State which variant is affected.
- Do not flag style preferences as defects. Quality findings need a demonstrable failure mode or maintainability cost.
- If you are < 80% sure after reading the code, it is Needs Verification, not Confirmed.

## 4. Severity model

| Severity | Criteria |
|---|---|
| **Critical** | Remote/unauthenticated or low-privilege exploit giving account takeover, RCE, mass data exposure, or auth bypass; live production secrets committed |
| **High** | Exploit needs a precondition (authenticated user, victim interaction, local app on device) but yields significant data/privilege compromise; broken access control on sensitive objects |
| **Medium** | Meaningful weakness with limited blast radius or needing chained conditions; missing defense-in-depth on sensitive flows; reliability bugs causing data loss/crash under realistic use |
| **Low** | Hardening gaps, minor leaks, maintainability issues with a real but small cost |
| **Info** | Observations, positive notes, best-practice suggestions, N/A notes |

State likelihood x impact in one line when assigning Critical/High. Do not inflate; a pile of Lows is not a High.

## 5. Standards, cite only IDs you are confident of

- **OWASP ASVS v5.0.0**: IDs `v5.0.0-<chapter>.<section>.<req>` (e.g. `v5.0.0-8.2.1`). Chapters: V1 Encoding & Sanitization, V2 Validation & Business Logic, V3 Web Frontend Security, V4 API & Web Service, V5 File Handling, V6 Authentication, V7 Session Management, V8 Authorization, V9 Self-contained Tokens, V10 OAuth & OIDC, V11 Cryptography, V12 Secure Communication, V13 Configuration, V14 Data Protection, V15 Secure Coding & Architecture, V16 Security Logging & Error Handling, V17 WebRTC. If you cannot recall the exact requirement number, cite `ASVS v5.0.0 V8 (Authorization)` and add `(req ID unverified)`.
- **OWASP Top 10**: cite with year, e.g. `A01:2025 Broken Access Control` (2021 edition acceptable if the user's org uses it; be consistent within a report).
- **OWASP API Security Top 10 (2023)**: API1 BOLA, API2 Broken Authentication, API3 Broken Object Property Level Authorization, API4 Unrestricted Resource Consumption, API5 BFLA, API6 Unrestricted Access to Sensitive Business Flows, API7 SSRF, API8 Security Misconfiguration, API9 Improper Inventory Management, API10 Unsafe Consumption of APIs.
- **OWASP MASVS v2**: `MASVS-STORAGE-1/2`, `MASVS-CRYPTO-1/2`, `MASVS-AUTH-1/2/3`, `MASVS-NETWORK-1/2`, `MASVS-PLATFORM-1/2/3`, `MASVS-CODE-1/2/3/4`, `MASVS-RESILIENCE-1/2/3/4`, `MASVS-PRIVACY-1/2/3/4`. Pair with a MASTG test/technique ID only if certain (e.g. `MASTG-TEST-02xx`); otherwise name the MASTG area ("MASTG: Testing Local Storage").
- **OWASP Mobile Top 10 (2024)**: M1 Improper Credential Usage, M2 Inadequate Supply Chain Security, M3 Insecure Authentication/Authorization, M4 Insufficient Input/Output Validation, M5 Insecure Communication, M6 Inadequate Privacy Controls, M7 Insufficient Binary Protections, M8 Security Misconfiguration, M9 Insecure Data Storage, M10 Insufficient Cryptography.
- **WCAG 2.2** (2.1 where noted): cite success criterion e.g. `WCAG 2.2 SC 1.1.1`.
- **NIST SSDF (SP 800-218)**: `PW.x`, `PS.x`, `RV.x`, `PO.x` practice IDs.
- **CWE**: add where clear (e.g. CWE-89). Never guess a CWE number.
- **Quality**: no formal ID: cite principle (e.g. `Clean Code: error handling`, `CERT`/`Effective Java`/`Kotlin coding conventions`/`Swift API Design Guidelines`).

## 6. Level semantics (`--level`)

- **l1** (baseline): high-confidence, commonly-exploited issues; every Critical/High; skip exhaustive hardening.
- **l2** (default, standard apps handling sensitive data): l1 + full checklist of the variant file, defense-in-depth, logging, config hygiene.
- **l3** (high assurance: finance, health, critical infra): l2 + architecture/trust-boundary review, crypto key-lifecycle, anti-tamper/resilience (mobile), exhaustive authorization matrix, supply-chain integrity (pinning, provenance, signing).
Report the level used and which checks were gated to higher levels but skipped.

## 7. Secrets handling

Detect: private keys (`-----BEGIN ... PRIVATE KEY-----`), `AKIA…`, `AIza…`, `sk_live_`, `ghp_`, `xox[bp]-`, JWT-looking strings, DB URLs with passwords, `password`/`secret`/`apikey`/`token` assignments to string literals, Firebase/Google service files, keystores (`*.jks`, `*.keystore`, `*.p12`), `.env` committed. Mask values in the report (`AKIA…`, 4 chars max). Recommend rotation, not just removal (git history retains it; check `git log` only for presence, not contents).

## 8. Report format (strict)

Begin with one line: `Code audit: <variant>, level <l1|l2|l3>, scope <path/scope>, <N files read>`.

### 8.1 Executive Summary & Risk Posture
- 3-6 sentence overall posture (plain language: what is the single biggest risk, what is solid).
- Counts table (Confirmed only; Needs Verification counted separately):

| Critical | High | Medium | Low | Info | Needs Verification |
|---|---|---|---|---|---|
| n | n | n | n | n | n |

- Overall risk rating: Critical / High / Medium / Low, with one-sentence justification.
- Scope: in / out / limitations (what you could not see).

### 8.2 Findings Table
One row per finding, sorted by severity then ID. IDs: `CA-<WEB|AND|IOS>-<NNN>` (e.g. `CA-WEB-001`).

| ID | Severity | Variant / Category | Location (`file:line`) | Standard Ref | Summary |
|---|---|---|---|---|---|

Category = pillar tag: `Security`, `Quality`, `Supply-Chain/Config`, `A11y/Compliance`. Add a second table, same columns, for **Needs Runtime/Dynamic Verification** items (IDs `CA-…-NNN-V`), and a short bullet list for **Out of Scope / N/A**.

### 8.3 Detailed Findings & Code Fixes
For each Confirmed finding (Critical first):

```
#### CA-WEB-001 | <Severity> | <Title>
- Location: path:line[, path:line...]
- Standard: <IDs>
- Root cause: <why the code is wrong, source -> sink trace; what check is missing>
- Impact: <who can do what under which precondition; concrete result>
- Evidence: <5-10 line excerpt of the offending code, secrets masked>
- Fix (patch):
  ```diff
  - old
  + new
  ```
- Notes: <side effects of fix, test to add, related instances>
```
Group Low/Info findings compactly (location, one-line issue, one-line fix) if there are many.

### 8.4 Verification & Next Steps
- **Dynamic/runtime checks required**: per Needs-Verification item: exact test to run (e.g. "Send request as user B to `/api/orders/<A's id>`; expect 403", "MASTG: attempt Frida hook of pinning check", "run `adb shell am start -n …` against exported activity").
- **Standards verification**: which ASVS/MASVS sections were fully covered, partially covered, or not assessed at the chosen level.
- **Recommended tooling** (do not run): SAST/SCA/secret scanners/linters relevant to the stack (e.g. Semgrep, `npm audit`/`osv-scanner`, gitleaks, Android Lint/`apkleaks`, MobSF, SwiftLint).
- **Prioritized remediation order** (top 5) and suggested regression tests.
- **Limitations**: files unread, generated code skipped, server code absent, etc.
