# Web variant checklist

Standards: OWASP ASVS v5.0.0 (level from `--level`), OWASP Top 10, OWASP API Security Top 10 (2023), WCAG 2.2 AA (2.1 AA minimum) + WAI-ARIA, Core Web Vitals & HTTP/TLS RFCs, ISO/IEC 25010, GDPR/CCPA/CPRA, SOC 2 / ISO 27001 (governance mapping), NIST SSDF, Clean Code.
Applies to server (Node/Express/Nest/Next API, Django/Flask/FastAPI, Rails, Spring, ASP.NET, Laravel, Go, etc.) and browser code (React/Vue/Angular/Svelte, templates). Identify the framework first and apply its secure defaults.

Level gating: **l1** = items marked (1). **l2** = (1)+(2). **l3** = all, including (3).

## A. Security & Auth/Crypto

**Access control (ASVS V8, A01, API1/3/5)**
- (1) Enumerate every route/handler/resolver/RPC (grep router definitions, controllers, `@app.route`, `app.get`, GraphQL resolvers, Next.js `app/**/route.ts`, `pages/api`, server actions). For each: is authentication enforced? is authorization enforced **at the handler/service**, not only in the UI or a client-side guard? Build a route -> authn -> authz table in your working notes; report gaps.
- (1) IDOR/BOLA: object fetched by client-supplied ID without ownership/tenant check (`findById(req.params.id)` with no `where userId`).
- (1) BFLA: admin/privileged functions reachable by normal roles; role from client-controlled field/header/JWT claim without server verification.
- (1) Mass assignment / BOPLA: `Model.create(req.body)`, `Object.assign(user, req.body)`, `**kwargs` into ORM, GraphQL input spreading; privileged fields (`role`, `isAdmin`, `balance`, `tenantId`).
- (2) Default-deny not used; deny-lists for authz; multi-tenant filter missing in some queries; GraphQL field-level authz and introspection/depth limits.
- (2) CSRF on cookie-authenticated state-changing routes (SameSite, anti-CSRF token, Origin check).

**Authentication & session (ASVS V6, V7, A07, API2)**
- (1) Password storage: plaintext/MD5/SHA1/unsalted SHA-256 -> require Argon2id/scrypt/bcrypt/PBKDF2 with proper params.
- (1) Login/reset/OTP flows: user enumeration, no rate limit/lockout, predictable or non-expiring reset tokens, token not single-use, reset link host from `Host` header, MFA bypass paths.
- (1) Session cookies: `HttpOnly`, `Secure`, `SameSite`, `__Host-` prefix where feasible; session rotation on login; invalidation on logout/password change; sane idle/absolute timeout (2).
- (1) Tokens/JWT (ASVS V9): `alg: none`/algorithm confusion, weak/hardcoded HMAC secret, missing `exp`/`aud`/`iss` validation, decode-without-verify, tokens in `localStorage` (note XSS coupling), long-lived access tokens, refresh token not rotated/revocable (2).
- (2) OAuth/OIDC (ASVS V10): missing/unchecked `state`/PKCE, open or wildcard `redirect_uri`, implicit flow, `nonce` unchecked, client secret in frontend, token audience not validated.
- (3) Step-up auth for sensitive actions; session binding; credential stuffing defenses.

**Injection & output encoding (ASVS V1, A05)**
- (1) SQL: string concatenation/template literals/f-strings in queries; raw ORM escape hatches (`$queryRawUnsafe`, `sequelize.query` with interpolation, `.extra()`, `text()` w/o binds). NoSQL: `$where`, operators from user JSON (`{"$ne":..}`), unsanitized object queries.
- (1) OS command: `exec`, `child_process`, `os.system`, `subprocess(shell=True)`, `Runtime.exec` with user input.
- (1) XSS: `dangerouslySetInnerHTML`, `v-html`, `[innerHTML]`, `bypassSecurityTrust*`, `innerHTML=`, `document.write`, `eval`/`new Function`, `setTimeout(string)`, unescaped template output (`|safe`, `{{{ }}}`, `<%- %>`, `th:utext`), `href`/`src` from user data (`javascript:` URLs), markdown rendered without sanitization (DOMPurify or equivalent).
- (2) SSTI (`render_template_string`, `Handlebars.compile(userInput)`, `eval` in templates), LDAP/XPath/header/CRLF injection, log injection, ReDoS-prone regex on user input, prototype pollution (`merge`/`set` on user objects, `__proto__`), XXE (XML parsers with external entities), open redirect (`res.redirect(req.query.next)`).
- (2) Path traversal / LFI: user input in `fs`/`open`/`sendFile`/`path.join` without normalization and base-dir check.

**SSRF (ASVS V1/V15, API7, A01 in 2025 list)**
- (1) Server-side fetch of user-supplied URL (`fetch`, `axios`, `requests`, `HttpClient`, webhooks, image/URL previews, PDF renderers, importers) without scheme/host allow-list, private/link-local/metadata-IP blocking (169.254.169.254), redirect control, DNS-rebinding consideration.

**Deserialization & unsafe parsing (ASVS V1/V15, A08)**
- (1) `pickle.loads`, `yaml.load` (non-safe), `ObjectInputStream`, `unserialize`, `node-serialize`, `BinaryFormatter`, `Marshal.load` on untrusted data.

**File handling (ASVS V5)**
- (1) Uploads: no size limit, extension/MIME trust from client only, no content sniffing, served from same origin with executable type, stored in web root, filename used in path, zip-slip, SVG with script, missing `Content-Disposition`/`X-Content-Type-Options`.

**Crypto & secrets (ASVS V11, V14, A04)**
- (1) Hardcoded secrets/keys/tokens (see base §7), secrets in client bundles (`NEXT_PUBLIC_*`, `VITE_*`, `REACT_APP_*` holding real secrets), `.env` committed.
- (1) Weak/broken primitives: MD5/SHA1 for security, DES/3DES/RC4/ECB, static IV/nonce reuse, `Math.random`/`random` for tokens, short keys, custom crypto, `rejectUnauthorized:false`/`verify=False`/`InsecureSkipVerify`.
- (2) Key management: keys in code/config, no rotation path, PII/sensitive data unencrypted at rest where policy demands (V14), sensitive data in URLs/GET params/caches (missing `Cache-Control: no-store`).

**Transport, headers, CORS (ASVS V3, V12, V13, A02)**
- (1) CORS: `Access-Control-Allow-Origin` reflected from `Origin` or `*` with credentials; `null` origin allowed; regex allowing suffix-match spoof.
- (1) CSP absent or `unsafe-inline`/`unsafe-eval`/wildcards on scripts (2); HSTS, `X-Content-Type-Options`, `frame-ancestors`/`X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy` (2); `helmet`/Django `SECURE_*`/Spring Security headers config.
- (1) Server/proxy config allows TLS < 1.2 or weak ciphers (nginx `ssl_protocols`, Node `minVersion`, ALB policy), no HTTP->HTTPS redirect, HSTS missing `max-age` >= 1 year / `includeSubDomains` (2).
- (2) Mixed content, http:// endpoints in prod config, third-party scripts without SRI (3), `postMessage` without origin check, `window.open` without `noopener`.

**API & resource consumption (ASVS V4, API4/6/9/10)**
- (1) No rate limiting/throttling on auth, OTP, password-reset, search, expensive endpoints, GraphQL batching/depth; no pagination caps; unbounded request body size.
- (2) Sensitive business flows (checkout, coupon redeem, signup bonus) lacking idempotency keys, replay protection, or anti-automation; unsafe consumption of third-party API responses (unvalidated); exposed Swagger/GraphQL playground/actuator/debug routes in prod; old API versions left reachable.

## B. Code Quality, Concurrency & Logic (ASVS V2, V15, A06, A10)

- (1) Business-logic flaws: client-trusted price/total/discount/quantity (negative or fractional), skipped workflow steps (pay -> ship without verifying payment state), unchecked state transitions, coupon/refund double-use, integer overflow/rounding in money (floats for currency).
- (1) Race conditions: check-then-act without transaction/lock (balance debit, inventory, one-time token redeem, unique constraint absent), non-atomic read-modify-write, double-submit; missing DB constraints; async handlers sharing mutable module state; missing `await` / unhandled promise rejections; TOCTOU on files.
- (1) Error handling: empty `catch`, `except: pass`, errors swallowed and request proceeds (fail-open authz/validation), stack traces/SQL errors returned to clients, inconsistent error shapes leaking internals.
- (2) Resource leaks: unclosed DB connections/streams/file handles, listeners/timers/subscriptions not cleaned (React `useEffect` without cleanup, event emitters), unbounded caches/queues/in-memory maps, N+1 queries on hot paths.
- (2) Validation: server-side validation absent (client-only), no schema validation (zod/joi/pydantic/Bean Validation) at trust boundary, type juggling/loose equality in auth comparisons, non-constant-time secret comparison.
- (2) Complexity/dead code: functions > ~80 lines or deeply nested security-critical logic, duplicated authz logic, unreachable branches, commented-out auth, TODO/FIXME on security paths, feature flags that disable checks.

## C. Dependencies, Config & Supply Chain (ASVS V13, V15, A02/A03, SSDF PW/PS/RV)

- (1) Read manifests + lockfiles (`package.json`, lockfile, `requirements.txt`/`poetry.lock`, `pom.xml`, `go.mod`, `Gemfile.lock`, `composer.lock`). Flag: no lockfile; floating `*`/`latest`/git/URL deps; abandoned or typosquat-looking packages; install scripts (`postinstall`) from unknown packages; known-EOL framework majors. Only name specific CVEs if you are certain; otherwise recommend running SCA (`npm audit`, `osv-scanner`, `pip-audit`).
- (1) Debug/dev flags in prod config: `DEBUG=True`, `NODE_ENV` not production, verbose error pages, source maps published, default credentials, admin panels, `app.use(cors())` open, permissive `ALLOWED_HOSTS=['*']`.
- (2) Docker/IaC/CI: container runs as root, `latest` base images, secrets in `ENV`/build args/layers, `.dockerignore` missing `.env`/`.git`, `0.0.0.0/0` security groups, public buckets, Terraform with plaintext secrets, GitHub Actions: `pull_request_target` with checkout of PR head, unpinned third-party actions (not SHA), `permissions: write-all`, secrets echoed, `curl | sh`.
- (2) Logging/auditability (ASVS V16, A09): no audit log for authn events/authz failures/admin actions/data export; logs include passwords, tokens, PII, full card numbers; no correlation IDs; user-controlled data unsanitized in logs; no alerting hooks.
- (3) Build provenance: lockfile integrity, signed commits/artifacts, SBOM generation, dependency pinning by hash, separate prod/CI credentials.

## D. Accessibility & Platform Compliance (WCAG 2.2 AA, code-level only)

Report only what is determinable from code/markup; visual contrast needs runtime check -> Needs Verification.
- (1) `<img>` without `alt` (or decorative without `alt=""`) SC 1.1.1; icon-only buttons/links without accessible name (`aria-label`) SC 4.1.2/2.4.4; form inputs without `<label>`/`aria-labelledby` SC 1.3.1/3.3.2.
- (1) Non-semantic interactive elements (`<div onClick>` without role/tabindex/key handlers) SC 2.1.1/4.1.2; `tabindex` > 0; `outline: none` without replacement SC 2.4.7 (2.4.11 focus not obscured in 2.2).
- (1) Keyboard operability: every interactive control reachable and operable by keyboard, no keyboard traps, skip-to-content link (SC 2.1.1/2.1.2/2.4.1); visible focus indicator on all focusable elements (SC 2.4.7).
- (1) Colour contrast: from CSS/theme tokens you can compute ratios; flag text pairs < 4.5:1 (normal) / 3:1 (large text, UI components, SC 1.4.3/1.4.11) as Confirmed only when both colors are static literals; dynamic/themed/image backgrounds -> Needs Verification.
- (1) WAI-ARIA: invalid/redundant roles, `aria-*` referencing missing IDs, `aria-hidden` on focusable elements, roles missing required states (`aria-expanded`, `aria-checked`), ARIA used where native HTML works (first rule of ARIA).
- Legal note: map WCAG failures to ADA / Section 508 / European Accessibility Act exposure in the finding's Impact.
- (2) Missing `lang` on `<html>` SC 3.1.1; heading order/landmarks SC 1.3.1/2.4.1; dialogs without focus trap/`aria-modal`/Escape handling; live regions for async status SC 4.1.3; autoplay media w/o controls SC 1.4.2; error identification/association (`aria-describedby`, `aria-invalid`) SC 3.3.1; pointer target size < 24px SC 2.5.8 (CSS evidence); drag-only interactions without alternative SC 2.5.7; `autocomplete` tokens on identity fields SC 1.3.5.
- (2) Viewport meta disabling zoom (`user-scalable=no`, `maximum-scale=1`) SC 1.4.4; text in images.
- Privacy compliance (code-level): cookies/trackers set before consent, third-party analytics SDKs loading unconditionally, PII sent to third parties (GDPR/CCPA hygiene; flag as Needs Verification if consent logic is external).

## E. Performance, SEO & Quality (Core Web Vitals, HTTP RFCs, ISO/IEC 25010)

Code shows causes, not measurements: report measured LCP/INP/CLS as Needs Verification (Lighthouse/CrUX/WebPageTest); report code causes as findings (Low/Medium).
- (2) **LCP causes:** hero image not preloaded or lazy-loaded above the fold (`loading="lazy"` on LCP image), no `fetchpriority="high"`, huge unoptimized images (no `srcset`/`sizes`, no WebP/AVIF), render-blocking CSS/JS in `<head>` without `defer`/`async`, webfont without `font-display`, client-only rendering of main content, large synchronous bundles (no code splitting).
- (2) **INP causes:** long synchronous handlers, heavy work on main thread (large JSON parse, sync loops), no debouncing on input handlers, excessive re-renders (missing memoization/keys, state too high in tree), third-party scripts loaded eagerly.
- (2) **CLS causes:** `<img>`/`<video>`/iframes without `width`/`height` or `aspect-ratio`, late-injected banners/ads without reserved space, font swap without metric overrides, animations on layout properties instead of `transform`.
- (2) **Transfer/caching:** no Brotli/Gzip config for text assets; static assets without long-lived `Cache-Control: immutable` + content-hashed filenames; HTML cached incorrectly (or sensitive pages cacheable, see V14); missing ETag/Last-Modified; no CDN; HTTP/1.1 only; unminified/unbundled JS/CSS; source maps public; duplicate dependencies bloating bundles.
- (2) **SEO & metadata (where public pages exist):** missing/duplicate `<title>` and `meta description`, no canonical `<link rel="canonical">`, unclean/parameterized URLs for content, missing `robots.txt`/sitemap (or `robots.txt` blocking prod / `noindex` left on in prod; or exposing sensitive paths), missing Open Graph/Twitter tags, missing structured data (JSON-LD) where relevant, client-rendered content invisible to crawlers (no SSR/SSG), broken heading hierarchy, soft-404 handling, `hreflang` errors, missing `lang`.
- (2) **Quality (ISO/IEC 25010):** reliability (no timeouts/retries/circuit-breakers on outbound calls, no graceful shutdown, no health endpoints), maintainability (test coverage of security-critical code absent, lint/type-check not enforced in CI), compatibility (browser support target undefined, polyfills missing), usability (no error/empty/loading states).
- (3) Performance budgets and monitoring absent from CI (Lighthouse CI, bundle-size limit).

## F. Privacy & Governance (GDPR, CCPA/CPRA, SOC 2, ISO/IEC 27001)

- (1) Analytics/ads/tracking scripts and cookies set before consent; no consent banner/CMP wiring in code; consent state not honored by server/tags; "reject" path missing (GDPR Art. 7, ePrivacy). External CMP config -> Needs Verification.
- (1) PII over-collection (fields not needed, logged, or sent to third parties), PII/tokens in URLs and analytics events, unencrypted PII at rest where code defines storage (GDPR Art. 5(1)(c), 32).
- (2) Data-subject rights absent in code: no account/data deletion or export endpoint, deletion that leaves copies in logs/caches/backups (GDPR Art. 15/17, CCPA delete/know); no opt-out of sale/share signal (GPC `Sec-GPC` header honored?) for CCPA/CPRA.
- (2) Retention: no TTL/purge jobs for logs, sessions, soft-deleted records; privacy-policy-listed processors not matching third-party scripts/SDKs (Needs Verification).
- (2) SOC 2 / ISO 27001 evidence hooks: audit logs for access/change, RBAC enforced and reviewable, secrets management, change management/CI approvals, dependency scanning in CI, backup/restore config, incident-logging. Report gaps as control-mapped Low/Medium; actual certification readiness is out of scope (Needs Verification).
- (3) Data-flow mapping: PII inventory, cross-border transfer paths (SCC/regions in cloud config), DPIA triggers (profiling, sensitive categories).

## Suggested grep seeds (confirm every hit by reading)

`eval\(|new Function|innerHTML|dangerouslySetInnerHTML|v-html|bypassSecurityTrust|exec\(|execSync|child_process|subprocess|os\.system|shell=True|pickle\.loads|yaml\.load\(|unserialize|\$queryRawUnsafe|\.raw\(|query\(.*\+|f".*SELECT|rejectUnauthorized|verify=False|InsecureSkipVerify|Access-Control-Allow-Origin|cors\(|jwt\.decode|algorithms|alg.*none|localStorage\.setItem|Math\.random|md5|sha1|createCipher\b|DEBUG\s*=\s*True|password\s*=\s*["']|secret|api[_-]?key|BEGIN .*PRIVATE KEY|req\.body\)|Object\.assign\(|__proto__|redirect\(.*req\.|fetch\(.*req\.|axios.*req\.|sendFile|path\.join\(.*req`
