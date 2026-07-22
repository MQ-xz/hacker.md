---
name: "secure-code-review"
description: >
  Perform an exhaustive, adversarial security analysis across any codebase in any language
  or framework — identifying, validating, and chaining exploitable vulnerabilities with full
  PoC fidelity. Covers all OWASP Top 10 (2021), OWASP API Security Top 10 (2023), OWASP LLM
  Top 10, OWASP Mobile Top 10, and all 12 MITRE ATT&CK Enterprise tactics (Initial Access
  through Impact). Produces structured reports with CVSS v3.1 scores, ATT&CK technique IDs,
  exploit chains, and actionable remediation with corrected code. Works on any stack: Python,
  Node, Go, Java, PHP, Ruby, .NET, Rust, C/C++, mobile, serverless, or polyglot. Trigger
  whenever the user shares code for review, requests a security audit, pentest, vulnerability
  assessment, or mentions any security concern — even casually. Trigger on: "is this safe?",
  "review my auth", "find bugs", "pentest this", "security review", "CVE", "injection",
  "SSRF", "XSS", "RCE", or any code paste with a security question. When in doubt, trigger.
compatibility:
  tools:
    required: [filesystem_read, bash]
    optional: [git_history, runtime_environment, network_request]
  context:
    required: [repository_access]
    optional: [deployment_config, threat_model, prior_audit_reports]
---

# Secure Code Review — Universal Adversarial Pipeline v1

This is NOT a checklist. It is a layered adversarial analysis system where each phase feeds
the next. Think like a red team operator chaining vulnerabilities, not a scanner emitting CWEs.

**This skill is language-agnostic.** It applies to any repository in any stack.
Technology-specific patterns are loaded from reference files only after Phase 0 identifies
the stack — never assume framework-specific behavior before detection.

---

## ⚠ PRE-ANALYSIS: THREE-GATE VALIDATION PROTOCOL

Apply to EVERY candidate finding before reporting it:

**Gate 1 — Reachability:** Is this code path reachable from external input? Dead code,
CLI-only paths with no external input, and compile-time disabled blocks are not reportable
as High/Critical. Fail → Informational or remove.

**Gate 2 — Exploitability:** Can an attacker actually trigger this given auth requirements,
network access, and runtime preconditions? Document minimum privilege required.
Fail → Confidence: Theoretical; document blockers explicitly.

**Gate 3 — Impact Calibration:** What is the actual blast radius? Score CVSS against THIS
codebase, not a generic template or similar CVE.

| Result | Confidence Tier |
|---|---|
| Fails Gate 1 | Informational (or remove) |
| Passes Gate 1, fails Gate 2 | Theoretical — document what must be true |
| Passes 1+2 with static evidence | Likely — include partial PoC |
| Passes all gates with observable PoC | Confirmed |

---

## Operating Mode

State mode explicitly in the report header.

| Mode | Use When | Phases | Cap |
|---|---|---|---|
| **FULL AUDIT** | Complete repo, unconstrained | All 28 phases | None |
| **QUICK TRIAGE** | Time-boxed ≤60 min | 0,1,2,3,5,7,10,11,15 | Top 10 |
| **PR DIFF** | Reviewing a changeset | 0,2,3,5 (diff + callers) | None |
| **TARGETED** | Specific component or vuln class | 0,1 + relevant phases | None |

For partial modes: explicitly state skipped phases and their residual risk.

---

## Phase 0 — Calibration, Framework Mapping & Scope

### 0.1 Technology Detection & Reference Router

Identify: languages + versions (flag all EOL runtimes), frameworks, deployment model,
metaprogramming/reflection presence (downgrade confidence on affected flows).

**Load references based on detected stack:**

| Condition | Load |
|---|---|
| Always | `references/owasp-attack-framework.md` |
| Any language | `references/injection-taxonomy.md` (Phase 3), `references/crypto.md` (Phase 7) |
| Specific language detected | `references/language-specific.md` (Phase 8) — read only matching section |
| APIs present | `references/api-security.md` (Phase 9) |
| Browser/SPA/frontend | `references/client-side.md` (Phase 10) |
| Infrastructure/CI/cloud | `references/infra-supply-chain.md` (Phases 12–13) |
| LLM/RAG/agent code | `references/ai-llm.md` (Phase 14) |
| All findings | `references/reporting-template.md` (Phase 28) |

### 0.2 OWASP & ATT&CK Coverage Matrix

**→ Load `references/owasp-attack-framework.md`** and complete the Phase 0 coverage matrix.
Mark each OWASP category and ATT&CK tactic as ✓ Covered / ⚠ Partial / ✗ N/A / ? Runtime.
This matrix is the explicit contract for what this review assesses.

### 0.3 Threat Modeling (STRIDE)

| Component | Key Question | Finding |
|---|---|---|
| Spoofing | Can identity be forged? Which principals lack cryptographic proof? | |
| Tampering | What data flows are unsigned at rest or in transit? | |
| Repudiation | What critical actions lack audit trails? Can logs be injected or deleted? | |
| Info Disclosure | What surfaces in errors, logs, responses, URLs, timing side-channels? | |
| Denial of Service | What operations are unbounded in resource consumption? | |
| Elevation of Privilege | What paths allow lower-trust → higher-trust context? | |

### 0.4 Asset Classification

- **Tier 1 (Critical):** Auth tokens, PII/PHI/PCI data, signing secrets, encryption keys, admin functions
- **Tier 2 (High):** Business logic state, session data, internal APIs, audit logs, third-party credentials
- **Tier 3 (Medium):** Configuration, feature flags, non-sensitive user content
- **Tier 4 (Low):** Public static assets, cached non-sensitive responses

### 0.5 Attacker Personas

Define which are active for this codebase's deployment context:
- Unauthenticated external attacker (internet-facing endpoints)
- Authenticated low-privilege user (IDOR, priv-esc, business logic abuse)
- Authenticated high-privilege user (insider threat, admin abuse)
- Supply chain / CI attacker (poisoned dependency, workflow injection)
- AI/LLM adversarial user (prompt injection, indirect injection, agent manipulation)
- Mobile user (reverse engineering, traffic interception, local storage abuse)

### 0.6 Configuration Pre-Scan (Before Code Analysis)

**Read ALL configuration files first:** settings, middleware config, .env files, Docker Compose,
CI/CD YAML, cloud IaC, and any framework-level security configuration.

This step surfaces Critical platform-level failures (disabled CSRF, hardcoded secrets, debug
mode, dev server in production) before code-level analysis and prevents them from being buried
late in the report. Emit any findings immediately as candidates.

> **Output:** Stack inventory · Reference load plan · OWASP/ATT&CK coverage matrix · STRIDE table ·
> Active personas · Config pre-scan findings · Scoped phase plan

---

## Phase 1 — Attack Surface Mapping

### Enumerate ALL Ingestion Points (Do Not Limit to HTTP)

- HTTP: REST endpoints, GraphQL operations, WebSocket upgrades, SSE, multipart uploads
- RPC: gRPC services (all proto fields = untrusted), tRPC procedures, Thrift services
- CLI: argument parsers, stdin readers, environment variable injection points
- Async: message queue consumers (all MQ technologies), webhook receivers, event handlers, schedulers
- File: archive extraction pipelines, import/batch commands, file watchers, config loaders
- IPC: Unix sockets, named pipes, shared memory
- Browser: postMessage listeners, service workers, extension APIs, deeplink handlers
- Serverless: cloud event triggers, stream consumers, scheduled functions
- Mobile: activity intents, content providers, exported services, push notification handlers
- Admin: management commands that read external files, URLs, or environment data

### Build Three Artifacts

1. **Endpoint map:** route → handler → middleware chain → dependencies
2. **Data flow graph:** Source → Transformations → Sink per entry point
3. **Auth coverage matrix:** every endpoint × (required auth spec | enforced in code | gap)

The auth coverage matrix is the single most effective tool for finding broken access control
at scale. Generate it mechanically; verify each row in code — do not infer from patterns.

> **Output:** Entry point inventory · Data flow graph · Trust boundary map · **Auth coverage matrix with gaps**

---

## Phase 2 — Source → Sink Taint Analysis

### Sources — Universal (Not Language-Specific)

**Network (always untrusted):** All HTTP parameters, path segments, query strings, request
bodies (any encoding), ALL HTTP headers including non-standard:
X-Forwarded-For, X-Real-IP, X-Original-URL, X-Rewrite-URL, Host, Referer, Origin,
Content-Type, Accept, X-HTTP-Method-Override, X-Forwarded-Host, X-Forwarded-Proto,
cookies (value, name, domain, path attributes), WebSocket frames, gRPC fields + metadata,
GraphQL query/variables/operation name/extensions

**Async/Event:** Message queue payloads, webhook bodies, cloud event metadata,
scheduler parameters if externally configurable

**File/System:** Upload content + filename + MIME + Content-Disposition; environment
variables; CLI arguments; stdin; user-supplied or env-injectable config files

**Second-Order Sources (critical — most scanners miss these):**
- DB read-back of previously user-supplied data used in subsequent query construction
- Cache reads feeding downstream logic (cache can be poisoned)
- OAuth/OIDC token claims from external identity providers
- **LLM/AI model outputs** — always treat as untrusted input to downstream systems
- Third-party API responses incorporated into queries, templates, or other sinks
- Browser storage read by client-side code
- Session data (especially if serializer allows arbitrary object deserialization)

### Universal Sink Categories (→ Load `references/injection-taxonomy.md` for payloads)

| Sink Category | Technology-Neutral Patterns |
|---|---|
| Code execution | Dynamic eval, expression evaluators, template construction from strings, deserialization of untrusted bytes |
| Query execution | Any query built by string concatenation/interpolation; ORM raw/escape-hatch methods |
| OS execution | Shell command string construction; argument injection into system utilities |
| File system | Path construction from user input; archive extraction without path normalization |
| External requests | HTTP client calls where URL is user-influenced; DNS resolution of user-controlled hostnames |
| Rendering | HTML/Markdown/template rendering with user content; PDF generators; email body construction |
| Data exposure | Serialization including server-only fields; stack traces in responses; verbose error messages |

**Instance exhaustion rule:** When a vulnerable pattern is found (e.g., unsafe eval on DB values),
enumerate ALL call sites of that pattern across the entire codebase before moving on.
Never report only the first instance.

> **Output:** Verified taint flows with file:line refs · Sanitization gap analysis · Exploit paths ranked by sink severity

---

## Phase 3 — Injection Taxonomy [A03, T1190, T1059]

**→ Load `references/injection-taxonomy.md`**

Apply all injection classes regardless of detected language. The reference covers:
SQL (all variants including second-order), NoSQL, OS command, SSTI (per-engine payloads),
LDAP, XPath, XXE, Log4Shell-class, CRLF, CSV/formula, ReDoS, Host header injection,
open redirect, HTTP request smuggling, HTTP/2 (Rapid Reset, HPACK bomb), cache poisoning,
file upload (MIME bypass, Zip Slip, polyglots, SVG XSS, archive bombs), webhook security,
subdomain takeover.

---

## Phase 4 — Authentication & Session Security [A07, API2, T1078, T1606]

Technology-agnostic checks — apply the concept, not the framework-specific API:

- **Token security:** Algorithm confusion attacks, weak secrets, missing signature validation, expired token acceptance, token leakage in logs/Referer/redirect URLs
- **Session:** Serializer type (is arbitrary object deserialization possible?), secret exposure, fixation, insufficient entropy, missing expiry
- **Credential storage:** Passwords hashed with memory-hard function? API keys in source or committed config? MFA seeds committed?
- **SSO/Federation:** SAML: unsigned assertions, XML signature wrapping, ACS URL validation. OAuth: state CSRF, open redirect in redirect_uri
- **MFA:** Disabled via configuration flag? TOTP seeds in source? Backup code exposure?
- **Password reset:** Reset URL constructed from a user-controllable Host header?
- **Impersonation features:** Does target-user validation verify the TARGET is in the allowed set, not just that the requester has impersonation permission?
- **Rate limiting on auth endpoints:** Login, registration, OTP, password reset

---

## Phase 5 — Authorization & Access Control [A01, API1, API3, API5, T1068]

- **BOLA/IDOR:** Object IDs in path/body/query not validated against session ownership — test every object type
- **Mass assignment:** User body merged into server object including privileged fields (role, admin, balance, verified, is_staff)
- **Horizontal priv-esc:** Same-role access to another user's resources
- **Vertical priv-esc:** Low-privilege access to high-privilege functions
- **Function-level auth:** Middleware auth vs per-handler auth — verify the auth coverage matrix; look for overrides that bypass middleware (e.g., `check_permissions` returning True unconditionally)
- **Multi-tenancy:** Tenant context from authenticated session vs user-supplied parameter
- **Field-level auth:** Query/resolver/handler-level auth is not sufficient — field-level must be separately enforced
- **Header-based security controls:** Any control using Host, Referer, X-Forwarded-For, or other client-controlled headers as security boundary is broken by design

---

## Phase 6 — Business Logic & Workflow Abuse [A04, API6, T1078, T1499]

Model complete user flows:
- Step skipping: can state C be reached without A → B?
- Replay attacks: state-changing requests without idempotency keys
- Race conditions: check-then-act on shared mutable state (balance, coupon, quota, invite)
- Negative/overflow values: negative quantities or prices producing unintended credit
- Communication cost abuse: endpoints triggering email/SMS/voice/push with no auth or rate limiting
- Account enumeration: different timing or messages for valid vs invalid usernames
- Bulk operations without bounds: any endpoint accepting an unbounded list input
- Trust on client-controlled fields: prices, discounts, roles, flags sent from client

---

## Phase 7 — Cryptographic Security [A02, M10, T1552]

**→ Load `references/crypto.md`**

Universal checks:
- Algorithm selection: MD5/SHA1/DES/RC4/ECB → always Critical/High regardless of use case
- Password hashing: memory-hard function (bcrypt/scrypt/Argon2id) required — fast hash = always Critical
- IV/nonce management: static IV, counter wrap, GCM nonce reuse → always Critical
- PRNG: insecure random source for security tokens, session IDs, CSRF tokens → always High
- Timing-safe comparison: standard equality for HMAC/token comparison → timing oracle
- TLS: validation disabled, TLS 1.0/1.1, weak cipher suites → always Critical/High
- Key storage: keys hardcoded, in committed env files, in client-side bundles

---

## Phase 8 — Language & Runtime Vulnerabilities [T1059, T1203]

**→ Load `references/language-specific.md`** — read ONLY the section(s) for detected languages.

Covers 9 language families: C/C++, Go, Rust, JavaScript/TypeScript/Node.js, Python, PHP,
Java/JVM, Ruby, .NET/C#. After reading: apply all relevant language-specific deserialization,
type confusion, memory safety, concurrency, and eval patterns to the codebase.

---

## Phase 9 — Input Surface Expansion & API Security [API1-API10]

**→ Load `references/api-security.md`** (if APIs present)

Key expansion areas missed by basic scanning:
- **All HTTP headers** as injection vectors, not just body and query params
- **GraphQL:** introspection in production, depth/complexity attacks, alias batching for rate limit bypass, subscription auth gaps, field-level authorization
- **gRPC:** reflection API exposed, missing field validation (Protobuf enforces types, NOT ranges or business rules), metadata injection, stream token expiry not enforced
- **WebSocket:** auth only on handshake vs per-frame, message flooding, unbounded message size
- **REST version sprawl:** old versions lacking newer auth, rate limiting, and validation controls

---

## Phase 10 — Client-Side Security [A01, A05, T1203]

**→ Load `references/client-side.md`** (if browser/SPA/frontend code present)

- DOM-based XSS source → sink traces in client JavaScript
- CSP: unsafe-inline, unsafe-eval, wildcard domains, JSONP bypass, AngularJS CDN bypass
- Clickjacking: missing frame-ancestors on sensitive action pages
- postMessage: missing origin validation, wildcard targetOrigin on sensitive data
- Subresource Integrity: external scripts/styles without integrity hash
- Security header completeness: HSTS, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COEP/COOP/CORP
- CSP/XFO exemptions on embed or public endpoints weakening overall posture

---

## Phase 11 — Secrets & Sensitive Data Exposure [A02, T1552]

Scan ALL file types — not just source code:

- Source files: API keys, tokens, private keys, hardcoded passwords, connection strings
- **Framework settings files and all components thereof** (any settings/, config/, components/ directories)
- **Committed environment files** (.env, .env.local, .env.production, .env.test)
- Build files: Docker Compose, Makefile, build scripts with inline credentials
- CI/CD config: GitHub Actions workflows, GitLab CI, Jenkinsfile, CircleCI — secrets in run steps
- Client-side bundles: minified JS containing API keys or internal endpoints
- Mobile binaries (if present): hardcoded creds, internal URLs, private certs
- Git history: deleted secrets, old credential values, previous .env files
- **Disabled security features as configuration:** any boolean flag disabling auth, MFA, CSRF, rate limiting
- **PII/PHI in log statements:** credentials or personal data written to application logs

---

## Phase 12 — Configuration & Infrastructure [A05, API8, T1562]

**→ Load `references/infra-supply-chain.md`** (if infrastructure config present)

- Container: unpinned base images (supply chain risk), root user, secrets baked into layers
- Orchestration: wildcard RBAC, privileged containers, automounted service account tokens, host namespaces
- CI/CD: `pull_request_target` with checkout, script injection via workflow context variables, mutable action pins, overly broad OIDC trust, secrets echoed to logs
- Cloud IaC: public storage buckets, world-open firewall rules, IAM wildcards, public serverless functions without auth
- Debug config in production: debug mode, development servers, verbose error pages, development middleware
- CORS: wildcard origin on authenticated endpoints, credentials=true with wildcard
- Security headers: verify all required headers on all response types

---

## Phase 13 — Dependency & Supply Chain [A06, A08, T1195]

**→ Load `references/infra-supply-chain.md`** (supply chain section)

- Enumerate dependencies; identify known CVEs with ecosystem-appropriate tooling
- **Reachability filter (mandatory):** only report CVEs where the vulnerable function is reachable
- Dependency confusion risk: internal package names claimable on public registries
- Lockfile integrity: loose version constraints on security-sensitive packages
- Malicious package signals: install scripts, obfuscated entry points, typosquatting
- EOL / abandoned packages: no security advisory response, last commit > 2 years

---

## Phase 14 — AI & LLM Security [LLM01-LLM10, T1059]

**→ Load `references/ai-llm.md`** (if LLM/AI/RAG/agent code present)

- Direct and indirect prompt injection (external documents, emails, web content fed to LLM)
- RAG corpus poisoning and retrieval manipulation
- LLM output used as code/SQL/HTML sink without sanitization (LLM05)
- Secrets or PII in system prompts — they are extractable (LLM07)
- Agentic tool-call parameter injection, excessive agency without human approval gates (LLM06)
- LLM provider API key exposure; model selection injection
- Token budget DoS; unbounded agent recursion (LLM10)

---

## Phase 15 — Logging, Monitoring & Observability [A09, T1070, T1562]

**Audit logging completeness:**
- Auth events (success/failure) logged with user ID, IP, timestamp, user-agent?
- Authorization failures logged?
- Critical business operations logged (payments, privilege grants, account changes)?
- Admin actions logged to a tamper-evident sink?

**Log integrity (T1070):**
- Can authenticated users delete or alter their own log entries?
- Are logs written to a separate, append-only sink (not the same DB the app writes to)?
- Is CRLF injection possible into log statements? (forges log lines)

**Detection coverage (T1562):**
- Alerting on repeated auth failures, mass data access, unusual query volumes?
- Can an attacker exploit the app to disable logging?
- Are security-relevant exceptions swallowed silently?

**Information leakage:**
- Stack traces returned in production responses
- SQL error messages returned to clients
- PII/credentials written to application logs
- Internal hostnames, IPs, or file paths in error messages

---

## Phase 16 — SSRF & Server-Side Interactions [A10, API7, T1190]

SSRF appears in many non-obvious contexts — scan broadly:

- Any HTTP client call where URL is influenced by user input (direct or indirect)
- URL-based features: link preview, screenshot, PDF-from-URL, image proxy, webhook delivery, "import from URL"
- OAuth redirect_uri not validated against registered allowlist
- Cloud-specific targets: AWS IMDS (`169.254.169.254`), GCP metadata, Azure metadata
- Blind SSRF: DNS callback, timing differential, port scan via error messages
- SSRF filter bypasses: protocol switching (`file://`, `gopher://`), IP encoding (`0x7f000001`), DNS rebinding, redirect chains

---

## Phase 17 — DoS, Rate Limiting & Resource Exhaustion [API4, T1498, T1499]

**Rate limiting gaps — must cover ALL of:**
- Auth: login, password reset, OTP/MFA, registration
- Communication: email/SMS/push/voice sending endpoints
- Data access: search, list, export (enumeration + scraping)
- Computation: image processing, PDF generation, ML inference, crypto operations
- Token operations: creation, refresh, revocation

**Resource exhaustion patterns:**
- Unbounded pagination (no server-enforced maximum page size)
- Regex DoS: user input fed to catastrophically backtracking regex
- Archive bombs: decompressed size not validated before extraction
- XML/JSON bombs: deeply nested entity/object expansion
- GraphQL: unlimited depth, unlimited fan-out, alias batching
- User-controlled allocation sizes: buffer/array allocation without bounds checking
- Unbounded computation: user-controlled loop iterations, exponent values

---

## Phase 18 — Persistence & Backdoor Mechanisms [T1505, T1546, T1574]

- **Webshell upload:** file upload without server-side type enforcement + serve-as-executable path
- **Eval-stored-config:** code stored in DB or config file, loaded and executed at runtime
  (plugin systems, dynamic import/require with user-influenced paths, cron creation via API)
- **Hook injection:** event hook or middleware injection from user-controlled data
- **Dependency hijack:** internal packages claimable on public registries (see Phase 13)

---

## Phase 19 — Defense Evasion & Anti-Forensics [T1562, T1070, T1485]

- Disabled defenses via configuration flag: any boolean disabling WAF, CSRF, auth, MFA, audit logging
- Log tampering: can authenticated users delete or suppress their own log entries?
- Data destruction paths: bulk-delete API reachable by low-privilege users without soft-delete or backup
- Forensic gap analysis: post-RCE, what evidence could an attacker erase? What would be undetectable?

---

## Phase 20 — Lateral Movement & Internal Trust Abuse [T1210, T1550, T1080]

- Internal service trust: services trusting requests based on network origin alone (no cryptographic verification)
- Stolen token reuse: compromised user token replayed against internal microservices without re-validation
- Shared cache/DB poisoning: one tenant's data influencing another's reads
- SSRF as pivot: use Phase 16 SSRF to enumerate internal services, access internal admin interfaces, or steal cloud credentials
- Unauthenticated internal admin: any admin panel, debug endpoint, or management API accessible within the network without auth

---

## Phase 21 — Shadow APIs & Information Discovery [API9, T1082, T1083]

- **Shadow/zombie APIs:** old versions (`/v1/`, `/legacy/`) still live without current auth/rate limiting; framework-generated admin endpoints (Swagger UI, GraphQL playground, Spring Actuator, debug toolbar) in production
- **Undocumented endpoints:** discoverable via JS bundle analysis, `.well-known/`, `/debug/`, `/metrics/`, `/health/`, directory fuzzing
- **Information disclosure:** version numbers in headers/HTML, internal hostnames in responses, directory listing, `.git` at web root, backup files (`.bak`, `.old`, `.swp`), verbose error messages with internal paths

---

## Phase 22 — Unsafe Third-Party API Consumption [API10, T1199]

- Third-party API responses incorporated into queries/templates without schema validation
- Webhooks from third-party services accepted without HMAC signature verification
- SDK usage that disables TLS validation, logs credentials, or leaks user data
- PII/PHI sent to third-party APIs (analytics, monitoring, AI providers) without data classification review
- Blast radius if a third-party IdP is compromised: are there compensating controls?

---

## Phase 23 — Dynamic Validation & Exploit Confirmation

For each finding, construct a PoC producing an unambiguous observable signal:
- SQLi: time delay, response delta, DNS callback
- SSRF: DNS callback, metadata response, port scan error differential
- RCE: DNS callback, distinctive file write, process output marker
- Auth bypass: authed vs unauthed response body differs
- IDOR: response contains another user's data

If live testing unavailable: construct the PoC request and state the expected signal.

---

## Phase 24 — Exploit Chain Construction [MITRE ATT&CK Kill Chain]

**→ Reference `references/owasp-attack-framework.md`** to annotate chains with ATT&CK IDs.

1. Build matrix: attacker persona × privilege × entry point × finding
2. For each finding: "what does this enable, and what does it combine with?"
3. Prioritize unauthenticated chains and chains requiring only low privilege
4. Per chain: all steps, Confirmed/Likely/Theoretical per step, combined impact
5. Annotate with ATT&CK tactics (TA00xx) and techniques (Txxxx)

Must-check chain patterns:
- Hardcoded signing secret + unsafe deserializer → unauthenticated RCE
- SSRF → cloud IMDS → credential theft → full account compromise
- IDOR + mass assignment → privilege escalation → admin action abuse
- Open redirect in OAuth flow → token theft → account takeover
- File upload bypass → write to executable path → code execution
- Unauthenticated token creation → access all protected API endpoints → mass exfiltration
- Disabled CSRF + sensitive action → privilege grant or data modification via forged request

---

## Phase 25 — Git History & Artifact Mining [T1552]

- Deleted secrets visible in history
- Old vulnerable implementations before a "fix" commit
- Commented-out debug code with credentials or internal URLs
- Previous .env files, old TLS certificates, CI secrets

---

## Phase 26 — Architecture-Level Analysis [A04, T1199]

- Service-to-service communication with implicit trust (no cryptographic verification)
- Zero-trust violations: "internal network" treated as equivalent to "authenticated"
- Database isolation in multi-tenant deployments: shared schema vs per-tenant schema
- Cache namespace collisions enabling cross-tenant data leakage
- Queue security: unauthenticated message queue → any service can enqueue malicious messages

---

## Phase 27 — Risk Scoring & Prioritization [CVSS v3.1]

**→ Load `references/reporting-template.md`** for CVSS quick reference.

CVSS v3.1 mandatory for every Critical/High finding. Justify each vector component against
THIS codebase. Do not copy scores from similar CVEs.

Tag each finding with:
- OWASP category (Top 10 / API Security / LLM / Mobile as applicable)
- MITRE ATT&CK tactic (TA00xx) + technique (Txxxx)

---

## Phase 28 — Report Generation

**→ Load `references/reporting-template.md`** for exact per-finding format.

### Executive Summary (Required)
- Finding totals by severity
- Top 3 by concrete business impact (name the data/users/systems affected)
- All exploit chains with ATT&CK kill chain annotation
- Systemic patterns (architectural root causes, not isolated bugs)
- OWASP/ATT&CK coverage matrix showing what was and was not assessed
- Immediate priority action list (specific, not generic)
- What was NOT covered and its residual risk (required for all modes)

### Per-Finding — Required Fields (Critical/High)
All fields from `references/reporting-template.md` plus:
```
**OWASP:** A0X / API X / LLM0X — <Category Name>   (as applicable)
**MITRE ATT&CK:** TAxxxx / Txxxx — <Tactic> / <Technique>
```

Medium/Low: use condensed format from reporting-template.md.

### Systemic Pattern Block
Group related findings by architectural root cause. Name the design decision that
created the class of vulnerability. Recommend design-level remediation.

---

## Anti-Patterns — Never Produce These

```
❌ Report a finding without applying the three-gate validation protocol
✓  Gate 1 (reachable?) → Gate 2 (exploitable?) → Gate 3 (blast radius calibrated?)

❌ Stop at the first instance of a vulnerability pattern
✓  Enumerate ALL call sites before moving to the next finding class

❌ Assign "Confirmed" based on static evidence alone
✓  Confirmed = constructed PoC with a stated observable signal

❌ Assign High/Critical to eval() without checking if attacker can influence the input
✓  Trace the full source: is the input externally controllable? What auth is required?

❌ Omit OWASP and ATT&CK identifiers from findings
✓  Every Critical/High finding carries its OWASP category and ATT&CK technique

❌ Mark a phase complete without stating what was not covered and its residual risk
✓  Explicitly document every skipped check and its potential missed finding class

❌ Apply Django/Rails/Spring-specific patterns before detecting the framework
✓  Phase 0.1 detects the stack; Phase 8 loads the correct language-specific section
```
