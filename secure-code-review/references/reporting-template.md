# Reporting Template Reference

Load this file during Phases 27–28. Use the exact structures below — no deviation.

---

## Per-Finding Structure (Zero Exceptions)

```markdown
### [SEVERITY] FIND-XXX: <Short Descriptive Title>

**Affected Component:** <file:line_number> or <service:endpoint:method>
**Vulnerability Type:** <e.g., SQL Injection — Blind Time-Based>
**CWE:** CWE-XXX — <CWE Name>
**CVSS v3.1 Vector:** CVSS:3.1/AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_
**CVSS Base Score:** X.X (Critical / High / Medium / Low)
**Confidence:** Confirmed | Likely | Theoretical | Informational
**Remediation Effort:** Low | Medium | High
**Remediation SLA:** 24–72h | 7 days | 30 days | 90 days

---

#### Source → Sink Trace

`<file>:<line>` [SOURCE: e.g., HTTP query param `?id=`]
  → `<file>:<line>` [transformation: e.g., passed to `buildQuery()`]
  → `<file>:<line>` [SINK: e.g., `db.execute(sql)` — raw query, no parameterization]

---

#### Description

<Precise technical description scoped to THIS codebase. Explain WHY this specific
code is exploitable. No generic CWE descriptions. No "this could potentially..."
Explain what the attacker controls, what the sink does with it, and what the
outcome is. Reference specific variable names, function names, and file locations.>

---

#### Reproduction Steps (PoC)

```http
POST /api/v1/users/search HTTP/1.1
Host: target.com
Authorization: Bearer <valid_token>
Content-Type: application/json

{"query": "' OR '1'='1' -- "}
```

**Expected result:** <Attacker observes: HTTP 200 with all user records / 5 second delay
confirming blind injection / DNS callback to attacker.com / etc.>

**Exploit chain steps (if multi-step):**
1. Step 1: obtain X via Y
2. Step 2: use X to trigger Z
3. Step 3: observe W

---

#### Impact Analysis

<What can a real attacker accomplish, specifically? Not "information disclosure."
Concrete: "Attacker can dump the entire `users` table including password hashes,
email addresses, and PII for all N users." Include blast radius. Include whether
exploitation requires authentication, interaction, or specific conditions.>

---

#### Exploit Chain (if applicable)

Chains with: FIND-YYY (<title>)

Combined impact: <describe escalated impact>
Chain steps:
1. Exploit FIND-YYY to obtain <X>
2. Use <X> to exploit this finding
3. Result: <escalated impact>

---

#### Suggested Fix

**Before (vulnerable):**
```<language>
// paste the actual vulnerable code here
```

**After (secure):**
```<language>
// paste the fixed code here — actual fix, not pseudocode
```

**Explanation:** <Why the fix works. What property it enforces. If a library or API
is recommended, name it specifically (e.g., "use `pg` parameterized queries, not
string concatenation").>

---

#### Regression Test

**Test type:** Unit | Integration | E2E
**Framework:** <e.g., Jest, pytest, RSpec>

```<language>
// Specific test case that would catch this regression
it('rejects SQL injection in search query', async () => {
  const res = await request(app)
    .post('/api/v1/users/search')
    .set('Authorization', `Bearer ${validToken}`)
    .send({ query: "' OR '1'='1' -- " });
  expect(res.status).toBe(400);
  expect(res.body.users).toBeUndefined();
});
```

---

#### Compensating Controls

<If immediate fix is blocked by release cycle, architectural constraints, etc.>

- **WAF rule:** Block payloads matching `['"]?\s*(OR|AND)\s+['"]?1['"]?\s*=\s*['"]?1` on this endpoint
- **Feature flag:** Disable the affected endpoint until patched via flag `SEARCH_ENDPOINT_ENABLED=false`
- **Network restriction:** Restrict endpoint to internal network only (not a fix, reduces attack surface)
- **Monitoring:** Alert on anomalous response sizes / error rates on this endpoint

---

#### References

- OWASP: [Testing for SQL Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection)
- CWE: https://cwe.mitre.org/data/definitions/89.html
- Framework: <link to ORM parameterization docs>
```

---

## Confidence Tier Definitions

| Tier | Criteria | Reporting Requirement |
|---|---|---|
| **Confirmed** | PoC constructed and observable impact demonstrated (response delta, DNS callback, time delay, data returned) | Full PoC required |
| **Likely** | Strong static evidence: clear source→sink trace, sanitization gap confirmed, no runtime blocker identified | PoC showing partial evidence + explanation of what blocks full confirmation |
| **Theoretical** | Code path exists but: runtime conditions unclear, compensating control may exist, or requires chaining with unconfirmed finding | Must document explicitly what would need to be true for exploitation |
| **Informational** | Defense-in-depth gap, missing header, best-practice deviation with no direct exploit path | Document without PoC; deprioritize |

---

## CVSS v3.1 Quick Reference

**Attack Vector (AV):**
- N (Network): exploitable remotely
- A (Adjacent): same network segment
- L (Local): requires local access
- P (Physical): physical access required

**Attack Complexity (AC):**
- L (Low): no special conditions required
- H (High): requires specific configuration, race condition, or prior info

**Privileges Required (PR):**
- N (None): unauthenticated
- L (Low): basic user auth
- H (High): admin or elevated auth

**User Interaction (UI):**
- N (None): exploitable without victim action
- R (Required): victim must take an action (click link, open file)

**Scope (S):**
- U (Unchanged): impact confined to vulnerable component
- C (Changed): impact extends beyond vulnerable component (e.g., SSRF hitting other service)

**Impact (C/I/A — each):**
- N (None): no impact
- L (Low): limited impact, attacker gains partial access
- H (High): total loss of confidentiality/integrity/availability

**Common vectors for reference:**
```
Unauthenticated RCE (network):   CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H = 10.0 Critical
Authenticated SQLi (network):    CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H = 8.8 High
Stored XSS (network):            CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N  = 5.4 Medium
IDOR read-only (network):        CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N  = 6.5 Medium
Local priv-esc:                  CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H  = 7.8 High
```

---

## Executive Summary Template

```markdown
## Executive Summary

**Review Date:** YYYY-MM-DD
**Codebase / Scope:** <repo name, commit hash, or component>
**Operating Mode:** Full Audit | Quick Triage | PR Diff | Targeted
**Reviewer:** Claude (secure-code-review skill v1)

---

### Finding Totals

| Severity | Count |
|---|---|
| Critical | X |
| High | X |
| Medium | X |
| Low | X |
| Informational | X |
| **Total** | **X** |

---

### Top Findings by Business Impact

1. **FIND-001: <Title>** (Critical) — <one-sentence business impact, e.g., "Unauthenticated attacker can read any user's PII via blind SQL injection in the search endpoint">
2. **FIND-002: <Title>** (High) — <impact>
3. **FIND-003: <Title>** (High) — <impact>

---

### Exploit Chains Identified

- **Chain A:** FIND-XXX + FIND-YYY → <escalated impact>
- **Chain B:** FIND-ZZZ + FIND-WWW → <escalated impact>

---

### Systemic Patterns

<e.g., "Authorization is enforced at the REST middleware layer but is absent at the
GraphQL resolver level for the same resources. This is an architectural gap, not
isolated incidents — all GraphQL resolvers should be audited.">

---

### Immediate Actions (Priority Order)

1. <Specific, actionable — not "fix all vulns">
2. <Specific>
3. <Specific>

---

### What Was Not Covered

<If operating mode was not FULL AUDIT, explicitly state what phases were skipped
and what risks remain unassessed. E.g., "This was a PR Diff review scoped to
auth module changes. Phases 12 (DoS), 14 (Infrastructure), and 16 (AI/LLM) were
not covered.">
```

---

## Anti-Patterns (Never Produce These)

```
❌ "This could potentially lead to SQL injection"
✓  "The `query` parameter on line 47 of search.js is interpolated directly into
    the PostgreSQL query string at line 52 without parameterization. PoC: ..."

❌ "Use input validation"
✓  "Replace `db.query('SELECT * FROM users WHERE id = ' + req.params.id)` with
    `db.query('SELECT * FROM users WHERE id = $1', [req.params.id])`"

❌ CVSS Score: High (copied from similar CVE)
✓  CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H = 8.8 High
   (justified: network-exploitable by any authenticated user, no user interaction,
   complete confidentiality and integrity loss on users table)

❌ "An attacker could potentially access sensitive information"
✓  "An authenticated attacker with a standard user account can dump the full users
    table including bcrypt password hashes, email addresses, and TOTP secrets for
    all 50,000 registered users in a single request"

❌ Theoretical finding without documenting what blocks confirmation
✓  "Confidence: Theoretical — the code path exists (src/lib/parser.js:134) but
    confirming exploitation requires knowing whether the JWT secret is weak enough
    to brute-force, which requires live access to a valid token"
```

---

## Condensed Finding Format (Medium / Low / Informational)

For Medium and lower severity findings, use this condensed structure when time-constrained.
Critical and High findings always require the full format above.

```markdown
### [SEVERITY] FIND-XXX: <Short Title>

**Affected Component:** <file:line>
**Vulnerability Type:** <type>
**CWE:** CWE-XXX
**CVSS Base Score:** X.X (<Severity>)
**Confidence:** <tier>

**Description:** <2–3 sentences: what the code does, why it's wrong, what attacker gains.
Reference specific variable/function names.>

**PoC:** <minimal HTTP request or code snippet demonstrating the issue>

**Fix:** Replace `<vulnerable pattern>` with `<safe pattern>`. <One sentence explanation.>
```

---

## Systemic Pattern Block Template

Include this section after all individual findings, before the executive summary close.

```markdown
## Systemic Patterns & Architectural Recommendations

### Pattern 1: <Short Name>
**Scope:** <N files / all endpoints of type X / entire component Y>
**Root Cause:** <Architectural decision or missing control that created this pattern>
**Individual Findings:** FIND-XXX, FIND-YYY, FIND-ZZZ
**Recommended Remediation:** <Design-level fix — not "patch each instance" but "change the architecture">
**Verification:** <How to confirm the systemic fix was applied completely>
```

---

## Auth Coverage Matrix Template

Include this in Phase 1 / Phase 5 output for every codebase:

```markdown
## Authentication Coverage Matrix

| Endpoint Class | Method | Auth Required (Spec) | Auth Enforced (Code) | Gap |
|---|---|---|---|---|
| /api/core/clinicaltrials/ | GET | Token | None | ✗ FIND-011 |
| /api/core/tokens/ | POST | Admin | None | ✗ FIND-010 |
| /impersonate/<uid>/ | POST | SuperUser | SuperUser | ✓ |
| /rest/registerevent/ | POST | None | None | Intentional? |
```

This matrix is the most efficient way to surface broken access control at scale.
Generate it mechanically during Phase 1, then validate each gap during Phase 5.
