# Security Frameworks Reference

Load this file during Phase 0 to complete the framework coverage matrix and during
report generation to attach the correct OWASP/ATT&CK identifiers to each finding.

---

## OWASP Top 10 (2021) — Full Coverage Checklist

| ID | Category | Covered In | Key Checks |
|---|---|---|---|
| **A01** | Broken Access Control | Phase 5, 6, 16 | IDOR, BOLA, missing auth, path traversal, CORS misconfiguration, privilege escalation, directory listing |
| **A02** | Cryptographic Failures | Phase 7, 11 | Weak algorithms, hardcoded keys, missing TLS, cleartext data at rest, insufficient key length |
| **A03** | Injection | Phase 2, 3 | SQLi, NoSQLi, OS command, SSTI, LDAP, XPath, XXE, log injection, CSV/formula injection |
| **A04** | Insecure Design | Phase 6, 18, 20 | Missing rate limits, insecure business logic, lack of threat modeling outputs in design, no defense-in-depth |
| **A05** | Security Misconfiguration | Phase 12, 21 | Default credentials, unnecessary features, missing security headers, verbose error messages, open cloud storage |
| **A06** | Vulnerable & Outdated Components | Phase 13 | Known CVE reachability, EOL runtimes, unpinned deps, abandoned packages |
| **A07** | Identification & Authentication Failures | Phase 4 | Weak passwords, broken session management, missing MFA, insecure credential storage, session fixation |
| **A08** | Software & Data Integrity Failures | Phase 13, 12 | Insecure deserialization, unsigned updates, CI/CD pipeline integrity, SRI missing, auto-update without verification |
| **A09** | Security Logging & Monitoring Failures | **Phase 15** | No audit logs, log injection, logs with PII, missing alerting on auth failure, log tampering (T1070) |
| **A10** | Server-Side Request Forgery | **Phase 16** | Internal metadata access, cloud IMDS, blind SSRF, URL redirect chains, DNS rebinding |

---

## OWASP API Security Top 10 (2023) — Full Coverage Checklist

| ID | Category | Covered In | Key Checks |
|---|---|---|---|
| **API1** | Broken Object Level Authorization | Phase 5 | BOLA/IDOR: object IDs in path/body not validated against session ownership |
| **API2** | Broken Authentication | Phase 4 | Weak tokens, JWT algorithm confusion, missing expiry, credential stuffing |
| **API3** | Broken Object Property Level Authorization | Phase 5 | Mass assignment: user controls fields that should be server-only (is_admin, balance, role) |
| **API4** | Unrestricted Resource Consumption | **Phase 17** | No rate limiting, unbounded pagination, missing request size limits, regex DoS |
| **API5** | Broken Function Level Authorization | Phase 5 | HTTP method bypass, admin endpoints accessible to regular users, RBAC gaps |
| **API6** | Unrestricted Access to Sensitive Business Flows | Phase 6 | Account enumeration, bulk operations without limits, scraping endpoints |
| **API7** | Server-Side Request Forgery | Phase 16 | (See A10 above) |
| **API8** | Security Misconfiguration | Phase 12 | CORS wildcard, unnecessary HTTP methods, missing security headers, GraphQL introspection in prod |
| **API9** | Improper Inventory Management | **Phase 21** | Shadow APIs, deprecated versions still live, undocumented internal endpoints, debug APIs exposed |
| **API10** | Unsafe Consumption of APIs | **Phase 22** | Trusting third-party API responses without validation, injection via third-party data, SSRF via webhooks |

---

## OWASP Mobile Top 10 (2024) — Apply When Mobile Code Present

| ID | Category | Covered In | Key Checks |
|---|---|---|---|
| **M1** | Improper Credential Usage | Phase 4, 11 | Hardcoded creds in APK/IPA, insecure credential storage |
| **M2** | Inadequate Supply Chain Security | Phase 13 | Malicious SDK, third-party library integrity |
| **M3** | Insecure Authentication/Authorization | Phase 4, 5 | Client-side auth checks, insecure biometric implementation |
| **M4** | Insufficient Input/Output Validation | Phase 2, 3 | Missing validation on all mobile I/O, deeplink injection |
| **M5** | Insecure Communication | Phase 7 | Certificate pinning absent, cleartext traffic, TLS 1.0/1.1 |
| **M6** | Inadequate Privacy Controls | Phase 11 | PII in logs/analytics, excessive permissions, data leakage via screenshots |
| **M7** | Insufficient Binary Protections | Phase 0 | No obfuscation, debuggable flag, root/jailbreak detection absent |
| **M8** | Security Misconfiguration | Phase 12 | Exported components, debug flags, backup enabled |
| **M9** | Insecure Data Storage | Phase 11 | Plaintext creds in SharedPreferences/NSUserDefaults/SQLite, cache exposure |
| **M10** | Insufficient Cryptography | Phase 7 | Weak keys, ECB mode, custom crypto, hardcoded IV |

---

## OWASP LLM Top 10 (2025) — Apply When AI/LLM Code Present

| ID | Category | Covered In | Key Checks |
|---|---|---|---|
| **LLM01** | Prompt Injection | Phase 14 | Direct and indirect injection; user data in system context |
| **LLM02** | Sensitive Information Disclosure | Phase 14 | PII/secrets in prompts, training data extraction, system prompt leakage |
| **LLM03** | Supply Chain | Phase 13, 14 | Compromised model weights, poisoned fine-tuning data, malicious plugins |
| **LLM04** | Data and Model Poisoning | Phase 14 | RAG corpus poisoning, adversarial examples, embedding inversion |
| **LLM05** | Improper Output Handling | Phase 14 | LLM output rendered as HTML/SQL/code without sanitization |
| **LLM06** | Excessive Agency | Phase 14 | Overprivileged tools, irreversible actions without human approval |
| **LLM07** | System Prompt Leakage | Phase 14 | Secrets in system prompt, extraction via instruction override |
| **LLM08** | Vector and Embedding Weaknesses | Phase 14 | Retrieval manipulation, embedding inversion, similarity score abuse |
| **LLM09** | Misinformation | Phase 14 | Unvalidated LLM output used in decisions, hallucination in security context |
| **LLM10** | Unbounded Consumption | Phase 14, 17 | Token budget DoS, no per-user limits, unbounded agent loops |

---

## MITRE ATT&CK for Enterprise — Phase Mapping

Each ATT&CK tactic maps to one or more review phases. During exploit chain construction
(Phase 24), annotate chains with the ATT&CK technique IDs they exercise.

### TA0001 — Initial Access
| Technique | ID | Review Phase |
|---|---|---|
| Exploit Public-Facing Application | T1190 | Phase 2, 3, 4, 5 |
| Supply Chain Compromise | T1195 | Phase 13 |
| Phishing (spear-phishing link in app) | T1566 | Phase 4, 6 |
| Valid Accounts (credential reuse) | T1078 | Phase 4, 11 |
| Trusted Relationship | T1199 | Phase 22 |

### TA0002 — Execution
| Technique | ID | Review Phase |
|---|---|---|
| Command and Scripting Interpreter | T1059 | Phase 3 (OS command injection) |
| Software Deployment Tools | T1072 | Phase 12 (CI/CD) |
| Serverless Execution | T1648 | Phase 12 |
| Exploitation for Client Execution | T1203 | Phase 10 (XSS → client exec) |
| Scheduled Task/Job | T1053 | Phase 1 (cron/worker attack surface) |

### TA0003 — Persistence
| Technique | ID | Review Phase |
|---|---|---|
| Server Software Component (webshells) | T1505 | **Phase 18** |
| Account Manipulation | T1098 | Phase 4, 5 |
| Create Account | T1136 | Phase 5, 6 |
| Modify Authentication Process | T1556 | Phase 4 |
| Event Triggered Execution | T1546 | **Phase 18** (hook injection) |
| Hijack Execution Flow | T1574 | **Phase 18** (dynamic lib abuse) |

### TA0004 — Privilege Escalation
| Technique | ID | Review Phase |
|---|---|---|
| Exploitation for Privilege Escalation | T1068 | Phase 5 |
| Abuse Elevation Control Mechanism | T1548 | Phase 5 |
| Access Token Manipulation | T1134 | Phase 4, 5 |

### TA0005 — Defense Evasion
| Technique | ID | Review Phase |
|---|---|---|
| Impair Defenses (disable logging/monitoring) | T1562 | **Phase 15, 19** |
| Indicator Removal (log deletion/alteration) | T1070 | **Phase 15, 19** |
| Obfuscated Files or Information | T1027 | Phase 2, 8 |
| Masquerading | T1036 | Phase 2 (MIME bypass, polyglots) |
| Rootkit | T1014 | **Phase 18** |

### TA0006 — Credential Access
| Technique | ID | Review Phase |
|---|---|---|
| Unsecured Credentials | T1552 | Phase 11 |
| Exploitation for Credential Access | T1212 | Phase 4 |
| Brute Force | T1110 | Phase 4, 17 (rate limiting) |
| Adversary-in-the-Middle | T1557 | Phase 7 (TLS) |
| Steal Web Session Cookie | T1539 | Phase 4, 10 |
| Forge Web Credentials (JWT/SAML) | T1606 | Phase 4 |
| Password Policy Discovery → Spraying | T1110.003 | Phase 17 |

### TA0007 — Discovery
| Technique | ID | Review Phase |
|---|---|---|
| System Information Discovery | T1082 | **Phase 21** (error disclosure) |
| File and Directory Discovery | T1083 | **Phase 21** |
| Network Service Discovery | T1046 | **Phase 21** |
| Account Discovery | T1087 | Phase 5, 21 |
| Software Discovery | T1518 | Phase 21 (version disclosure) |
| API Enumeration | T1590 | **Phase 21** (shadow APIs, GraphQL introspection) |

### TA0008 — Lateral Movement
| Technique | ID | Review Phase |
|---|---|---|
| Exploitation of Remote Services | T1210 | **Phase 20** |
| Internal Spearphishing | T1534 | **Phase 20** |
| Use Alternate Authentication Material | T1550 | **Phase 20** (stolen tokens reused internally) |
| Taint Shared Content | T1080 | **Phase 20** (shared cache/DB poisoning) |

### TA0009 — Collection
| Technique | ID | Review Phase |
|---|---|---|
| Data from Information Repositories | T1213 | **Phase 20** (SSRF to internal repos) |
| Data from Local System | T1005 | Phase 3 (path traversal) |
| Email Collection | T1114 | Phase 14 (AI agent email access) |
| Clipboard Data | T1115 | Phase 10 (client-side) |
| Screen Capture | T1113 | Phase 10 |
| Database Extraction | T1005 | Phase 2, 3 (SQLi) |

### TA0010 — Exfiltration
| Technique | ID | Review Phase |
|---|---|---|
| Exfiltration Over C2 Channel | T1041 | Phase 16 (SSRF as exfil) |
| Exfiltration Over Alternative Protocol | T1048 | Phase 16, 20 (DNS OOB, ICMP) |
| Transfer Data to Cloud Account | T1537 | Phase 12, 16 |
| Scheduled Transfer | T1029 | Phase 18 (backdoor callback) |

### TA0011 — Command & Control
| Technique | ID | Review Phase |
|---|---|---|
| Application Layer Protocol | T1071 | **Phase 18** (C2 over HTTP/DNS) |
| Web Service (as C2) | T1102 | **Phase 18** |
| Ingress Tool Transfer | T1105 | Phase 3, 18 (RCE → download) |

### TA0040 — Impact
| Technique | ID | Review Phase |
|---|---|---|
| Data Destruction | T1485 | **Phase 19** |
| Data Encrypted for Impact (ransomware) | T1486 | **Phase 19** |
| Defacement | T1491 | Phase 10 (XSS → defacement) |
| Endpoint Denial of Service | T1499 | **Phase 17** |
| Network Denial of Service | T1498 | **Phase 17** |
| Resource Hijacking (cryptomining) | T1496 | Phase 3, 18 (post-RCE) |
| Account Access Removal | T1531 | Phase 5, 19 |

---

## Framework Coverage Matrix — Per-Finding Template Addition

When completing per-finding reports, include these fields:

```
**OWASP Top 10:** A0X — <Category Name>
**OWASP API Security:** API X — <Category Name>  (if applicable)
**OWASP LLM Top 10:** LLM0X — <Category Name>    (if applicable)
**MITRE ATT&CK:** TAxxxx / Txxxx — <Tactic> / <Technique>
```

Example:
```
**OWASP Top 10:** A03 — Injection
**OWASP API Security:** API6 — Unrestricted Access to Sensitive Business Flows
**MITRE ATT&CK:** TA0002 / T1059 — Execution / Command and Scripting Interpreter
```

---

## Phase 0 Coverage Matrix — Fill at Start of Every Audit

Copy this into your Phase 0 output and mark each framework item as:
`✓ Covered` | `⚠ Partial` | `✗ Not Applicable` | `? Requires Runtime`

```
OWASP Top 10 (2021):
[ ] A01 Broken Access Control
[ ] A02 Cryptographic Failures
[ ] A03 Injection
[ ] A04 Insecure Design
[ ] A05 Security Misconfiguration
[ ] A06 Vulnerable & Outdated Components
[ ] A07 Authentication Failures
[ ] A08 Software & Data Integrity
[ ] A09 Logging & Monitoring
[ ] A10 SSRF

OWASP API Security (2023) — if APIs present:
[ ] API1 BOLA
[ ] API2 Broken Auth
[ ] API3 Broken Object Property Auth
[ ] API4 Unrestricted Resource Consumption
[ ] API5 Broken Function Level Auth
[ ] API6 Unrestricted Business Flow Access
[ ] API7 SSRF
[ ] API8 Misconfiguration
[ ] API9 Improper Inventory Management
[ ] API10 Unsafe API Consumption

OWASP Mobile (2024) — if mobile code present:
[ ] M1-M10 (see reference for individual checks)

OWASP LLM (2025) — if LLM/AI code present:
[ ] LLM01-LLM10 (see reference for individual checks)

MITRE ATT&CK Tactics:
[ ] TA0001 Initial Access
[ ] TA0002 Execution
[ ] TA0003 Persistence
[ ] TA0004 Privilege Escalation
[ ] TA0005 Defense Evasion
[ ] TA0006 Credential Access
[ ] TA0007 Discovery
[ ] TA0008 Lateral Movement
[ ] TA0009 Collection
[ ] TA0010 Exfiltration
[ ] TA0011 Command & Control
[ ] TA0040 Impact
```
