# Cryptographic Security Reference

Load this file during Phase 7.

---

## Algorithm Weakness Matrix

| Algorithm | Status | Attack | Safe Replacement |
|---|---|---|---|
| DES / 3DES | Broken | SWEET32 (birthday), brute force | AES-256-GCM |
| RC4 | Broken | Statistical bias (NOMORE attack) | AES-256-GCM |
| AES-ECB | Broken | Deterministic — identical blocks produce identical ciphertext | AES-GCM or AES-CBC+HMAC |
| AES-CBC (unauthenticated) | Vulnerable | Padding oracle (POODLE-class), bit-flip | AES-GCM (AEAD) |
| AES-GCM with nonce reuse | Broken | Authentication key recovery from two messages | AES-GCM + random 96-bit nonce per message |
| MD5 | Broken | Collision (chosen-prefix) | SHA-256 / SHA-3 |
| SHA-1 | Broken | SHAttered collision | SHA-256 / SHA-3 |
| SHA-1 in certificates | Deprecated | Certificate forgery | SHA-256 |
| RSA < 2048-bit | Weak | Factoring | RSA-4096 or ECDSA P-256 |
| RSA-PKCS#1 v1.5 | Vulnerable | Bleichenbacher oracle | RSA-OAEP or ECDH |
| DSA with reused nonce (k) | Broken | Private key recovery (PS3-class) | ECDSA with deterministic k (RFC 6979) |
| HMAC-MD5 | Acceptable but deprecated | Length extension (plain MD5 only) | HMAC-SHA256 |

---

## Password Hashing

| Scheme | Status | Issue |
|---|---|---|
| MD5(password) | Broken | No salt, fast cracking |
| SHA-*/bcrypt without pepper | Weak | Database dump → offline crack |
| bcrypt cost < 10 | Weak | Too fast on modern hardware |
| bcrypt (cost ≥ 12) | Acceptable | Recommended minimum |
| scrypt (N≥32768, r=8, p=1) | Good | Memory-hard |
| Argon2id (m≥64MB, t≥3, p≥4) | Best | Current OWASP recommendation |

Flag any use of: `md5()`, `sha1()`, `sha256()` directly on passwords.
Require: bcrypt/scrypt/Argon2id with appropriate parameters.

---

## IV / Nonce Management

**AES-CBC:**
- IV must be random (cryptographically secure) per message
- Static IV → deterministic encryption, plaintext recovery via chosen-plaintext
- IV transmitted with ciphertext (this is correct) but must not be reused

**AES-GCM:**
- Nonce (96-bit recommended) must NEVER repeat under the same key
- Nonce reuse → authentication key recovery (full authentication bypass)
- With random 96-bit nonce: collision probability after 2^32 messages → key rotation required
- Deterministic nonce (counter-based) is safe if counter never wraps

**CTR / Stream cipher equivalent:**
- Keystream reuse: two messages encrypted with same key+nonce → XOR plaintexts trivially

---

## Key & Material Management

**Detection signals for insecure key storage:**
- Key/IV in source code (string literal, const, hardcoded byte array)
- Key in environment variable without external secrets manager
- Key in config file committed to git
- Encryption key same as authentication key (must be separate)
- No key rotation mechanism

**Secure patterns:**
- AWS KMS / GCP KMS / Azure Key Vault for symmetric keys
- HashiCorp Vault with dynamic secrets
- Key derivation via HKDF (not raw password) for derived keys
- Separate keys for: encryption, authentication, signing

---

## PRNG / Entropy Per Language

| Language | Insecure | Secure |
|---|---|---|
| JavaScript | `Math.random()` | `crypto.randomBytes(n)`, `crypto.getRandomValues()` |
| Python | `random.random()`, `random.randint()` | `secrets.token_bytes()`, `os.urandom()` |
| PHP | `rand()`, `mt_rand()` | `random_bytes()`, `random_int()` |
| Java | `java.util.Random` | `java.security.SecureRandom` |
| Go | `math/rand` | `crypto/rand` |
| Ruby | `rand()` | `SecureRandom.random_bytes()` |
| C | `rand()` | `getrandom()`, `/dev/urandom` |
| .NET | `System.Random` | `System.Security.Cryptography.RandomNumberGenerator` |

**Flag:** any use of insecure PRNG for: session IDs, CSRF tokens, password reset tokens,
API keys, nonces, OTP codes, UUID generation for security purposes.

---

## Timing Attacks

**Vulnerable patterns (early-exit comparison):**
```python
# Python — vulnerable
if user_token == stored_token:  # exits on first mismatch

# JavaScript — vulnerable
if (userToken === storedToken)

# PHP — vulnerable
if ($userToken == $storedToken)
```

**Safe constant-time comparators:**
```python
# Python
import hmac
hmac.compare_digest(user_token, stored_token)

# Node.js
crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b))

# PHP
hash_equals($stored_token, $user_token)

# Java
MessageDigest.isEqual(a.getBytes(), b.getBytes())

# Go
subtle.ConstantTimeCompare([]byte(a), []byte(b))

# Ruby
ActiveSupport::SecurityUtils.secure_compare(a, b)
```

**Apply to:** HMAC verification, API key comparison, session token validation,
password reset token comparison, webhook signature verification.

**User enumeration via timing:** login flow returning faster for invalid username
than invalid password → username enumeration. Fix: run full auth flow regardless.

---

## TLS / Transport Security

**TLS versions:**
- TLS 1.0, 1.1: deprecated (RFC 8996) — must be disabled
- TLS 1.2: acceptable with correct cipher suite selection
- TLS 1.3: preferred

**Weak cipher suites to reject:**
- `RC4-*`, `*-NULL-*`, `*-EXPORT-*`, `*-DES-*`, `*-MD5`, `*-ANON-*`
- `TLS_RSA_*` (no forward secrecy) — prefer ECDHE

**Certificate validation bypass patterns:**
```python
# Python requests — NEVER
requests.get(url, verify=False)

# Node.js — NEVER
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'
https.request({rejectUnauthorized: false})

# Go — NEVER
tls.Config{InsecureSkipVerify: true}

# PHP cURL — NEVER
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false)

# Java — NEVER
TrustManager that accepts all certificates
```

**HSTS:**
- Required on all HTTPS endpoints
- `max-age` must be ≥ 31536000 (1 year)
- `includeSubDomains` required if subdomains all serve HTTPS
- `preload` for inclusion in browser preload lists

**Certificate pinning:**
- Required in mobile apps communicating with sensitive APIs
- Absence → MITM via installed CA certificate (corporate proxy, nation-state)
