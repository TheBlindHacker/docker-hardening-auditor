# 🛡️ Docker & Container Security Hardening & Deep Forensics Suite (2026 Edition)

**Standard**: CIS Docker Benchmark v1.6.0 / v1.7.0 & NIST SP 800-190 | **Version**: 2.0.0 | **License**: MIT | **Author**: Joe B. (The Blind Hacker)

An enterprise-grade container security playbook, AI coding agent skill (**Claude Code**, **Cursor**, **Codex CLI**, **Gemini CLI**, **Antigravity**), and cross-platform auditing toolkit (**Python**, **Bash**, **PowerShell**).

Goes far beyond basic `Dockerfile` linting to cover what real-world red-team and DevSecOps engineering has taught us over the years: **unpacked OCI layer "Ghost Secret" forensics**, **battle-tested Anchore `Syft` + `Grype` SBOM/CVE pipelines**, **TruffleHog + 12-Pattern Regex & Shannon Entropy credential hunting**, and **2026 kernel syscall lockdown (`io_uring`, `eBPF`, `userfaultfd`, Cgroups v2, SLSA provenance)**.

---

## ⚡ Key Capabilities

- 🚫 **12-Point CIS & 2026 Hardening Engine**: Eliminates `UID 0` root execution, drops Linux capabilities (`cap_drop: [ALL]`), enforces `read_only: true` root filesystems with `noexec,nosuid,nodev` `tmpfs`, locks down `cgroup: private` & `pids_limit`, and blocks `runc` file-descriptor breakout primitives (`CVE-2024-21626`).
- 🕵️ **OverlayFS Layer Forensics & "Ghost Secret" Hunter**: Exports images via `docker save`, unpacks every intermediate `.tar` layer, flags `.wh.*` whiteout markers where developers tried to `rm` a secret in a later layer, and scans every historical layer for credentials.
- 🔑 **TruffleHog + 12-Pattern Regex & Shannon Entropy Engine**: Combines `trufflehog docker` / `trufflehog filesystem` verification with a built-in 12-signature regex catalog and Shannon entropy calculator (`H >= 4.25` bits/char) across **Python**, **Bash**, and **PowerShell**.
- 📦 **Battle-Tested Anchore `Syft` + `Grype` Workflows**: Decouples CycloneDX SBOM generation (`syft --scope all-layers`) from sub-second CVE matching (`grype sbom:... --only-fixed --by-cve`), including Distroless/Wolfi binary inspection and `.grype.yaml` / OpenVEX triage.
- 🛡️ **Drop-In 2026 Kernel Seccomp Profile**: Ships with `templates/seccomp-2026-hardened.json` explicitly blocking high-risk kernel escape syscalls (`io_uring_setup`, `io_uring_enter`, `io_uring_register`, `bpf`, `userfaultfd`, `kexec_load`, `ptrace`, `keyctl`, `unshare`).
- 🔍 **Live In-Container Runtime Triage**: Decodes `/proc/self/status` capability bitmasks (`CapEff`), `NoNewPrivs`, `Seccomp` filter state, `/proc/self/uid_map` user namespaces, and exposed runtime sockets (`/var/run/docker.sock`, `/run/containerd/containerd.sock`) from inside running containers.

---

## 📂 Repository Architecture

```text
docker-hardening-auditor/
├── SKILL.md                              # Complete AI Agent Skill instructions & 12-Point CIS/2026 rubric
├── README.md                             # Deep-dive engineering guide, Grype/Syft & TruffleHog playbooks
├── LICENSE                               # MIT License
├── scripts/
│   ├── audit_container.py                # Zero-dependency Python CIS, runtime & Regex/Entropy secret auditor
│   ├── deep_audit_docker.sh              # Bash deep OCI layer unpack, Grype/Syft, TruffleHog & regex auditor
│   └── Invoke-DockerDeepAudit.ps1        # PowerShell 5.1/7+ native layer unpack, entropy & CVE auditor
├── templates/
│   ├── Dockerfile.hardened               # Multi-stage non-root (10001:10001) SUID-stripped Dockerfile
│   ├── docker-compose.hardened.yml       # Cgroups v2, read_only, cap_drop ALL, seccomp-hardened compose
│   ├── seccomp-2026-hardened.json        # 2026 Seccomp profile blocking io_uring, bpf, userfaultfd, ptrace
│   └── .dockerignore                     # Strict build-context airgap ignore list
└── tests/
    └── test_audit_container.py           # Pytest suite verifying AST, Compose, Capability & Secret detectors
```

---

## 🧠 Deep Dive 1: What Years of Auditing with `Grype` & `Syft` Taught Us

Most teams run a single naive vulnerability scan against `my-app:latest`, get flooded with 300 unfixable upstream Debian low-severity findings, and eventually ignore the scanner altogether. Here is the production-tested 2026 methodology:

### 1. Decouple `Syft` SBOM Creation from `Grype` Scanning
Extracting and indexing a multi-gigabyte container image takes 20–60 seconds. Auditing a generated CycloneDX JSON SBOM with `Grype` takes **less than 1 second**:

```bash
# 1. Generate a rich CycloneDX SBOM indexing all layers and language binaries
syft company/api:2.0.0 --scope all-layers -o cyclonedx-json=sbom.cdx.json

# 2. Scan the SBOM instantly with Grype (gate CI on High/Critical fixable CVEs)
grype sbom:sbom.cdx.json --by-cve --only-fixed --fail-on high
```

### 2. Understand `--scope squashed` vs. `--scope all-layers`
| Scope Flag | What It Inspects | When to Use It |
| :--- | :--- | :--- |
| `--scope squashed` *(Default)* | Only files visible in the final merged container rootfs | Daily developer CI gates where build-stage tools were already discarded |
| `--scope all-layers` | Every intermediate `.tar` layer in the image manifest | Deep security audits, compliance reviews, and detecting vulnerable packages hidden by whiteout files |

### 3. Auditing Distroless, Chainguard/Wolfi & Static Go/Rust Binaries
When you strip out the OS package manager (`apt`/`apk`) by using `gcr.io/distroless/static-debian12` or `FROM scratch`, scanners that only check `/var/lib/dpkg/status` report **zero vulnerabilities** even if your compiled binary embeds vulnerable dependencies.
- **Go Binaries**: `Syft` reads `.go.buildinfo` directly from ELF binaries. Always compile with standard Go module metadata intact.
- **Rust Binaries**: Compile with `cargo auditable build --release` so `Syft` and `Grype` can extract the embedded dependency tree from the `.dep-v0` ELF section.

### 4. Actionable Triage: `--only-fixed`, EPSS, CISA KEV & OpenVEX
- **Eliminate Unfixable Noise**: Pass `--only-fixed` in CI gates so builds only break when an upstream patch actually exists. Run a separate weekly scheduled job *without* `--only-fixed` to track unpatched upstream exposure.
- **Exploitability Prioritization (EPSS & KEV)**: Export JSON (`grype sbom:sbom.cdx.json -o json`) and filter for CVEs present in the **CISA Known Exploited Vulnerabilities (KEV)** catalog or with **EPSS score >= 0.10**.
- **Version-Controlled `.grype.yaml` Suppressions**:
  ```yaml
  # .grype.yaml — Checked into repository root with mandatory expiration review
  ignore:
    - vulnerability: CVE-2023-45853
      reason: "MiniZip contrib code is not compiled into our runtime zlib shared object (Verified 2026-11)"
      package:
        name: zlib1g
  ```

---

## 🕵️ Deep Dive 2: Hunting "Ghost Secrets" in Layers (`TruffleHog` + Bash & PowerShell Regex)

### Why Deleted Secrets Still Leak in Docker Images
Every `RUN`, `COPY`, and `ADD` instruction creates an immutable filesystem layer. If a developer writes:
```dockerfile
# ❌ BROKEN PATTERN: Secret remains permanently in Layer 2!
COPY .env /app/.env
RUN python scripts/seed_config.py && rm -f /app/.env
```
If those happen in separate layers (or a base image had credentials deleted in a child image), the upper layer only records an OverlayFS whiteout file (`.wh..env`). Anyone who runs `docker save` and unpacks the tarballs recovers `/app/.env` in full.

**The 2026 Fix — BuildKit Ephemeral Secret Mounts**:
```dockerfile
# ✅ SECURE 2026 PATTERN: Mounted in-memory via tmpfs for one RUN step; never touches any layer
# syntax=docker/dockerfile:1.7
RUN --mount=type=secret,id=seed_env,target=/run/secrets/seed_env \
    python scripts/seed_config.py --config /run/secrets/seed_env
```

---

### 1. Automated Layer & Build-Context Secret Hunting in **Bash**

Run the full script (`bash scripts/deep_audit_docker.sh --image myorg/api:2.0.0 --dir .`), or use this standalone Bash snippet to unpack an image and hunt for whiteout files, TruffleHog hits, and 12 high-risk credential regex patterns:

```bash
#!/usr/bin/env bash
set -euo pipefail

IMAGE="${1:?Usage: $0 <image:tag>}"
WORK_DIR="$(mktemp -d)"
trap 'rm -r -f "${WORK_DIR}"' EXIT

echo "[*] 1. Checking non-truncated image build history for ARG/ENV leaks..."
docker history --no-trunc "${IMAGE}" | grep -Ei '(SEC[R]ET|TOK[E]N|PASS[W]ORD|API[_-]?KEY|AK[I]A|gh[pousr]_)' || true

echo "[*] 2. Running TruffleHog across all OCI layers..."
if command -v trufflehog >/dev/null 2>&1; then
    trufflehog docker --image="${IMAGE}" --results=verified,unknown
fi

echo "[*] 3. Exporting and unpacking intermediate layer tarballs..."
docker save "${IMAGE}" -o "${WORK_DIR}/image.tar"
mkdir -p "${WORK_DIR}/unpacked"
tar -xf "${WORK_DIR}/image.tar" -C "${WORK_DIR}/unpacked"

# Regex signature combining Private Keys, AWS, GitHub, GitLab, Slack, Stripe, GCP, AI keys, JWTs & DB URIs
COMBINED_REGEX='(-----BEGIN [A-Z0-9 ]*PRI[V]ATE KEY-----|AK[I]A[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{22,255}|glpat-[A-Za-z0-9_-]{20,64}|xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,64}|(sk|rk)_live_[0-9a-zA-Z]{24,99}|AIza[0-9A-Za-z_-]{35}|sk-proj-[A-Za-z0-9_-]{32,180}|eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{16,}|(postgres|mysql|mongodb|redis)[:]//[^:\s/@]+:[^@\s/]{4,}@)'

find "${WORK_DIR}/unpacked" -type f \( -name "*.tar" -o -path "*/blobs/sha256/*" \) | while read -r layer_tar; do
    echo "  -> Inspecting layer blob: ${layer_tar##*/}"
    # Detect OverlayFS whiteout markers (.wh.*)
    tar -tf "${layer_tar}" 2>/dev/null | grep -E '(^|/)\.wh\.' && echo "     [!] Whiteout marker detected in layer!" || true
    # Extract layer to scratch dir and run regex scan
    LAYER_DIR="${WORK_DIR}/layer_extract"
    mkdir -p "${LAYER_DIR}"
    tar -xf "${layer_tar}" -C "${LAYER_DIR}" 2>/dev/null || true
    grep -rnEI "${COMBINED_REGEX}" "${LAYER_DIR}" 2>/dev/null || true
    rm -r -f "${LAYER_DIR}"
done
```

---

### 2. Automated Layer & Build-Context Secret Hunting in **PowerShell**

Run the full script (`pwsh -File scripts/Invoke-DockerDeepAudit.ps1 -Image "myorg/api:2.0.0" -Directory "."`), or use this standalone PowerShell snippet with native regex + Shannon entropy detection:

```powershell
param([Parameter(Mandatory = $true)][string]$Image)

$SecretPatterns = @{
    "PrivateKey"  = '-----BEGIN [A-Z0-9 ]*PRI[V]ATE KEY-----'
    "AwsAccessId" = '\b(AK[I]A|AS[I]A)[0-9A-Z]{16}\b'
    "GitHubPat"   = '\b(gh[pousr]_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b'
    "GitLabPat"   = '\bglpat-[A-Za-z0-9_\-]{20,64}\b'
    "SlackToken"  = '\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,64}\b'
    "StripeLive"  = '\b(sk|rk)_live_[0-9a-zA-Z]{24,99}\b'
    "GcpApiKey"   = '\bAIza[0-9A-Za-z_\-]{35}\b'
    "AiApiKey"    = '\b(sk-proj-[A-Za-z0-9_\-]{32,180}|sk-ant-api[0-9]{2}-[A-Za-z0-9_\-]{32,180})\b'
    "JwtToken"    = '\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{16,}\b'
    "DatabaseUri" = '\b(postgres(ql)?|mysql|mongodb(\+srv)?|redis)[:]//[^:\s/@]+:[^@\s/]{4,}@[^\s"'']+'
}

$TempDir = Join-Path ([IO.Path]::GetTempPath()) ("layer_scan_" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $TempDir -Force | Out-Null

try {
    $TarPath = Join-Path $TempDir "image.tar"
    docker save $Image -o $TarPath
    tar -xf $TarPath -C $TempDir
    Remove-Item $TarPath -Force

    Get-ChildItem -Path $TempDir -Recurse -File | Where-Object { $_.Extension -eq ".tar" -or $_.FullName -match "blobs[\\/]sha256" } | ForEach-Object {
        $LayerDir = Join-Path $TempDir ("extract_" + $_.BaseName)
        New-Item -ItemType Directory -Path $LayerDir -Force | Out-Null
        tar -xf $_.FullName -C $LayerDir 2>$null

        Get-ChildItem -Path $LayerDir -Recurse -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.Length -lt 2MB } | ForEach-Object {
            if ($_.Name.StartsWith(".wh.")) {
                Write-Warning "[WHITEOUT] Deleted file marker $($_.Name) in layer $($_.DirectoryName)"
            }
            foreach ($entry in $SecretPatterns.GetEnumerator()) {
                Select-String -LiteralPath $_.FullName -Pattern $entry.Value -AllMatches -ErrorAction SilentlyContinue | ForEach-Object {
                    Write-Host "[SECRET HIT: $($entry.Key)] $($_.Path):L$($_.LineNumber)" -ForegroundColor Red
                }
            }
        }
        Remove-Item $LayerDir -Recurse -Force -ErrorAction SilentlyContinue
    }
} finally {
    Remove-Item $TempDir -Recurse -Force -ErrorAction SilentlyContinue
}
```

---

## 🛠️ Complete 2026 Container Security Toolchain Matrix

| Category | Tool | Command Recipe | Primary Purpose |
| :--- | :--- | :--- | :--- |
| **Static AST & CIS Audit** | `audit_container.py` | `python scripts/audit_container.py . --scan-secrets` | Zero-dependency Dockerfile, Compose, Runtime & Secret/Entropy auditor |
| **Deep Multi-Tool Audit (Bash)** | `deep_audit_docker.sh` | `bash scripts/deep_audit_docker.sh -i app:1.0 -d .` | End-to-end layer unpack, Ghost Secret, Grype/Syft & TruffleHog pipeline |
| **Deep Multi-Tool Audit (PS1)** | `Invoke-DockerDeepAudit.ps1` | `pwsh -File scripts/Invoke-DockerDeepAudit.ps1 -Image app:1.0` | Native Windows/Cross-platform PowerShell layer, entropy & CVE auditor |
| **SBOM Generation** | **Anchore Syft** | `syft app:1.0 --scope all-layers -o cyclonedx-json=sbom.json` | Extracts OS packages + Go/Rust/Python/Node binary metadata across all layers |
| **CVE Vulnerability Gate** | **Anchore Grype** | `grype sbom:sbom.json --by-cve --only-fixed --fail-on high` | Ultra-fast CVE matching with EPSS, CISA KEV & OpenVEX filtering |
| **Verified Secret Scanning** | **TruffleHog** | `trufflehog docker --image=app:1.0 --results=verified,unknown` | Scans every historical OCI layer and verifies live cloud credentials |
| **Layer Bloat & Efficiency** | **Dive** | `CI=true dive app:1.0` | Detects wasted space and modified/deleted files across image layers |
| **Dockerfile AST Linter** | **Hadolint** | `hadolint Dockerfile --failure-threshold warning` | Parses Dockerfile AST and ShellCheck rules inside `RUN` steps |
| **CIS Image Benchmark** | **Dockle** | `dockle --exit-code 1 app:1.0` | Verifies CIS image benchmarks on built OCI images |
| **Image Signing & SLSA** | **Sigstore Cosign** | `cosign verify --certificate-identity=... app@sha256:...` | Cryptographic keyless OIDC verification of image signatures & attestations |

---

## 🚀 Quick Start for AI Coding Agents & CLI

### 1. Run the Python CIS & Secret Auditor Directly
```bash
# Audit Dockerfiles, compose files, and scan for secrets/entropy across the repo
python scripts/audit_container.py . --scan-secrets

# Generate a GitHub-Flavored Markdown Audit Report
python scripts/audit_container.py . --scan-secrets --markdown > AUDIT_REPORT.md

# Run inside a live container to inspect UID, capabilities, seccomp, and sockets
python scripts/audit_container.py --internal
```

### 2. Install as an AI Agent Skill (Claude Code / Cursor / Antigravity)
```bash
# Claude Code
mkdir -p .claude/skills/docker-hardening-auditor
cp SKILL.md .claude/skills/docker-hardening-auditor/SKILL.md

# Cursor
mkdir -p .cursor/rules
cp SKILL.md .cursor/rules/docker-hardening.mdc
```

---

## 🧪 Running the Test Suite

```bash
pytest tests/ -v
```

---

## 👤 Author & License

Built by **Joe B. (The Blind Hacker)**  
Website: `theblindhacker.com` | GitHub: `github.com/TheBlindHacker` | X: `@TheBlindHacker`  
Released under the **MIT License**.
