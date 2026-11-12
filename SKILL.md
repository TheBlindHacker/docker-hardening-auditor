---
name: docker-hardening-auditor
description: Comprehensive 2026 CIS Docker auditor, Grype/Syft SBOM & CVE workflow, TruffleHog + Regex layer secret hunter, and runtime container inspector.
compatibility: Claude Code, Cursor, Codex CLI, Gemini CLI, Antigravity, VS Code Copilot
metadata:
  author: Joe B. (The Blind Hacker)
  version: 2.0.0
  tags:
    - docker
    - containers
    - grype
    - syft
    - trufflehog
    - devsecops
    - cis-benchmark
    - hardening
    - kubernetes
---

# Docker & Container Security Hardening & Deep Forensics Suite (`docker-hardening-auditor` v2.0)

An enterprise-grade 2026 container security skill and multi-language auditing toolkit (**Python**, **Bash**, **PowerShell**) for AI coding agents (**Claude Code**, **Cursor**, **Codex CLI**, **Gemini CLI**, **Antigravity**) and DevSecOps engineers.

Automates static `Dockerfile` and `docker-compose.yml` AST/regex analysis, unpacked OCI image layer forensics ("Ghost Secret" & OverlayFS whiteout hunting), **Anchore Syft + Grype** multi-scope SBOM/CVE auditing, **TruffleHog + 12-Pattern Regex/Entropy** credential scanning, live in-container runtime triage, and drop-in hardening remediation aligned with the **CIS Docker Benchmark v1.6.0 / v1.7.0** and **NIST SP 800-190**.

---

## 🎯 When to Activate This Skill

Invoke this skill whenever:
- Auditing `Dockerfile`, `Containerfile`, or `docker-compose.yml` files for misconfigurations or privilege escalation risks.
- Hunting for leaked secrets, API keys, private keys, or `.env` files across current build contexts, `docker history --no-trunc`, or deleted intermediate OCI image layers (`docker save` tarball forensics).
- Orchestrating **Anchore Grype**, **Syft**, **TruffleHog**, **Trivy**, **Dive**, **Dockle**, **Hadolint**, or **Cosign** in local audits or CI/CD gates.
- Converting legacy root containers (`UID 0`) to unprivileged **non-root** (`UID 10001:10001`), **Rootless**, or **Distroless / Wolfi** execution.
- Locking down 2026 Linux kernel attack surfaces (`io_uring`, `eBPF`, `userfaultfd`, Cgroups v2 `cgroup: private`, `pids_limit`, and `runc` file-descriptor leaks like `CVE-2024-21626`).
- Performing live runtime triage inside running containers (`docker exec` / Kubernetes pod shells).

---

## 🔒 The 12-Point CIS Docker & 2026 Hardening Benchmark

When evaluating container assets, systematically audit against these 12 defense-in-depth pillars:

### 1. Root Execution Elimination & User Namespaces (CIS 4.1 / CWE-250)
- **Vulnerability**: Container runs as `root` (`UID 0`), granting host-equivalent privileges if a container breakout vulnerability is exploited.
- **Remediation**: Explicitly create and run as a non-root system user with numeric `UID:GID` (`10001:10001` avoids colliding with host UIDs `1000–9999`), and enable User Namespace remapping (`--userns-remap=default` or Kubernetes `hostUsers: false`):
  ```dockerfile
  RUN groupadd -g 10001 appgroup && \
      useradd -u 10001 -g appgroup -s /usr/sbin/nologin -M -d /nonexistent appuser
  USER 10001:10001
  ```

### 2. Linux Capabilities Dropping (CIS 5.3 / Least Privilege)
- **Vulnerability**: Container inherits default Docker Linux capabilities (`CAP_NET_RAW`, `CAP_CHOWN`, `CAP_MKNOD`, `CAP_AUDIT_WRITE`) or runs with `privileged: true`.
- **Remediation**: Drop **ALL** capabilities and selectively re-add only what is strictly required:
  ```yaml
  cap_drop:
    - ALL
  cap_add:
    - NET_BIND_SERVICE # Only if binding to ports < 1024
  ```

### 3. Immutable Root Filesystem & Hardened `tmpfs` (CIS 5.12 / CWE-653)
- **Vulnerability**: Writable root filesystem allows attackers who exploit an RCE to drop binary payloads, modify application code, or persist implants.
- **Remediation**: Enforce `read_only: true` with `noexec,nosuid,nodev` ephemeral `tmpfs` mounts:
  ```yaml
  read_only: true
  tmpfs:
    - /tmp:rw,noexec,nosuid,nodev,size=64m
    - /run:rw,noexec,nosuid,nodev,size=16m
  ```

### 4. Privilege Escalation & SUID/SGID Elimination (CIS 5.25 / CWE-250)
- **Vulnerability**: Processes can acquire additional privileges via SUID/SGID binaries (`mount`, `su`, `passwd`, `newgrp`).
- **Remediation**: Strip SUID/SGID bits during build and enforce `no-new-privileges:true` at runtime:
  ```dockerfile
  RUN find / -xdev -perm /6000 -type f -exec chmod a-s {} + 2>/dev/null || true
  ```
  ```yaml
  security_opt:
    - no-new-privileges:true
  ```

### 5. Dangerous Host Mounts & Runtime Socket Exposure (CIS 5.31 / CWE-250)
- **Vulnerability**: Mounting `/var/run/docker.sock`, `/run/containerd/containerd.sock`, `/proc`, `/sys`, or `/etc`. Access to the container runtime socket grants instant root takeover of the physical host.
- **Remediation**: Never mount runtime sockets into application containers. If read-only metadata is required, route through an isolated, read-only socket proxy enforcing strict HTTP verb/endpoint allowlists.

### 6. Resource Quotas, `pids_limit` & Cgroups v2 Isolation (CIS 5.10 / 5.11 / 5.28)
- **Vulnerability**: Missing CPU, memory, or PID ceilings allow a single container fork-bomb or memory leak to starve the host OS. Shared host cgroup namespaces expose legacy cgroup `release_agent` escape primitives.
- **Remediation**: Enforce `cgroup: private`, `pids_limit`, and memory/CPU ceilings:
  ```yaml
  cgroup: private
  pids_limit: 256
  deploy:
    resources:
      limits:
        cpus: "1.50"
        memory: 1024M
      reservations:
        cpus: "0.25"
        memory: 256M
  ```

### 7. Cryptographic Digest Pinning & Zero-CVE Base Images (CIS 4.2)
- **Vulnerability**: Mutable tags (`:latest`, `:3.12`) are vulnerable to upstream tag mutation and supply-chain poisoning. Standard Debian/Ubuntu base images ship with hundreds of unnecessary OS packages and shell utilities (`/bin/sh`, `apt`).
- **Remediation**: Pin immutable `@sha256:...` digests and prefer **Distroless** (`gcr.io/distroless/static-debian12`) or **Wolfi / Chainguard** runtime images:
  ```dockerfile
  FROM python:3.12-slim@sha256:7f0c1a4b95f2694b8e8f8564f9bf51737e1b9b91c13d7ff43a5796a5dd608bfa
  ```

### 8. Multi-Stage Builds & `runc` FD Leak Defense (`CVE-2024-21626`)
- **Vulnerability**: Compilers (`gcc`), headers, and build tools left in production images expand post-exploitation capabilities. Malicious base images using `WORKDIR /proc/self/fd/<N>` can exploit leaked host file descriptors in older `runc` versions (`< 1.1.12`).
- **Remediation**: Separate build and runtime stages cleanly, audit `WORKDIR` directives for `/proc/self/fd` references, and keep host `runc`/`containerd` patched.

### 9. BuildKit Secret Mounts vs. `ARG`/`ENV` & OverlayFS "Ghost Secrets" (CIS 4.7 / CWE-312)
- **Vulnerability**:
  1. Passing secrets via `ARG` or `ENV` bakes them permanently into `docker inspect` and `docker history --no-trunc`.
  2. Copying a secret file in one layer (`COPY .npmrc /root/.npmrc`) and deleting it in a later layer (`RUN rm -f /root/.npmrc`) creates an **OverlayFS whiteout marker (`.wh..npmrc`)** in the upper layer while leaving the raw secret file **100% intact** inside the lower layer's `.tar` blob!
- **Remediation**: Use BuildKit ephemeral secret mounts (`--mount=type=secret`), which mount into an in-memory `tmpfs` only for that single `RUN` instruction and never touch any image layer:
  ```dockerfile
  # syntax=docker/dockerfile:1.7
  RUN --mount=type=secret,id=pkg_config,target=/run/secrets/pkg_config \
      pip install --no-cache-dir --config-settings="--global-option=..." -r requirements.txt
  ```

### 10. 2026 Kernel Seccomp Profile (`io_uring`, `eBPF`, `userfaultfd` Lockdown)
- **Vulnerability**: Over 60% of Linux kernel container escape CVEs in 2024–2026 abused `io_uring` (`io_uring_setup`, `io_uring_enter`, `io_uring_register`), `bpf`, `userfaultfd`, `keyctl`, or `unshare`. Running with `seccomp:unconfined` or legacy seccomp profiles leaves these syscalls exposed.
- **Remediation**: Attach the included `templates/seccomp-2026-hardened.json` profile blocking `io_uring_*`, `bpf`, `userfaultfd`, `kexec_load`, `ptrace`, `keyctl`, and `unshare`:
  ```yaml
  security_opt:
    - no-new-privileges:true
    - seccomp:templates/seccomp-2026-hardened.json
  ```

### 11. 2026 OCI Supply Chain Provenance, SBOM Attestations & Cosign
- **Vulnerability**: Deploying unsigned images without verifiable SLSA build provenance or embedded SBOMs prevents admission controllers (Kyverno / OPA Gatekeeper) from verifying image authenticity.
- **Remediation**: Build with BuildKit SLSA provenance + SBOM attestations and sign with **Sigstore Cosign**:
  ```bash
  docker buildx build \
    --attest type=sbom \
    --attest type=provenance,mode=max \
    -t company/hardened-api:2.0.0 .
  cosign sign --yes company/hardened-api@sha256:...
  ```

### 12. Native Socket Liveness Healthchecks (CIS 4.6)
- **Vulnerability**: Installing network download tools inside production images solely to run `HEALTHCHECK` provides attackers with ready-made exfiltration binaries.
- **Remediation**: Use language-native socket probes or a minimal statically compiled healthcheck binary:
  ```dockerfile
  HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python3", "-c", "import socket; s = socket.socket(); s.connect(('127.0.0.1', 8080)); s.close()"]
  ```

---

## 🧠 Deep Dive: What We Learned Auditing with Anchore `Grype` & `Syft`

Years of production vulnerability auditing with **Anchore Syft** and **Grype** across enterprise container fleets taught several critical lessons that standard quick-start guides miss:

### 1. Decouple `Syft` SBOM Generation from `Grype` CVE Matching
Scanning a 1.5 GB container image directly with a vulnerability scanner on every run re-extracts layers repeatedly. Instead, generate a **CycloneDX SBOM** once with `Syft` (capturing all layers) and feed that SBOM into `Grype`:
```bash
# Step 1: Generate comprehensive CycloneDX SBOM across all layers once
syft myorg/app:2.0.0 --scope all-layers -o cyclonedx-json=sbom.cdx.json

# Step 2: Run Grype against the SBOM in < 1 second
grype sbom:sbom.cdx.json --by-cve --only-fixed --fail-on high
```

### 2. `--scope squashed` vs. `--scope all-layers`
- **`--scope squashed` (Default)**: Evaluates only the final merged filesystem view seen by a running container. If a build tool or vulnerable library was deleted in an intermediate layer, `--scope squashed` hides it.
- **`--scope all-layers` (Forensic Mode)**: Inspects every intermediate layer tarball. Essential for compliance audits and verifying that deleted packages or build-stage artifacts did not leave behind exploitable libraries or credentials in earlier layers.

### 3. Auditing Distroless, `scratch`, and Statically Compiled Go / Rust Images
When you migrate to `gcr.io/distroless/static-debian12` or `FROM scratch`, `/var/lib/dpkg/status` and `/lib/apk/db/installed` no longer exist. Naive OS-package scanners report **"0 vulnerabilities"** while your compiled Go or Rust binary links vulnerable `golang.org/x/crypto` or `openssl` crates!
- **Solution**: `Syft` and `Grype` inspect ELF binary sections (`.go.buildinfo` for Go and `.dep-v0` / `cargo-auditable` for Rust). Ensure Rust binaries are built with `cargo auditable build --release` and Go binaries retain buildinfo (do not strip with `-buildvcs=false`).

### 4. Taming False Positives with `--only-fixed`, EPSS, KEV, and OpenVEX
- **`--only-fixed`**: Filters out upstream Linux distribution CVEs marked `wontfix` or `unfixed` (such as low-impact local DoS flaws in `glibc` or `systemd` libraries that have no upstream patch), focusing developer remediation on actionable upgrades.
- **EPSS & CISA KEV Triage**: Use `grype sbom:sbom.cdx.json -o json` to prioritize CVEs where **EPSS >= 0.10 (10% probability of exploitation in the wild)** or the CVE appears in CISA's **Known Exploited Vulnerabilities (KEV)** catalog.
- **Declarative `.grype.yaml` & OpenVEX**: Store reviewed false positives in `.grype.yaml` under version control rather than passing ad-hoc CLI flags:
  ```yaml
  # .grype.yaml
  ignore:
    - vulnerability: CVE-2023-45853
      reason: "zlib MiniZip overflow not compiled or reachable in runtime Python binary (Reviewed 2026-11)"
      package:
        name: zlib1g
  ```

---

## 🕵️ Going Deeper: Hunting Secrets in Layers with TruffleHog & Regex

### 1. Why Secrets Survive `RUN rm` Inside Docker Images
Docker images are a stack of immutable tar archives (`blobs/sha256/*`). If Layer 3 runs `COPY .env /app/.env` and Layer 5 runs `RUN rm /app/.env`, Layer 5 merely writes a zero-byte whiteout file named `/app/.wh..env`. Anyone who pulls the image can run `docker save myorg/app:latest -o image.tar`, extract Layer 3, and read `/app/.env` in plain text.

### 2. Multi-Layer Credential Verification with `TruffleHog`
```bash
# Scan all layers of a local or remote Docker image (including deleted files in historical layers!)
trufflehog docker --image=myorg/app:2.0.0 --results=verified,unknown --json

# Scan only verified live credentials (queries cloud provider APIs to confirm active status)
trufflehog docker --image=myorg/app:2.0.0 --only-verified

# Scan local build context before building
trufflehog filesystem . --results=verified,unknown --fail
```

### 3. Included Deep Audit & Secret-Hunting Scripts (`scripts/`)

This suite ships with three cross-platform scripts that automate static CIS hardening checks, `docker save` layer unpacking, OverlayFS `.wh.*` whiteout detection, 12-Pattern Regex + Shannon Entropy (`H >= 4.25`) secret hunting, `Syft` + `Grype` CVE gates, and live container inspection:

#### A. Bash Deep Auditor (`scripts/deep_audit_docker.sh`)
```bash
# Full audit: unpack image layers, hunt ghost secrets, run TruffleHog + Grype/Syft, and audit local repo
bash scripts/deep_audit_docker.sh --image myorg/api:2.0.0 --dir . --output AUDIT_REPORT.md

# Audit a live running container + local compose files
bash scripts/deep_audit_docker.sh --container hardened-api-prod --dir .
```

#### B. PowerShell Deep Auditor (`scripts/Invoke-DockerDeepAudit.ps1`)
```powershell
# Full audit on Windows / PowerShell 7+ with JSON and Markdown output
pwsh -File scripts/Invoke-DockerDeepAudit.ps1 `
  -Image "myorg/api:2.0.0" `
  -Directory "." `
  -JsonOutputPath "audit-results.json" `
  -MarkdownOutputPath "AUDIT_REPORT.md"
```

#### C. Zero-Dependency Python CIS & Secret Auditor (`scripts/audit_container.py`)
```bash
# Static CIS benchmark + Regex & Shannon Entropy secret scan across repository or unpacked layers
python scripts/audit_container.py . --scan-secrets --markdown > AUDIT_REPORT.md

# Run inside a live container to inspect UID, /proc/self/status CapEff, Seccomp mode, UserNS, and sockets
python scripts/audit_container.py --internal --json
```

---

## 🔍 Live In-Container Runtime Triage (`docker exec` / SSH)

When evaluating a live running container from an interactive shell:

```bash
# 1. Verify Non-Root Execution & User Namespace Remapping
id && cat /proc/self/uid_map
# Compliant uid_map maps container UIDs to unprivileged host subuids (e.g. 0 100000 65536)

# 2. Decode Effective Kernel Capabilities, NoNewPrivs & Seccomp Mode
grep -E '^(Cap(Inh|Prm|Eff|Bnd)|NoNewPrivs|Seccomp):' /proc/self/status
# Compliant: CapEff=0000000000000000 (or 0000000000000400 for NET_BIND_SERVICE), NoNewPrivs=1, Seccomp=2

# 3. Hunt for SUID / SGID Privilege Escalation Binaries
find / -xdev -perm /6000 -type f -exec ls -la {} + 2>/dev/null

# 4. Verify Immutable Root Filesystem
touch /.__rw_probe 2>&1

# 5. Check for Exposed Host Runtime Sockets
ls -la /var/run/docker.sock /run/containerd/containerd.sock 2>/dev/null
```

---

## 📊 Standard Deliverable: Hardening & Deep Forensics Audit Report

When presenting audit results to the user, format the output as follows:

```markdown
# 🛡️ Docker & Container Security Audit: [Target Path / Image Name]

## Executive Summary
- **Overall Risk Level**: [CRITICAL / HIGH / MEDIUM / PASS]
- **CIS & 2026 Benchmark Compliance**: [X] / 12 Pillars Passed
- **Layer & Secret Forensics**: [CLEAN / GHOST SECRETS DETECTED]
- **Grype CVE Gate (`--only-fixed`)**: [X Critical / Y High]

## Detailed Findings Matrix
| Severity | Code | Title | Location / Layer | Recommended Mitigation |
| :--- | :--- | :--- | :--- | :--- |
| **CRITICAL** | `DF-NO-USER` | Container Runs as Root (UID 0) | `Dockerfile:L1` | Add `USER 10001:10001` |
| **CRITICAL** | `SEC-AWS-KEY-ID` | AWS Access Key in Layer #2 | `Layer#2:/app/.env:L4` | Rotate key & rebuild with BuildKit secret mounts |
| **HIGH** | `DC-UNCONFINED-MAC` | Seccomp Profile Unconfined | `docker-compose.yml:L27` | Attach `templates/seccomp-2026-hardened.json` |

## Drop-In Remediation (Hardened Config & Build Commands)
[Provide complete, copy-pasteable hardened Dockerfile, docker-compose.yml, and BuildKit commands]
```
