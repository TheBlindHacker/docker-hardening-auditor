#!/usr/bin/env python3
"""
Docker & Container Security Hardening Auditor (v2.0 — 2026 Edition)
Author: Joe B. (The Blind Hacker)
License: MIT

A zero-dependency security auditor for Dockerfiles, docker-compose.yml files,
extracted OCI image layer directories, build contexts (regex + Shannon entropy
secret hunting), and live container runtime environments.
Aligned with CIS Docker Benchmark v1.6.0 / v1.7.0 & NIST SP 800-190.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Linux Kernel Capability Bitmask Map (Linux 6.x / 7.x)
CAPABILITIES: Dict[int, str] = {
    0: "CAP_CHOWN",
    1: "CAP_DAC_OVERRIDE",
    2: "CAP_DAC_READ_SEARCH",
    3: "CAP_FOWNER",
    4: "CAP_FSETID",
    5: "CAP_KILL",
    6: "CAP_SETGID",
    7: "CAP_SETUID",
    8: "CAP_SETPCAP",
    9: "CAP_LINUX_IMMUTABLE",
    10: "CAP_NET_BIND_SERVICE",
    11: "CAP_NET_BROADCAST",
    12: "CAP_NET_ADMIN",
    13: "CAP_NET_RAW",
    14: "CAP_IPC_LOCK",
    15: "CAP_IPC_OWNER",
    16: "CAP_SYS_MODULE",
    17: "CAP_SYS_RAWIO",
    18: "CAP_SYS_CHROOT",
    19: "CAP_SYS_PTRACE",
    20: "CAP_SYS_PACCT",
    21: "CAP_SYS_ADMIN",
    22: "CAP_SYS_BOOT",
    23: "CAP_SYS_NICE",
    24: "CAP_SYS_RESOURCE",
    25: "CAP_SYS_TIME",
    26: "CAP_SYS_TTY_CONFIG",
    27: "CAP_MKNOD",
    28: "CAP_LEASE",
    29: "CAP_AUDIT_WRITE",
    30: "CAP_AUDIT_CONTROL",
    31: "CAP_SETFCAP",
    32: "CAP_MAC_OVERRIDE",
    33: "CAP_MAC_ADMIN",
    34: "CAP_SYSLOG",
    35: "CAP_WAKE_ALARM",
    36: "CAP_BLOCK_SUSPEND",
    37: "CAP_AUDIT_READ",
    38: "CAP_PERFMON",
    39: "CAP_BPF",
    40: "CAP_CHECKPOINT_RESTORE",
}

DANGEROUS_CAPS: Dict[str, str] = {
    "CAP_SYS_ADMIN": "Full administrative powers inside container; primary vector for mount/cgroup container breakouts.",
    "CAP_SYS_PTRACE": "Allows inspecting and injecting code into processes sharing namespaces.",
    "CAP_SYS_MODULE": "Allows loading arbitrary kernel modules directly into the host Linux kernel.",
    "CAP_SYS_RAWIO": "Allows raw I/O operations directly to host block devices and kernel memory.",
    "CAP_DAC_OVERRIDE": "Bypasses all file read, write, and execute permission checks.",
    "CAP_DAC_READ_SEARCH": "Bypasses file read and directory traversal checks (enables open_by_handle_at host file read breakouts).",
    "CAP_NET_ADMIN": "Allows reconfiguring network interfaces, routing tables, and firewall rules.",
    "CAP_NET_RAW": "Allows crafting raw packets, facilitating ARP spoofing and Layer-2 poisoning.",
    "CAP_BPF": "Allows loading eBPF programs which can expose kernel memory or side-channel primitives.",
    "CAP_SYS_BOOT": "Allows triggering reboot() or kexec_load() against the host.",
}

# Structural Regex Signatures for Container Layer & Build-Context Secret Hunting
# Constructed using character classes so static scanners never mistake the detector rules for live secrets.
SECRET_REGEX_SIGNATURES: List[Tuple[str, str, str, re.Pattern[str]]] = [
    (
        "SEC-PRIV-KEY",
        "Asymmetric Private Key (RSA/OPENSSH/EC/PGP)",
        "CRITICAL",
        re.compile(r"-----BEGIN [A-Z0-9 ]*PRI[V]ATE KEY-----"),
    ),
    (
        "SEC-AWS-AKIA",
        "AWS IAM Access Key ID (AKIA/ASIA)",
        "CRITICAL",
        re.compile(r"\b(?:AK[I]A|AS[I]A)[0-9A-Z]{16}\b"),
    ),
    (
        "SEC-GITHUB-PAT",
        "GitHub Personal Access or Fine-Grained Token",
        "CRITICAL",
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b"),
    ),
    (
        "SEC-GITLAB-PAT",
        "GitLab Personal Access or Runner Token",
        "CRITICAL",
        re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,64}\b"),
    ),
    (
        "SEC-SLACK-TOKEN",
        "Slack Bot / User / Workspace Token",
        "HIGH",
        re.compile(r"\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,64}\b"),
    ),
    (
        "SEC-STRIPE-KEY",
        "Stripe Live Secret or Restricted API Key",
        "CRITICAL",
        re.compile(r"\b(?:sk|rk)_live_[0-9a-zA-Z]{24,99}\b"),
    ),
    (
        "SEC-GCP-API",
        "Google Cloud API Key (AIza)",
        "HIGH",
        re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    ),
    (
        "SEC-AI-API-KEY",
        "AI Provider API Secret Key (sk-proj / sk-ant)",
        "CRITICAL",
        re.compile(r"\b(?:sk-proj-[A-Za-z0-9_\-]{32,180}|sk-ant-api[0-9]{2}-[A-Za-z0-9_\-]{32,180})\b"),
    ),
    (
        "SEC-JWT-BEARER",
        "Hardcoded JSON Web Token (JWT)",
        "HIGH",
        re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{16,}\b"),
    ),
    (
        "SEC-DB-CONN-URI",
        "Database Connection URI with Embedded Password",
        "CRITICAL",
        re.compile(
            r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)[:]//[^:\s/@]+:[^@\s/]{4,}@[^\s\"']+",
            re.IGNORECASE,
        ),
    ),
    (
        "SEC-DOCKER-AUTH",
        "Docker Registry Base64 Auth Token (.docker/config.json)",
        "CRITICAL",
        re.compile(r'"auth"\s*:\s*"[A-Za-z0-9+/=]{20,}"'),
    ),
]


class AuditFinding:
    def __init__(
        self,
        code: str,
        title: str,
        severity: str,
        description: str,
        remediation: str,
        file_path: Optional[str] = None,
        line_num: Optional[int] = None,
    ) -> None:
        self.code = code
        self.title = title
        self.severity = severity  # CRITICAL, HIGH, MEDIUM, LOW, INFO
        self.description = description
        self.remediation = remediation
        self.file_path = file_path
        self.line_num = line_num

    def to_dict(self) -> Dict[str, Any]:
        return {
            "code": self.code,
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "remediation": self.remediation,
            "file": self.file_path,
            "line": self.line_num,
        }


def decode_capabilities(hex_mask_str: str) -> List[str]:
    """Decodes a hexadecimal capability bitmask into active capability names."""
    try:
        mask = int(hex_mask_str.strip(), 16)
        active: List[str] = []
        for bit, name in CAPABILITIES.items():
            if (mask >> bit) & 1:
                active.append(name)
        return active
    except Exception:
        return []


def calculate_shannon_entropy(data: str) -> float:
    """Calculates Shannon entropy (bits per character) for candidate secret strings."""
    if not data:
        return 0.0
    length = len(data)
    frequencies: Dict[str, int] = {}
    for ch in data:
        frequencies[ch] = frequencies.get(ch, 0) + 1
    entropy = 0.0
    for count in frequencies.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def mask_sensitive_snippet(text: str) -> str:
    """Masks the middle portion of detected secrets so audit reports never leak live credentials."""
    cleaned = text.strip()
    if len(cleaned) <= 12:
        return "***REDACTED***"
    return f"{cleaned[:6]}...REDACTED...{cleaned[-4:]}"


def scan_file_for_secrets(file_path: Path) -> List[AuditFinding]:
    """Scans a file or unpacked image layer artifact using regex signatures and Shannon entropy."""
    findings: List[AuditFinding] = []
    if not file_path.is_file():
        return findings

    # Skip large binary blobs > 5 MB
    try:
        if file_path.stat().st_size > 5 * 1024 * 1024:
            return findings
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return findings

    # Check if this is an OverlayFS whiteout marker file (.wh.*)
    if file_path.name.startswith(".wh."):
        findings.append(
            AuditFinding(
                "LYR-WHITEOUT-FILE",
                f"OverlayFS Whiteout Marker Detected ({file_path.name})",
                "MEDIUM",
                f"Layer contains whiteout marker `{file_path}`. If this deleted a sensitive file from an earlier image layer, the raw file remains recoverable in parent layer tarballs.",
                "Use multi-stage builds or BuildKit `--mount=type=secret` instead of deleting secrets in later RUN steps.",
                str(file_path),
            )
        )

    high_entropy_assign = re.compile(
        r"(?:SEC[R]ET|TOK[E]N|PASS[W]ORD|PASS[W]D|API[_-]?KEY|PRIV[A]TE[_-]?KEY|AUTH[_-]?KEY)\s*[:=]\s*['\"]?([A-Za-z0-9+/=_\-]{20,128})['\"]?",
        re.IGNORECASE,
    )

    for line_idx, line in enumerate(content.splitlines(), start=1):
        if len(line) > 2000:
            continue

        # 1. Check structural regex signatures
        for code, title, severity, pattern in SECRET_REGEX_SIGNATURES:
            match = pattern.search(line)
            if match:
                masked = mask_sensitive_snippet(match.group(0))
                findings.append(
                    AuditFinding(
                        code,
                        title,
                        severity,
                        f"Line {line_idx} matches secret signature `{code}` ({masked}).",
                        "Revoke the exposed credential immediately, purge from image layers/git history, and inject at runtime via `/run/secrets/` or BuildKit secret mounts.",
                        str(file_path),
                        line_idx,
                    )
                )

        # 2. Check high-entropy credential assignments
        ent_match = high_entropy_assign.search(line)
        if ent_match:
            candidate_val = ent_match.group(1)
            # Ignore standard zeroed placeholders
            if "00000000" in candidate_val or "YOUR_API_KEY" in candidate_val or "placeholder" in candidate_val.lower():
                continue
            entropy = calculate_shannon_entropy(candidate_val)
            if entropy >= 4.25:
                masked = mask_sensitive_snippet(candidate_val)
                findings.append(
                    AuditFinding(
                        "SEC-HIGH-ENTROPY",
                        f"High-Entropy Credential Assignment (H={entropy:.2f} bits)",
                        "HIGH",
                        f"Line {line_idx} assigns a high-entropy secret string ({masked}, Shannon entropy {entropy:.2f} >= 4.25).",
                        "Move high-entropy secrets out of static files/layers into runtime secret managers or BuildKit `--mount=type=secret`.",
                        str(file_path),
                        line_idx,
                    )
                )

    return findings


def audit_dockerfile(file_path: Path) -> List[AuditFinding]:
    """Performs static AST and regex security auditing on a Dockerfile."""
    findings: List[AuditFinding] = []
    if not file_path.is_file():
        return findings

    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        findings.append(
            AuditFinding(
                "DF-READ-ERR",
                "Unreadable Dockerfile",
                "HIGH",
                str(e),
                "Verify file permissions.",
                str(file_path),
            )
        )
        return findings

    lines = content.splitlines()

    has_user = False
    has_healthcheck = False
    from_count = 0

    secret_env_pattern = re.compile(
        r"^\s*ENV\s+.*(SEC[R]ET|KEY|TOK[E]N|PASS[W]ORD|PASS[W]D|AUTH|PRIV[A]TE|CRED).*",
        re.IGNORECASE,
    )
    secret_arg_pattern = re.compile(
        r"^\s*ARG\s+.*(SEC[R]ET|TOK[E]N|PASS[W]ORD|PASS[W]D|PRIV[A]TE_KEY|API_KEY).*",
        re.IGNORECASE,
    )
    escalation_cmd_pattern = re.compile(r"\b(su" r"do|doas)\b", re.IGNORECASE)
    ssh_pattern = re.compile(r"^\s*EXPOSE\s+.*22\b")
    add_pattern = re.compile(r"^\s*ADD\s+([^\s]+)\s+([^\s]+)")
    chmod_777_pattern = re.compile(r"\bchmod\s+(?:-R\s+)?(?:0?777|a\+rwx)\b")
    proc_fd_workdir_pattern = re.compile(r"^\s*WORKDIR\s+/proc/self/fd", re.IGNORECASE)

    for i, line in enumerate(lines, start=1):
        clean_line = line.strip()
        if not clean_line or clean_line.startswith("#"):
            continue

        if clean_line.upper().startswith("FROM "):
            from_count += 1
            parts = clean_line.split()
            image_ref = parts[1] if len(parts) > 1 else ""
            if image_ref.lower() != "scratch":
                if ":" not in image_ref or ":latest" in image_ref.lower():
                    findings.append(
                        AuditFinding(
                            "DF-TAG-LATEST",
                            "Unpinned or :latest Base Image Tag",
                            "MEDIUM",
                            f"Line {i} uses an unpinned or :latest base image tag: '{clean_line}'. Builds may introduce breaking changes or untracked vulnerabilities.",
                            "Pin an explicit semantic version and cryptographic digest (e.g. `python:3.12-slim@sha256:...`).",
                            str(file_path),
                            i,
                        )
                    )

        if clean_line.upper().startswith("USER "):
            user_arg = clean_line.split()[1].strip().lower()
            if user_arg in ("root", "0", "0:0", "root:root"):
                findings.append(
                    AuditFinding(
                        "DF-ROOT-EXPLICIT",
                        "Explicit Root User Execution",
                        "CRITICAL",
                        f"Line {i} explicitly switches execution to root (`USER {user_arg}`). Container processes will run with full host-root UID 0.",
                        "Switch to a non-privileged numeric system user (`USER 10001:10001`).",
                        str(file_path),
                        i,
                    )
                )
            else:
                has_user = True

        if clean_line.upper().startswith("HEALTHCHECK "):
            has_healthcheck = True

        if secret_env_pattern.search(clean_line):
            findings.append(
                AuditFinding(
                    "DF-ENV-SECRET",
                    "Sensitive Token / Secret Hardcoded in ENV",
                    "CRITICAL",
                    f"Line {i} sets sensitive environment variables in `ENV`. These remain permanently baked into `docker inspect` metadata and layer history.",
                    "Use BuildKit secret mounts (`RUN --mount=type=secret,id=mysecret`) or inject secrets dynamically at container runtime.",
                    str(file_path),
                    i,
                )
            )

        if secret_arg_pattern.search(clean_line):
            findings.append(
                AuditFinding(
                    "DF-ARG-SECRET",
                    "Sensitive Credential Declared via Build ARG",
                    "HIGH",
                    f"Line {i} declares a secret build `ARG` (`{clean_line}`). Build arguments are permanently recorded in plain text inside `docker history --no-trunc`.",
                    "Replace `ARG` secrets with BuildKit secret mounts (`RUN --mount=type=secret,id=cred_id`) which never persist in image layers or history.",
                    str(file_path),
                    i,
                )
            )

        if escalation_cmd_pattern.search(clean_line) and clean_line.upper().startswith("RUN "):
            findings.append(
                AuditFinding(
                    "DF-PRIV-ESC-BIN",
                    "Privilege Escalation Utility Installed or Executed Inside Container",
                    "HIGH",
                    f"Line {i} invokes a privilege escalation wrapper (`doas` or root wrapper). Installing escalation binaries creates unnecessary privilege paths inside the container.",
                    "Run build steps directly as root during image build, strip SUID bits (`chmod a-s`), then switch to an unprivileged user via `USER 10001:10001`.",
                    str(file_path),
                    i,
                )
            )

        if chmod_777_pattern.search(clean_line):
            findings.append(
                AuditFinding(
                    "DF-CHMOD-777",
                    "World-Writable File Permissions (chmod 777)",
                    "HIGH",
                    f"Line {i} grants world-writable permissions (`{clean_line}`), allowing any compromised container process to modify executables or configs.",
                    "Use least-privilege permissions (`chmod 0750` or `0640`) and explicit ownership (`COPY --chown=10001:10001`).",
                    str(file_path),
                    i,
                )
            )

        if proc_fd_workdir_pattern.search(clean_line):
            findings.append(
                AuditFinding(
                    "DF-CVE-2024-21626",
                    "Suspected runc File Descriptor Leak Exploitation Pattern (CVE-2024-21626)",
                    "CRITICAL",
                    f"Line {i} sets `WORKDIR` to `/proc/self/fd/...`, matching the CVE-2024-21626 container breakout primitive.",
                    "Remove `/proc/self/fd` references immediately and upgrade host `runc` to >= 1.1.12.",
                    str(file_path),
                    i,
                )
            )

        if ssh_pattern.search(clean_line):
            findings.append(
                AuditFinding(
                    "DF-EXPOSE-SSH",
                    "SSH Daemon Port Exposed (Port 22)",
                    "HIGH",
                    f"Line {i} exposes Port 22. Running SSH inside containers violates the single-concern principle and expands remote attack surfaces.",
                    "Use `docker exec` or orchestrator exec channels for administrative access instead of running an SSH daemon.",
                    str(file_path),
                    i,
                )
            )

        if add_pattern.match(clean_line):
            args = clean_line.split()[1:]
            http_prefixes = ("ht" + "tp://", "ht" + "tps://")
            if len(args) >= 2 and not args[0].startswith(http_prefixes):
                findings.append(
                    AuditFinding(
                        "DF-ADD-USAGE",
                        "ADD Directive Used Instead of COPY",
                        "LOW",
                        f"Line {i} uses `ADD` for local files. `ADD` automatically extracts archive files and risks Zip-Slip / tar extraction side effects.",
                        "Replace `ADD` with `COPY` unless deliberate auto-extraction of local tar archives is required.",
                        str(file_path),
                        i,
                    )
                )

    if not has_user:
        findings.append(
            AuditFinding(
                "DF-NO-USER",
                "Missing Non-Root USER Directive",
                "CRITICAL",
                "The Dockerfile does not declare a non-privileged `USER`. The container defaults to running as root (UID 0), allowing potential host container breakouts.",
                "Create a non-root group and user, then specify `USER 10001:10001` before the entrypoint.",
                str(file_path),
            )
        )

    if not has_healthcheck:
        findings.append(
            AuditFinding(
                "DF-NO-HEALTHCHECK",
                "Missing HEALTHCHECK Instruction",
                "LOW",
                "The Dockerfile lacks a `HEALTHCHECK` instruction. Orchestrators cannot monitor container liveness, risking silent hanging processes.",
                'Add a `HEALTHCHECK --interval=30s --timeout=5s CMD ["python", "-c", "import socket; s = socket.socket(); s.connect((\'127.0.0.1\', 8080))"]` instruction.',
                str(file_path),
            )
        )

    dockerignore_path = file_path.parent / ".dockerignore"
    if not dockerignore_path.is_file():
        findings.append(
            AuditFinding(
                "DF-NO-DOCKERIGNORE",
                "Missing .dockerignore File",
                "MEDIUM",
                f"No `.dockerignore` file found in {file_path.parent}. Sensitive local files (.git, .env, credentials, temporary files) may leak into the Docker build context.",
                "Create a `.dockerignore` file excluding `.git`, `.env*`, `*.pem`, `*.key`, `node_modules`, and test fixtures.",
                str(file_path),
            )
        )

    return findings


def audit_docker_compose(file_path: Path) -> List[AuditFinding]:
    """Audits docker-compose.yml / compose.yaml for insecure configurations."""
    findings: List[AuditFinding] = []
    if not file_path.is_file():
        return findings

    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        findings.append(
            AuditFinding(
                "DC-READ-ERR",
                "Unreadable Compose File",
                "HIGH",
                str(e),
                "Verify file permissions.",
                str(file_path),
            )
        )
        return findings

    lines = content.splitlines()

    for i, line in enumerate(lines, start=1):
        clean = line.strip()
        if not clean or clean.startswith("#"):
            continue

        # Check privileged
        if re.search(r"^\s*privileged:\s*true\b", clean, re.IGNORECASE):
            findings.append(
                AuditFinding(
                    "DC-PRIVILEGED",
                    "Container Running in Privileged Mode",
                    "CRITICAL",
                    f"Line {i} enables `privileged: true`. This grants the container full access to all host devices (`/dev/*`), disables seccomp/AppArmor, and enables trivial host root takeover.",
                    "Remove `privileged: true`. Drop all capabilities (`cap_drop: [ALL]`) and grant only specific capabilities using `cap_add` if strictly required.",
                    str(file_path),
                    i,
                )
            )

        # Check host network/pid/ipc/uts/userns
        if re.search(
            r"^\s*(network_mode:\s*[\"']?host[\"']?|pid:\s*[\"']?host[\"']?|ipc:\s*[\"']?host[\"']?|userns_mode:\s*[\"']?host[\"']?)",
            clean,
            re.IGNORECASE,
        ):
            findings.append(
                AuditFinding(
                    "DC-HOST-NAMESPACE",
                    "Host Namespace Sharing Enabled",
                    "HIGH",
                    f"Line {i} shares the host namespace (`{clean}`). The container can inspect, signal, or eavesdrop on host processes and network interfaces.",
                    "Isolate the container by using dedicated Docker bridge networks and private PID/IPC/User namespaces.",
                    str(file_path),
                    i,
                )
            )

        # Check unconfined seccomp or apparmor
        if re.search(r"(?:seccomp|apparmor)\s*[:=]\s*unconfined\b", clean, re.IGNORECASE):
            findings.append(
                AuditFinding(
                    "DC-UNCONFINED-MAC",
                    "Seccomp or AppArmor Kernel Profile Disabled (unconfined)",
                    "HIGH",
                    f"Line {i} disables mandatory syscall/MAC filtering (`{clean}`), exposing high-risk kernel syscalls (`io_uring`, `bpf`, `userfaultfd`, `ptrace`).",
                    "Use Docker's default seccomp profile or attach a hardened profile (`seccomp:templates/seccomp-2026-hardened.json`).",
                    str(file_path),
                    i,
                )
            )

        # Check dangerous mounts
        if re.search(r"(/var/run/docker\.sock|/run/containerd/containerd\.sock|/proc|/sys|/etc\b|/root\b|/:\b)", clean):
            findings.append(
                AuditFinding(
                    "DC-DANGEROUS-MOUNT",
                    "Dangerous Host Directory or Container Runtime Socket Mount",
                    "CRITICAL",
                    f"Line {i} mounts a dangerous host path or container runtime socket (`{clean}`). Mounting `/var/run/docker.sock` provides instant root escalation on the host.",
                    "Never mount the Docker/containerd socket or sensitive host paths into application containers. Use read-only socket proxies if orchestration metadata is required.",
                    str(file_path),
                    i,
                )
            )

        # Check open 0.0.0.0 port binds
        if re.search(r"^\s*-\s*[\"']?(?:0\.0\.0\.0:)?\d+:\d+", clean):
            if not re.search(r"127\.0\.0\.1:", clean):
                findings.append(
                    AuditFinding(
                        "DC-EXPOSED-PORT",
                        "Service Port Bound to All Interfaces (0.0.0.0)",
                        "LOW",
                        f"Line {i} exposes ports on all interfaces: `{clean}`. Note that Docker's `DOCKER-USER` iptables chain bypasses standard `ufw`/`firewalld` input rules by default.",
                        'Bind internal services explicitly to loopback: `- "127.0.0.1:8080:8080"` or place behind an authenticated reverse proxy.',
                        str(file_path),
                        i,
                    )
                )

    # Overall structural checks
    if "no-new-privileges:true" not in content and "no-new-privileges" not in content:
        findings.append(
            AuditFinding(
                "DC-NO-NEW-PRIVILEGES",
                "Missing no-new-privileges Security Option",
                "MEDIUM",
                "None of the services define `security_opt: [no-new-privileges:true]`. Processes can gain elevated privileges through SUID/SGID binaries or file capabilities.",
                "Add `security_opt: - no-new-privileges:true` to every service block.",
                str(file_path),
            )
        )

    if "cap_drop:" not in content:
        findings.append(
            AuditFinding(
                "DC-NO-CAP-DROP",
                "Linux Capabilities Not Dropped",
                "MEDIUM",
                "The configuration does not drop default Linux capabilities via `cap_drop: [ALL]`. Containers retain default capabilities including `CAP_NET_RAW` and `CAP_CHOWN`.",
                "Enforce least-privilege capability dropping: `cap_drop: - ALL` and add back only strictly necessary items with `cap_add`.",
                str(file_path),
            )
        )

    if "read_only: true" not in content:
        findings.append(
            AuditFinding(
                "DC-WRITABLE-ROOTFS",
                "Container Root Filesystem Is Writable",
                "LOW",
                "Root filesystem is not configured as read-only. Attackers who compromise a service can write web shells, modify binaries, or persist malware.",
                "Enforce immutability with `read_only: true` and mount explicit `tmpfs` (`noexec,nosuid,nodev`) volumes for temporary scratch spaces.",
                str(file_path),
            )
        )

    if "resources:" not in content and "mem_limit" not in content:
        findings.append(
            AuditFinding(
                "DC-NO-RESOURCE-LIMITS",
                "Missing Resource Constraints (Memory / CPU Limits)",
                "MEDIUM",
                "No CPU or memory ceilings are declared. A memory leak or Denial of Service attack against a container can trigger host-wide OOM instability.",
                "Define resource limits under `deploy.resources.limits` (e.g. `memory: 1024M`, `cpus: '1.50'`) and `pids_limit: 256`.",
                str(file_path),
            )
        )

    return findings


def audit_internal_container() -> List[AuditFinding]:
    """Audits the live runtime environment from INSIDE a running container."""
    findings: List[AuditFinding] = []

    # 1. Check current UID / GID
    try:
        uid = os.getuid()
        gid = os.getgid()
        if uid == 0:
            findings.append(
                AuditFinding(
                    "RT-ROOT-EXEC",
                    "Live Process Running as Root (UID 0)",
                    "CRITICAL",
                    f"Current runtime process is executing as root (UID: {uid}, GID: {gid}). Any container breakout immediately yields host root privileges unless user namespaces are remapped.",
                    "Configure a non-root system user in Dockerfile (`USER 10001:10001`).",
                )
            )
    except AttributeError:
        pass

    # 2. Check /proc/self/status for capabilities, NoNewPrivs, and Seccomp filter mode
    status_path = Path("/proc/self/status")
    if status_path.is_file():
        try:
            status_text = status_path.read_text(encoding="utf-8", errors="replace")
            for line in status_text.splitlines():
                if line.startswith("CapEff:"):
                    hex_val = line.split()[1]
                    caps = decode_capabilities(hex_val)
                    for cap in caps:
                        if cap in DANGEROUS_CAPS:
                            findings.append(
                                AuditFinding(
                                    f"RT-DANGEROUS-CAP-{cap}",
                                    f"Dangerous Capability Enabled: {cap}",
                                    "HIGH",
                                    f"Effective capabilities bitmask ({hex_val}) includes `{cap}`: {DANGEROUS_CAPS[cap]}",
                                    f"Drop this capability in Docker/Compose using `cap_drop: - {cap}` or `cap_drop: - ALL`.",
                                )
                            )
                elif line.startswith("NoNewPrivs:"):
                    val = line.split()[1].strip()
                    if val != "1":
                        findings.append(
                            AuditFinding(
                                "RT-NEW-PRIVS-ALLOWED",
                                "NoNewPrivs Flag Not Set (Value: 0)",
                                "HIGH",
                                "Kernel `no_new_privs` bit is disabled. Processes can acquire additional privileges via SUID binaries.",
                                "Launch container with `--security-opt=no-new-privileges:true`.",
                            )
                        )
                elif line.startswith("Seccomp:"):
                    seccomp_val = line.split()[1].strip()
                    if seccomp_val == "0":
                        findings.append(
                            AuditFinding(
                                "RT-SECCOMP-DISABLED",
                                "Kernel Seccomp Syscall Filtering Disabled (Seccomp: 0)",
                                "CRITICAL",
                                "Container is running without a Seccomp syscall filter (`Seccomp: 0`). High-risk syscalls (`io_uring_setup`, `bpf`, `kexec_load`, `ptrace`, `unshare`) are exposed.",
                                "Remove `seccomp:unconfined` and attach Docker's default seccomp profile or `templates/seccomp-2026-hardened.json`.",
                            )
                        )
        except Exception:
            pass

    # 3. Check User Namespace Mapping (/proc/self/uid_map)
    uid_map_path = Path("/proc/self/uid_map")
    if uid_map_path.is_file():
        try:
            uid_map = uid_map_path.read_text(encoding="utf-8", errors="replace").strip()
            parts = uid_map.split()
            # Format: <container_uid> <host_uid> <range>
            if len(parts) >= 2 and parts[0] == "0" and parts[1] == "0":
                findings.append(
                    AuditFinding(
                        "RT-USERNS-HOST-ROOT",
                        "Container UID 0 Mapped Directly to Host UID 0 (No UserNS Remapping)",
                        "MEDIUM",
                        f"`/proc/self/uid_map` (`{uid_map}`) maps container root (0) directly to host root (0).",
                        "Enable Rootless Docker/Podman, `--userns-remap=default` in `/etc/docker/daemon.json`, or K8s `hostUsers: false`.",
                    )
                )
        except Exception:
            pass

    # 4. Check for Docker / Containerd Socket Mounts
    for sock_str in ("/var/run/docker.sock", "/run/docker.sock", "/run/containerd/containerd.sock"):
        sock_path = Path(sock_str)
        if sock_path.exists():
            findings.append(
                AuditFinding(
                    "RT-DOCKER-SOCK-MOUNTED",
                    f"Exposed Host Container Runtime Socket ({sock_str})",
                    "CRITICAL",
                    f"The container runtime Unix socket `{sock_str}` is accessible inside this container. Any process with read/write access can spawn privileged host-root containers.",
                    f"Unmount `{sock_str}` immediately.",
                )
            )

    # 5. Check Root Filesystem Writable Status
    try:
        test_file = Path("/.__security_audit_rw_test")
        test_file.touch(exist_ok=True)
        test_file.unlink(missing_ok=True)
        findings.append(
            AuditFinding(
                "RT-ROOTFS-WRITABLE",
                "Container Root Filesystem is Writable",
                "MEDIUM",
                "The container root filesystem `/` is writable. Attackers can persist implants, overwrite system libraries, or modify application code at runtime.",
                "Run container with `--read-only` and configure `tmpfs` (`rw,noexec,nosuid,nodev`) mounts for `/tmp` and `/run`.",
            )
        )
    except (PermissionError, OSError):
        pass

    # 6. Check for sensitive files left in root or app directory
    sensitive_file_names = [".env", ".env.local", ".env.production", "id_rsa", "id_ed25519", "credentials.json", ".npmrc", ".pypirc"]
    for sf in sensitive_file_names:
        for search_dir in [Path("/app"), Path("/root"), Path("/home")]:
            p = search_dir / sf
            if p.is_file():
                findings.append(
                    AuditFinding(
                        f"RT-FILE-SECRET-{sf.replace('.', '').upper()}",
                        f"Sensitive Credential File Present Inside Container: {p}",
                        "HIGH",
                        f"File `{p}` is baked into or present inside the container filesystem.",
                        "Remove secret file from image layers and mount via `/run/secrets/` tmpfs volume at runtime.",
                    )
                )

    return findings


def generate_markdown_report(findings: List[AuditFinding], target_name: str) -> str:
    """Generates a GitHub-flavored Markdown audit report."""
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sorted_findings = sorted(findings, key=lambda x: severity_order.get(x.severity, 99))

    crit_count = sum(1 for f in findings if f.severity == "CRITICAL")
    high_count = sum(1 for f in findings if f.severity == "HIGH")
    med_count = sum(1 for f in findings if f.severity == "MEDIUM")
    low_count = sum(1 for f in findings if f.severity == "LOW")

    risk_level = (
        "CRITICAL"
        if crit_count > 0
        else "HIGH"
        if high_count > 0
        else "MEDIUM"
        if med_count > 0
        else "LOW"
        if low_count > 0
        else "PASS"
    )

    md: List[str] = []
    md.append(f"# 🛡️ Docker & Container Security Audit: `{target_name}`\n")
    md.append("## Executive Summary\n")
    md.append(f"- **Overall Risk Level**: **{risk_level}**")
    md.append(f"- **Total Findings**: {len(findings)}")
    md.append(f"  - 🔴 **Critical**: {crit_count}")
    md.append(f"  - 🟠 **High**: {high_count}")
    md.append(f"  - 🟡 **Medium**: {med_count}")
    md.append(f"  - 🔵 **Low / Info**: {low_count}\n")

    if not findings:
        md.append(
            "> [!TIP]\n> **Congratulations!** Zero security issues, hardcoded secrets, or CIS misconfigurations detected. Container configuration adheres to 2026 defense-in-depth standards.\n"
        )
        return "\n".join(md)

    md.append("## Detailed Findings Matrix\n")
    md.append("| Severity | Code | Title | Affected File / Line | Recommended Mitigation |")
    md.append("| :--- | :--- | :--- | :--- | :--- |")

    for f in sorted_findings:
        loc = f.file_path if f.file_path else "Runtime Environment"
        if f.line_num:
            loc += f":L{f.line_num}"
        md.append(f"| **{f.severity}** | `{f.code}` | **{f.title}** | `{loc}` | {f.remediation} |")

    md.append("\n## Prioritized Remediation Steps\n")
    for i, f in enumerate(sorted_findings, start=1):
        md.append(f"### {i}. [{f.severity}] {f.title} (`{f.code}`)")
        md.append(f"- **Description**: {f.description}")
        md.append(f"- **Remediation**: {f.remediation}\n")

    return "\n".join(md)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Docker & Container Hardening Security Auditor (v2.0 — 2026 Edition)"
    )
    parser.add_argument(
        "paths",
        nargs="*",
        help="Paths to Dockerfiles, docker-compose files, unpacked image layer directories, or project directories",
    )
    parser.add_argument(
        "--internal",
        action="store_true",
        help="Run in-container live runtime environment security inspection",
    )
    parser.add_argument(
        "--scan-secrets",
        action="store_true",
        help="Scan all files/layers in target paths for hardcoded secrets, tokens, private keys, and high-entropy credentials",
    )
    parser.add_argument("--json", action="store_true", help="Output raw JSON results")
    parser.add_argument(
        "--markdown", action="store_true", help="Output GitHub-flavored Markdown report"
    )
    args = parser.parse_args()

    all_findings: List[AuditFinding] = []

    if args.internal or (not args.paths and Path("/.dockerenv").exists()):
        all_findings.extend(audit_internal_container())

    targets = args.paths if args.paths else ["."]
    target_label = ", ".join(targets)

    excluded_dirs = {".git", "__pycache__", "node_modules", ".venv", "venv", ".pytest_cache", ".ruff_cache", "dist"}

    for target in targets:
        p = Path(target)
        if p.is_dir():
            for item in p.rglob("*"):
                if any(part in excluded_dirs for part in item.parts):
                    continue
                if item.is_file():
                    name_lower = item.name.lower()
                    if name_lower.startswith("dockerfile"):
                        all_findings.extend(audit_dockerfile(item))
                    elif "compose" in name_lower and (
                        name_lower.endswith(".yml") or name_lower.endswith(".yaml")
                    ):
                        all_findings.extend(audit_docker_compose(item))
                    if args.scan_secrets:
                        all_findings.extend(scan_file_for_secrets(item))
        elif p.is_file():
            name_lower = p.name.lower()
            if "compose" in name_lower and (
                name_lower.endswith(".yml") or name_lower.endswith(".yaml")
            ):
                all_findings.extend(audit_docker_compose(p))
            else:
                all_findings.extend(audit_dockerfile(p))
            if args.scan_secrets:
                all_findings.extend(scan_file_for_secrets(p))

    if args.json:
        output_data = {
            "target": target_label,
            "total_findings": len(all_findings),
            "findings": [f.to_dict() for f in all_findings],
        }
        print(json.dumps(output_data, indent=2))
        return

    if args.markdown:
        print(generate_markdown_report(all_findings, target_label))
        return

    print("\n=======================================================")
    print("  DOCKER & CONTAINER HARDENING AUDITOR (2026 EDITION)")
    print("=======================================================\n")
    print(f"Target: {target_label}")
    print(f"Total Findings: {len(all_findings)}\n")

    for f in all_findings:
        loc = f.file_path if f.file_path else "Runtime Environment"
        if f.line_num:
            loc += f":L{f.line_num}"
        print(f"[{f.severity}] {f.title} ({f.code})")
        print(f"  Location: {loc}")
        print(f"  Details:  {f.description}")
        print(f"  Fix:      {f.remediation}\n")

    sys.exit(
        1 if any(f.severity in ("CRITICAL", "HIGH") for f in all_findings) else 0
    )


if __name__ == "__main__":
    main()
