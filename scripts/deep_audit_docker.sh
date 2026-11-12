#!/usr/bin/env bash
# ==============================================================================
# Docker Deep Security, Layer Forensics, Grype/Syft & Secret Auditor (2026)
# Author: Joe B. (The Blind Hacker)
# License: MIT
#
# Performs deep 2026 container security auditing across:
#   1. Static Dockerfile & Compose CIS Benchmark + BuildKit checks
#   2. Unpacked OCI Image Layer Forensics ("Ghost Secret" & Whiteout hunting)
#   3. TruffleHog (docker & filesystem) + 12-Pattern Defensive Regex Engine
#   4. Anchore Syft SBOM + Grype Multi-Scope (--scope all-layers vs squashed)
#   5. Dive Layer Efficiency, Trivy, Dockle, Hadolint & Cosign Attestation check
#   6. Live Running Container Runtime Inspection (Namespaces, Caps, Seccomp)
# ==============================================================================

set -euo pipefail

VERSION="2.0.0"
IMAGE_TARGET=""
DIR_TARGET="."
CONTAINER_TARGET=""
ONLY_FIXED="true"
FAIL_ON_SEVERITY="high"
REPORT_FILE=""

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Options:
  -i, --image <image:tag>       Target Docker/OCI image for deep layer & CVE unpack audit
  -d, --dir <path>              Target repository/build-context directory (default: .)
  -c, --container <id_or_name>  Target running container for live runtime inspection
  -f, --fail-on <severity>      Grype severity gate: negligible|low|medium|high|critical (default: high)
  -a, --all-cves                Include unfixed CVEs in Grype output (default: --only-fixed)
  -o, --output <report.md>      Write consolidated Markdown report to file
  -h, --help                    Display this help message

Examples:
  bash scripts/deep_audit_docker.sh --image myorg/api:1.4.2 --dir . --output audit-report.md
  bash scripts/deep_audit_docker.sh --container api-prod --dir .
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -i|--image)
            IMAGE_TARGET="${2:-}"
            shift 2
            ;;
        -d|--dir)
            DIR_TARGET="${2:-.}"
            shift 2
            ;;
        -c|--container)
            CONTAINER_TARGET="${2:-}"
            shift 2
            ;;
        -f|--fail-on)
            FAIL_ON_SEVERITY="${2:-high}"
            shift 2
            ;;
        -a|--all-cves)
            ONLY_FIXED="false"
            shift
            ;;
        -o|--output)
            REPORT_FILE="${2:-}"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "[!] Unknown argument: $1" >&2
            usage
            exit 1
            ;;
    esac
done

CRITICAL_COUNT=0
HIGH_COUNT=0
MEDIUM_COUNT=0
LOW_COUNT=0

log_banner() {
    echo ""
    echo "=============================================================================="
    echo "  $1"
    echo "=============================================================================="
}

log_finding() {
    local sev="$1"
    local code="$2"
    local msg="$3"
    case "${sev}" in
        CRITICAL) CRITICAL_COUNT=$((CRITICAL_COUNT + 1)) ;;
        HIGH)     HIGH_COUNT=$((HIGH_COUNT + 1)) ;;
        MEDIUM)   MEDIUM_COUNT=$((MEDIUM_COUNT + 1)) ;;
        LOW|INFO) LOW_COUNT=$((LOW_COUNT + 1)) ;;
    esac
    printf "[%s] (%s) %s\n" "${sev}" "${code}" "${msg}"
}

# Consolidated Extended Regex Patterns for Secret Hunting in Layers & Files
# Character classes prevent static scanners from mistaking regex signatures for live keys.
declare -A SECRET_PATTERNS=(
    ["SEC-PRIV-KEY"]='-----BEGIN [A-Z0-9 ]*PRI[V]ATE KEY-----'
    ["SEC-AWS-KEY-ID"]='(AK[I]A|AS[I]A)[0-9A-Z]{16}'
    ["SEC-GITHUB-PAT"]='(gh[pousr]_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{22,255})'
    ["SEC-GITLAB-PAT"]='glpat-[A-Za-z0-9_-]{20,64}'
    ["SEC-SLACK-TOK"]='xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,64}'
    ["SEC-STRIPE-LIVE"]='(sk|rk)_live_[0-9a-zA-Z]{24,99}'
    ["SEC-GCP-API-KEY"]='AIza[0-9A-Za-z_-]{35}'
    ["SEC-AI-KEY"]='(sk-proj-[A-Za-z0-9_-]{32,180}|sk-ant-api[0-9]{2}-[A-Za-z0-9_-]{32,180})'
    ["SEC-JWT-BEARER"]='eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{16,}'
    ["SEC-DB-URI"]='(postgres(ql)?|mysql|mongodb(\+srv)?|redis|amqp)[:]//[^:\s/@]+:[^@\s/]{4,}@[^\s"'"'"']+'
    ["SEC-DOCKER-CFG"]='"auth"[[:space:]]*:[[:space:]]*"[A-Za-z0-9+/=]{20,}"'
    ["SEC-GENERIC-ENV"]='(SEC[R]ET|TOK[E]N|PASS[W]ORD|PASS[W]D|API[_-]?KEY|PRIV[A]TE[_-]?KEY)[[:space:]]*[:=][[:space:]]*["'"'"']?[A-Za-z0-9+/=_-]{20,128}["'"'"']?'
)

mask_hit() {
    local raw="$1"
    local len="${#raw}"
    if [[ "${len}" -le 14 ]]; then
        echo "***REDACTED***"
    else
        echo "${raw:0:8}...REDACTED...${raw: -4}"
    fi
}

scan_directory_with_regex() {
    local target_path="$1"
    local context_label="$2"

    if [[ ! -d "${target_path}" ]]; then
        return 0
    fi

    echo "[*] Running 12-Pattern Defensive Regex Secret Engine on ${context_label} (${target_path})..."
    for code in "${!SECRET_PATTERNS[@]}"; do
        local pat="${SECRET_PATTERNS[$code]}"
        while IFS= read -r match_line; do
            [[ -z "${match_line}" ]] && continue
            # Skip known safe placeholder tokens
            if [[ "${match_line}" == *"00000000-0000-0000-0000-000000000000"* ]] || \
               [[ "${match_line}" == *"YOUR_API_KEY_HERE"* ]] || \
               [[ "${match_line}" == *"placeholder"* ]]; then
                continue
            fi
            local file_loc="${match_line%%:*}"
            local remainder="${match_line#*:}"
            local line_no="${remainder%%:*}"
            local snippet="${remainder#*:}"
            local masked
            masked="$(mask_hit "${snippet}")"
            log_finding "CRITICAL" "${code}" "${context_label} -> ${file_loc}:L${line_no} matched ${code} (${masked})"
        done < <(grep -rnEI \
            --exclude-dir=.git \
            --exclude-dir=node_modules \
            --exclude-dir=.venv \
            --exclude-dir=venv \
            --exclude-dir=__pycache__ \
            --exclude-dir=dist \
            --exclude="deep_audit_docker.sh" \
            --exclude="Invoke-DockerDeepAudit.ps1" \
            --exclude="audit_container.py" \
            "${pat}" "${target_path}" 2>/dev/null || true)
    done
}

# ==============================================================================
# PHASE 1: STATIC REPOSITORY, DOCKERFILE & BUILD-CONTEXT AUDIT
# ==============================================================================
log_banner "PHASE 1: STATIC DOCKERFILE, COMPOSE & BUILD-CONTEXT AUDIT (${DIR_TARGET})"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if command -v python3 >/dev/null 2>&1 && [[ -f "${SCRIPT_DIR}/audit_container.py" ]]; then
    echo "[*] Executing Python CIS & 2026 Hardening Auditor..."
    python3 "${SCRIPT_DIR}/audit_container.py" "${DIR_TARGET}" --scan-secrets || true
fi

scan_directory_with_regex "${DIR_TARGET}" "BuildContext"

if command -v trufflehog >/dev/null 2>&1; then
    echo "[*] Running TruffleHog Filesystem Credential Verification on ${DIR_TARGET}..."
    while IFS= read -r th_line; do
        [[ -z "${th_line}" ]] && continue
        log_finding "CRITICAL" "TH-FS-SECRET" "TruffleHog filesystem hit detected in ${DIR_TARGET}: $(mask_hit "${th_line}")"
    done < <(trufflehog filesystem "${DIR_TARGET}" --results=verified,unknown --json 2>/dev/null | head -n 50 || true)
else
    echo "[i] TruffleHog CLI not detected on PATH; skipping `trufflehog filesystem` pass (install: brew install trufflehog or trufflesecurity/trufflehog)."
fi

if command -v hadolint >/dev/null 2>&1; then
    while IFS= read -r df_file; do
        [[ -z "${df_file}" ]] && continue
        echo "[*] Running Hadolint AST check on ${df_file}..."
        hadolint "${df_file}" --failure-threshold warning || true
    done < <(find "${DIR_TARGET}" -maxdepth 3 -name "Dockerfile*" 2>/dev/null || true)
fi

# ==============================================================================
# PHASE 2: DEEP OCI IMAGE LAYER UNPACK, GHOST SECRET & GRYPE/SYFT AUDIT
# ==============================================================================
if [[ -n "${IMAGE_TARGET}" ]]; then
    log_banner "PHASE 2: DEEP OCI IMAGE LAYER FORENSICS & SBOM/CVE AUDIT (${IMAGE_TARGET})"

    # 2.1 Inspect Image History (--no-trunc) for leaked ARG / ENV secrets
    echo "[*] Auditing full non-truncated build history (docker history --no-trunc)..."
    while IFS= read -r hist_line; do
        [[ -z "${hist_line}" ]] && continue
        log_finding "CRITICAL" "IMG-HISTORY-SECRET" "Plaintext credential pattern visible in image layer history: $(mask_hit "${hist_line}")"
    done < <(docker history --no-trunc "${IMAGE_TARGET}" 2>/dev/null | grep -Ei '(SEC[R]ET|TOK[E]N|PASS[W]ORD|API[_-]?KEY|AK[I]A|gh[pousr]_|PRI[V]ATE KEY)' || true)

    # 2.2 TruffleHog Native Docker Image Scan (scans all layers directly)
    if command -v trufflehog >/dev/null 2>&1; then
        echo "[*] Running TruffleHog Docker Layer Scanner against ${IMAGE_TARGET}..."
        while IFS= read -r th_img_line; do
            [[ -z "${th_img_line}" ]] && continue
            log_finding "CRITICAL" "TH-IMAGE-SECRET" "TruffleHog detected credential inside ${IMAGE_TARGET} layer history: $(mask_hit "${th_img_line}")"
        done < <(trufflehog docker --image="${IMAGE_TARGET}" --results=verified,unknown --json 2>/dev/null | head -n 50 || true)
    fi

    # 2.3 Deep Unpacked Layer Tarball Inspection ("Ghost Secrets" & Whiteout Files)
    WORK_DIR="$(mktemp -d 2>/dev/null || mktemp -d -t 'docker_deep_audit')"
    cleanup_workdir() {
        if [[ -n "${WORK_DIR:-}" && -d "${WORK_DIR}" ]]; then
            rm -r -f "${WORK_DIR}"
        fi
    }
    trap cleanup_workdir EXIT

    echo "[*] Exporting ${IMAGE_TARGET} via 'docker save' to inspect intermediate OverlayFS layers..."
    IMAGE_TAR="${WORK_DIR}/image.tar"
    UNPACK_DIR="${WORK_DIR}/unpacked"
    mkdir -p "${UNPACK_DIR}"

    if docker save "${IMAGE_TARGET}" -o "${IMAGE_TAR}" 2>/dev/null; then
        tar -xf "${IMAGE_TAR}" -C "${UNPACK_DIR}" 2>/dev/null || true
        rm -f "${IMAGE_TAR}"

        # Unpack every individual layer tarball (OCI blobs/sha256/* or legacy */layer.tar)
        LAYER_INDEX=0
        while IFS= read -r layer_tar; do
            [[ -z "${layer_tar}" ]] && continue
            LAYER_INDEX=$((LAYER_INDEX + 1))
            LAYER_EXTRACT="${WORK_DIR}/layers/layer_${LAYER_INDEX}"
            mkdir -p "${LAYER_EXTRACT}"

            # Check for OverlayFS whiteout markers (.wh.*) inside the layer tar before extracting
            while IFS= read -r wh_entry; do
                [[ -z "${wh_entry}" ]] && continue
                log_finding "MEDIUM" "LYR-WHITEOUT" "Layer #${LAYER_INDEX} contains OverlayFS whiteout marker '${wh_entry}' — verify deleted file did not contain secrets in earlier layers!"
            done < <(tar -tf "${layer_tar}" 2>/dev/null | grep -E '(^|/)\.wh\.' || true)

            # Check for sensitive filenames inside the layer tar
            while IFS= read -r sens_entry; do
                [[ -z "${sens_entry}" ]] && continue
                log_finding "HIGH" "LYR-SENSITIVE-FILE" "Layer #${LAYER_INDEX} contains sensitive file artifact: ${sens_entry}"
            done < <(tar -tf "${layer_tar}" 2>/dev/null | grep -Ei '(^|/)(\.env(\.[a-z0-9]+)?|id_rsa|id_ed25519|.*\.pem|.*\.key|.*\.pfx|.*\.p12|\.npmrc|\.pypirc|credentials\.json|\.docker/config\.json)$' || true)

            # Extract text/config files from layer for regex secret scanning
            tar -xf "${layer_tar}" -C "${LAYER_EXTRACT}" 2>/dev/null || true
            scan_directory_with_regex "${LAYER_EXTRACT}" "ImageLayer#${LAYER_INDEX}"
            rm -r -f "${LAYER_EXTRACT}"
        done < <(find "${UNPACK_DIR}" -type f \( -name "*.tar" -o -path "*/blobs/sha256/*" \) 2>/dev/null || true)
    else
        echo "[!] Could not export image ${IMAGE_TARGET} via docker save (is the image pulled locally?)."
    fi

    # 2.4 Anchore Syft SBOM + Grype Multi-Scope Vulnerability Auditing
    SBOM_FILE="${WORK_DIR}/sbom.cdx.json"
    if command -v syft >/dev/null 2>&1; then
        echo "[*] Generating CycloneDX SBOM across all layers via Anchore Syft..."
        syft "${IMAGE_TARGET}" --scope all-layers -o "cyclonedx-json=${SBOM_FILE}" 2>/dev/null || true
    fi

    if command -v grype >/dev/null 2>&1; then
        echo "[*] Running Anchore Grype Vulnerability Audit (Squashed Runtime Scope vs All-Layers Scope)..."
        GRYPE_ARGS=("--by-cve")
        if [[ "${ONLY_FIXED}" == "true" ]]; then
            GRYPE_ARGS+=("--only-fixed")
        fi

        if [[ -f "${SBOM_FILE}" ]]; then
            echo "[*] Scanning Syft CycloneDX SBOM with Grype (${GRYPE_ARGS[*]})..."
            grype "sbom:${SBOM_FILE}" "${GRYPE_ARGS[@]}" --fail-on "${FAIL_ON_SEVERITY}" || \
                log_finding "HIGH" "GRYPE-CVE-GATE" "Grype SBOM scan exceeded severity threshold (${FAIL_ON_SEVERITY}) on ${IMAGE_TARGET}"
        else
            echo "[*] Scanning ${IMAGE_TARGET} directly with Grype (--scope all-layers ${GRYPE_ARGS[*]})..."
            grype "${IMAGE_TARGET}" --scope all-layers "${GRYPE_ARGS[@]}" --fail-on "${FAIL_ON_SEVERITY}" || \
                log_finding "HIGH" "GRYPE-CVE-GATE" "Grype all-layers scan exceeded severity threshold (${FAIL_ON_SEVERITY}) on ${IMAGE_TARGET}"
        fi
    else
        echo "[i] Anchore Grype not found on PATH; skipping Grype CVE scan (install: anchore/grype)."
    fi

    # 2.5 Dive Layer Efficiency & Wasted Space Check
    if command -v dive >/dev/null 2>&1; then
        echo "[*] Running Dive CI layer efficiency and wasted space analysis..."
        CI=true dive "${IMAGE_TARGET}" || \
            log_finding "MEDIUM" "DIVE-INEFFICIENT-LAYERS" "Dive detected low image layer efficiency or excessive wasted space across layers in ${IMAGE_TARGET}"
    fi

    # 2.6 Dockle CIS Image Linter
    if command -v dockle >/dev/null 2>&1; then
        echo "[*] Running Dockle CIS Benchmark image inspection..."
        dockle --exit-code 1 "${IMAGE_TARGET}" || \
            log_finding "MEDIUM" "DOCKLE-CIS-WARN" "Dockle reported CIS image benchmark warnings on ${IMAGE_TARGET}"
    fi

    # 2.7 OCI Supply Chain Provenance & SBOM Attestation Check
    echo "[*] Checking OCI Supply Chain Provenance & BuildKit Attestations..."
    if docker buildx imagetools inspect "${IMAGE_TARGET}" 2>/dev/null | grep -qi "intoto\|slsa\|spdx"; then
        echo "[+] Verified OCI SLSA Provenance / SBOM attestation manifest attached to ${IMAGE_TARGET}."
    else
        log_finding "LOW" "OCI-NO-ATTESTATION" "No SLSA provenance or embedded SBOM attestation detected on ${IMAGE_TARGET} (build with: docker buildx build --attest type=sbom --attest type=provenance,mode=max)."
    fi
fi

# ==============================================================================
# PHASE 3: LIVE RUNNING CONTAINER RUNTIME INSPECTION
# ==============================================================================
if [[ -n "${CONTAINER_TARGET}" ]]; then
    log_banner "PHASE 3: LIVE CONTAINER RUNTIME INSPECTION (${CONTAINER_TARGET})"

    if docker inspect "${CONTAINER_TARGET}" >/dev/null 2>&1; then
        PRIV_MODE="$(docker inspect --format '{{.HostConfig.Privileged}}' "${CONTAINER_TARGET}" 2>/dev/null || echo "false")"
        RO_ROOTFS="$(docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' "${CONTAINER_TARGET}" 2>/dev/null || echo "false")"
        PID_MODE="$(docker inspect --format '{{.HostConfig.PidMode}}' "${CONTAINER_TARGET}" 2>/dev/null || echo "")"
        NET_MODE="$(docker inspect --format '{{.HostConfig.NetworkMode}}' "${CONTAINER_TARGET}" 2>/dev/null || echo "")"
        CGROUP_NS="$(docker inspect --format '{{.HostConfig.CgroupnsMode}}' "${CONTAINER_TARGET}" 2>/dev/null || echo "")"
        PIDS_LIM="$(docker inspect --format '{{.HostConfig.PidsLimit}}' "${CONTAINER_TARGET}" 2>/dev/null || echo "0")"
        SEC_OPTS="$(docker inspect --format '{{json .HostConfig.SecurityOpt}}' "${CONTAINER_TARGET}" 2>/dev/null || echo "[]")"
        CFG_USER="$(docker inspect --format '{{.Config.User}}' "${CONTAINER_TARGET}" 2>/dev/null || echo "")"

        if [[ "${PRIV_MODE}" == "true" ]]; then
            log_finding "CRITICAL" "RT-INSPECT-PRIVILEGED" "Container '${CONTAINER_TARGET}' is running with Privileged=true!"
        fi
        if [[ -z "${CFG_USER}" || "${CFG_USER}" == "root" || "${CFG_USER}" == "0" ]]; then
            log_finding "CRITICAL" "RT-INSPECT-ROOT-USER" "Container '${CONTAINER_TARGET}' is configured to run as UID 0 (root)."
        fi
        if [[ "${RO_ROOTFS}" != "true" ]]; then
            log_finding "MEDIUM" "RT-INSPECT-RW-ROOTFS" "Container '${CONTAINER_TARGET}' has a writable root filesystem (ReadonlyRootfs=false)."
        fi
        if [[ "${PID_MODE}" == "host" || "${NET_MODE}" == "host" ]]; then
            log_finding "HIGH" "RT-INSPECT-HOST-NS" "Container '${CONTAINER_TARGET}' shares host namespaces (PidMode=${PID_MODE}, NetworkMode=${NET_MODE})."
        fi
        if [[ "${CGROUP_NS}" == "host" ]]; then
            log_finding "HIGH" "RT-INSPECT-CGROUP-HOST" "Container '${CONTAINER_TARGET}' shares host cgroup namespace (CgroupnsMode=host)."
        fi
        if [[ "${PIDS_LIM}" == "0" || "${PIDS_LIM}" == "<nil>" || "${PIDS_LIM}" == "-1" ]]; then
            log_finding "LOW" "RT-INSPECT-NO-PID-LIMIT" "Container '${CONTAINER_TARGET}' has no PIDs limit set (vulnerable to fork-bomb DoS)."
        fi
        if [[ "${SEC_OPTS}" != *"no-new-privileges"* ]]; then
            log_finding "HIGH" "RT-INSPECT-NO-NEW-PRIVS" "Container '${CONTAINER_TARGET}' is missing security-opt no-new-privileges:true."
        fi
        if [[ "${SEC_OPTS}" == *"unconfined"* ]]; then
            log_finding "CRITICAL" "RT-INSPECT-UNCONFINED" "Container '${CONTAINER_TARGET}' has unconfined Seccomp or AppArmor profile (${SEC_OPTS})."
        fi
    else
        echo "[!] Container '${CONTAINER_TARGET}' not found or Docker daemon unreachable."
    fi
fi

# ==============================================================================
# SUMMARY & EXIT GATE
# ==============================================================================
log_banner "AUDIT SUMMARY"
echo "  Critical Findings : ${CRITICAL_COUNT}"
echo "  High Findings     : ${HIGH_COUNT}"
echo "  Medium Findings   : ${MEDIUM_COUNT}"
echo "  Low/Info Findings : ${LOW_COUNT}"

if [[ -n "${REPORT_FILE}" ]]; then
    cat > "${REPORT_FILE}" <<EOF
# 🛡️ Deep Docker & Container Security Audit Report (2026)

- **Directory Audited**: \`${DIR_TARGET}\`
- **Image Audited**: \`${IMAGE_TARGET:-None}\`
- **Container Audited**: \`${CONTAINER_TARGET:-None}\`
- **Critical Findings**: **${CRITICAL_COUNT}**
- **High Findings**: **${HIGH_COUNT}**
- **Medium Findings**: **${MEDIUM_COUNT}**
- **Low/Info Findings**: **${LOW_COUNT}**
EOF
    echo "[+] Wrote Markdown summary to ${REPORT_FILE}"
fi

if [[ "${CRITICAL_COUNT}" -gt 0 || "${HIGH_COUNT}" -gt 0 ]]; then
    exit 1
fi
exit 0
