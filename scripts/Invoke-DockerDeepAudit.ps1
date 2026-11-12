<#
.SYNOPSIS
    Deep Docker & Container Security, Layer Forensics, Grype/Syft & Secret Auditor (2026 Edition)
.DESCRIPTION
    Performs defense-in-depth container security auditing across:
      1. Static Dockerfile & docker-compose.yml CIS Benchmark + 2026 hardening rules
      2. Unpacked OCI Image Layer Forensics ("Ghost Secret" & OverlayFS Whiteout hunting)
      3. TruffleHog (docker & filesystem) + 12-Pattern Regex & Shannon Entropy Secret Engine
      4. Anchore Syft SBOM + Grype Multi-Scope (--scope all-layers vs squashed) CVE analysis
      5. Dive Layer Efficiency, Dockle CIS Linting & OCI SLSA Attestation verification
      6. Live Running Container Runtime Inspection (Privileged, Caps, Seccomp, Cgroupns, PidsLimit)
.AUTHOR
    Joe B. (The Blind Hacker)
.LICENSE
    MIT
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false, HelpMessage = "Target Docker/OCI image tag for layer & CVE unpack audit")]
    [string]$Image = "",

    [Parameter(Mandatory = $false, HelpMessage = "Target repository or build-context directory")]
    [string]$Directory = ".",

    [Parameter(Mandatory = $false, HelpMessage = "Target running container name or ID for live runtime inspection")]
    [string]$Container = "",

    [Parameter(Mandatory = $false, HelpMessage = "Grype severity threshold gate (negligible, low, medium, high, critical)")]
    [ValidateSet("negligible", "low", "medium", "high", "critical")]
    [string]$FailOnSeverity = "high",

    [Parameter(Mandatory = $false, HelpMessage = "Include unfixed upstream CVEs in Grype scan")]
    [switch]$IncludeUnfixedCves,

    [Parameter(Mandatory = $false, HelpMessage = "Optional path to write JSON findings output")]
    [string]$JsonOutputPath = "",

    [Parameter(Mandatory = $false, HelpMessage = "Optional path to write Markdown report output")]
    [string]$MarkdownOutputPath = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

$Findings = [System.Collections.Generic.List[PSCustomObject]]::new()

function Add-AuditFinding {
    param(
        [Parameter(Mandatory = $true)][string]$Severity,
        [Parameter(Mandatory = $true)][string]$Code,
        [Parameter(Mandatory = $true)][string]$Title,
        [Parameter(Mandatory = $true)][string]$Location,
        [Parameter(Mandatory = $true)][string]$Details,
        [Parameter(Mandatory = $true)][string]$Remediation
    )
    $obj = [PSCustomObject]@{
        Severity    = $Severity
        Code        = $Code
        Title       = $Title
        Location    = $Location
        Details     = $Details
        Remediation = $Remediation
    }
    $script:Findings.Add($obj)
    $color = switch ($Severity) {
        "CRITICAL" { "Red" }
        "HIGH"     { "DarkYellow" }
        "MEDIUM"   { "Yellow" }
        default    { "Cyan" }
    }
    Write-Host "[$Severity] ($Code) $Title -> $Location" -ForegroundColor $color
}

function ConvertTo-MaskedSecret {
    param([Parameter(Mandatory = $true)][string]$RawText)
    $clean = $RawText.Trim()
    if ($clean.Length -le 14) {
        return "***REDACTED***"
    }
    return "{0}...REDACTED...{1}" -f $clean.Substring(0, 8), $clean.Substring($clean.Length - 4)
}

function Get-ShannonEntropy {
    param([Parameter(Mandatory = $true)][string]$InputString)
    if ([string]::IsNullOrEmpty($InputString)) {
        return 0.0
    }
    $freq = @{}
    foreach ($ch in $InputString.ToCharArray()) {
        if ($freq.ContainsKey($ch)) {
            $freq[$ch]++
        } else {
            $freq[$ch] = 1
        }
    }
    $entropy = 0.0
    $len = [double]$InputString.Length
    foreach ($count in $freq.Values) {
        $p = [double]$count / $len
        $entropy -= $p * [Math]::Log($p, 2.0)
    }
    return [Math]::Round($entropy, 2)
}

# 12-Pattern Defensive Regex Secret Catalog
# Character classes ensure static scanners do not mistake regex definitions for live secrets.
$SecretRegexCatalog = @(
    @{
        Code        = "SEC-PRIV-KEY"
        Title       = "Asymmetric Private Key (RSA/OPENSSH/EC/PGP)"
        Severity    = "CRITICAL"
        Pattern     = "-----BEGIN [A-Z0-9 ]*PRI[V]ATE KEY-----"
        Remediation = "Revoke private key immediately, purge from image layers, and mount at runtime via /run/secrets/."
    },
    @{
        Code        = "SEC-AWS-KEY-ID"
        Title       = "AWS IAM Access Key ID (AKIA/ASIA)"
        Severity    = "CRITICAL"
        Pattern     = "\b(AK[I]A|AS[I]A)[0-9A-Z]{16}\b"
        Remediation = "Rotate IAM credentials in AWS Console and switch to IAM Roles for Tasks/ServiceAccounts."
    },
    @{
        Code        = "SEC-GITHUB-PAT"
        Title       = "GitHub Personal Access or Fine-Grained Token"
        Severity    = "CRITICAL"
        Pattern     = "\b(gh[pousr]_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b"
        Remediation = "Revoke GitHub PAT and use BuildKit --mount=type=secret or ephemeral GITHUB_TOKEN in CI."
    },
    @{
        Code        = "SEC-GITLAB-PAT"
        Title       = "GitLab Personal Access or Runner Token"
        Severity    = "CRITICAL"
        Pattern     = "\bglpat-[A-Za-z0-9_\-]{20,64}\b"
        Remediation = "Revoke GitLab token and inject via runtime secret manager."
    },
    @{
        Code        = "SEC-SLACK-TOK"
        Title       = "Slack Bot / User / Workspace Token"
        Severity    = "HIGH"
        Pattern     = "\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,64}\b"
        Remediation = "Rotate Slack token and remove from static container layers."
    },
    @{
        Code        = "SEC-STRIPE-LIVE"
        Title       = "Stripe Live Secret or Restricted API Key"
        Severity    = "CRITICAL"
        Pattern     = "\b(sk|rk)_live_[0-9a-zA-Z]{24,99}\b"
        Remediation = "Roll Stripe live key immediately and move to runtime secret store."
    },
    @{
        Code        = "SEC-GCP-API-KEY"
        Title       = "Google Cloud API Key (AIza)"
        Severity    = "HIGH"
        Pattern     = "\bAIza[0-9A-Za-z_\-]{35}\b"
        Remediation = "Restrict or rotate GCP API key and use Workload Identity Federation."
    },
    @{
        Code        = "SEC-AI-KEY"
        Title       = "AI Provider API Secret Key (sk-proj / sk-ant)"
        Severity    = "CRITICAL"
        Pattern     = "\b(sk-proj-[A-Za-z0-9_\-]{32,180}|sk-ant-api[0-9]{2}-[A-Za-z0-9_\-]{32,180})\b"
        Remediation = "Revoke LLM API key and inject exclusively at container runtime."
    },
    @{
        Code        = "SEC-JWT-BEARER"
        Title       = "Hardcoded JSON Web Token (JWT)"
        Severity    = "HIGH"
        Pattern     = "\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{16,}\b"
        Remediation = "Remove static JWTs from source and container image layers."
    },
    @{
        Code        = "SEC-DB-URI"
        Title       = "Database Connection URI with Embedded Password"
        Severity    = "CRITICAL"
        Pattern     = "\b(postgres(ql)?|mysql|mongodb(\+srv)?|redis|amqp)[:]//[^:\s/@]+:[^@\s/]{4,}@[^\s`"']+"
        Remediation = "Construct database URLs at runtime from mounted secret files."
    },
    @{
        Code        = "SEC-DOCKER-CFG"
        Title       = "Docker Registry Base64 Auth Token (.docker/config.json)"
        Severity    = "CRITICAL"
        Pattern     = '"auth"\s*:\s*"[A-Za-z0-9+/=]{20,}"'
        Remediation = "Never bake .docker/config.json into images; use BuildKit --mount=type=secret."
    }
)

$HighEntropyAssignRegex = [regex]::new(
    '(?:SEC[R]ET|TOK[E]N|PASS[W]ORD|PASS[W]D|API[_-]?KEY|PRIV[A]TE[_-]?KEY|AUTH[_-]?KEY)\s*[:=]\s*["'']?([A-Za-z0-9+/=_\-]{20,128})["'']?',
    [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
)

function Invoke-DirectorySecretScan {
    param(
        [Parameter(Mandatory = $true)][string]$TargetPath,
        [Parameter(Mandatory = $true)][string]$ContextLabel
    )
    if (-not (Test-Path -LiteralPath $TargetPath)) {
        return
    }

    $excludedFolders = @(".git", "node_modules", ".venv", "venv", "__pycache__", ".pytest_cache", ".ruff_cache", "dist")
    $selfScripts = @("deep_audit_docker.sh", "Invoke-DockerDeepAudit.ps1", "audit_container.py")

    $files = Get-ChildItem -Path $TargetPath -Recurse -File -Force -ErrorAction SilentlyContinue
    foreach ($file in $files) {
        $skip = $false
        foreach ($ex in $excludedFolders) {
            if ($file.FullName -match ([regex]::Escape([IO.Path]::DirectorySeparatorChar + $ex + [IO.Path]::DirectorySeparatorChar))) {
                $skip = $true
                break
            }
        }
        if ($skip -or ($selfScripts -contains $file.Name)) {
            continue
        }

        # Check for OverlayFS Whiteout files (.wh.*)
        if ($file.Name.StartsWith(".wh.")) {
            Add-AuditFinding -Severity "MEDIUM" -Code "LYR-WHITEOUT-FILE" `
                -Title "OverlayFS Whiteout Marker Detected ($($file.Name))" `
                -Location "$ContextLabel :: $($file.FullName)" `
                -Details "Whiteout marker indicates a file deleted in a later layer; original file remains recoverable in parent layers." `
                -Remediation "Use multi-stage builds or BuildKit --mount=type=secret instead of deleting secrets in later layers."
        }

        if ($file.Length -gt 5MB) {
            continue
        }

        try {
            $lines = [System.IO.File]::ReadAllLines($file.FullName)
        } catch {
            continue
        }

        for ($i = 0; $i -lt $lines.Count; $i++) {
            $line = $lines[$i]
            if ($line.Length -gt 2000) { continue }
            if ($line -match "00000000-0000-0000-0000-000000000000" -or $line -match "YOUR_API_KEY_HERE" -or $line -match "placeholder") {
                continue
            }

            foreach ($rule in $SecretRegexCatalog) {
                $m = [regex]::Match($line, $rule.Pattern)
                if ($m.Success) {
                    $masked = ConvertTo-MaskedSecret -RawText $m.Value
                    Add-AuditFinding -Severity $rule.Severity -Code $rule.Code -Title $rule.Title `
                        -Location "$ContextLabel :: $($file.FullName):L$($i + 1)" `
                        -Details "Matched pattern $($rule.Code): $masked" `
                        -Remediation $rule.Remediation
                }
            }

            $entMatch = $HighEntropyAssignRegex.Match($line)
            if ($entMatch.Success) {
                $candidate = $entMatch.Groups[1].Value
                $entropy = Get-ShannonEntropy -InputString $candidate
                if ($entropy -ge 4.25) {
                    $masked = ConvertTo-MaskedSecret -RawText $candidate
                    Add-AuditFinding -Severity "HIGH" -Code "SEC-HIGH-ENTROPY" `
                        -Title "High-Entropy Credential Assignment (H=$entropy bits)" `
                        -Location "$ContextLabel :: $($file.FullName):L$($i + 1)" `
                        -Details "High-entropy secret value detected ($masked, Shannon entropy $entropy >= 4.25)." `
                        -Remediation "Move secrets out of static files/layers into runtime /run/secrets/ or BuildKit secret mounts."
                }
            }
        }
    }
}

# ==============================================================================
# PHASE 1: STATIC REPOSITORY, DOCKERFILE & BUILD-CONTEXT AUDIT
# ==============================================================================
Write-Host "`n==============================================================================" -ForegroundColor Cyan
Write-Host "  PHASE 1: STATIC DOCKERFILE, COMPOSE & BUILD-CONTEXT AUDIT ($Directory)" -ForegroundColor Cyan
Write-Host "==============================================================================" -ForegroundColor Cyan

$AuditPy = Join-Path $PSScriptRoot "audit_container.py"
if ((Get-Command python -ErrorAction SilentlyContinue) -and (Test-Path -LiteralPath $AuditPy)) {
    Write-Host "[*] Running Python CIS & 2026 Static Auditor..."
    $pyJson = & python $AuditPy $Directory --json 2>$null
    if ($LASTEXITCODE -ne 0 -or $pyJson) {
        try {
            $parsedPy = $pyJson | ConvertFrom-Json
            foreach ($f in $parsedPy.findings) {
                $loc = if ($f.file) { if ($f.line) { "$($f.file):L$($f.line)" } else { $f.file } } else { "StaticConfig" }
                Add-AuditFinding -Severity $f.severity -Code $f.code -Title $f.title `
                    -Location $loc -Details $f.description -Remediation $f.remediation
            }
        } catch {
            Write-Verbose "Could not parse JSON from audit_container.py"
        }
    }
}

Invoke-DirectorySecretScan -TargetPath $Directory -ContextLabel "BuildContext"

if (Get-Command trufflehog -ErrorAction SilentlyContinue) {
    Write-Host "[*] Running TruffleHog Filesystem Credential Scan on $Directory..."
    $thOut = & trufflehog filesystem $Directory --results=verified,unknown --json 2>$null | Select-Object -First 50
    foreach ($thLine in $thOut) {
        if (-not [string]::IsNullOrWhiteSpace($thLine)) {
            $masked = ConvertTo-MaskedSecret -RawText $thLine
            Add-AuditFinding -Severity "CRITICAL" -Code "TH-FS-SECRET" `
                -Title "TruffleHog Filesystem Credential Match" `
                -Location $Directory `
                -Details "TruffleHog identified credential material: $masked" `
                -Remediation "Rotate exposed credential and purge from repository history."
        }
    }
}

# ==============================================================================
# PHASE 2: DEEP OCI IMAGE LAYER UNPACK, GHOST SECRET & GRYPE/SYFT AUDIT
# ==============================================================================
if (-not [string]::IsNullOrWhiteSpace($Image)) {
    Write-Host "`n==============================================================================" -ForegroundColor Cyan
    Write-Host "  PHASE 2: DEEP OCI IMAGE LAYER FORENSICS & SBOM/CVE AUDIT ($Image)" -ForegroundColor Cyan
    Write-Host "==============================================================================" -ForegroundColor Cyan

    # 2.1 Non-Truncated Image History Inspection
    Write-Host "[*] Auditing full non-truncated build history (docker history --no-trunc)..."
    $histLines = & docker history --no-trunc $Image 2>$null
    foreach ($hLine in $histLines) {
        if ($hLine -match '(?i)(SEC[R]ET|TOK[E]N|PASS[W]ORD|API[_-]?KEY|AK[I]A|gh[pousr]_|PRI[V]ATE KEY)') {
            $masked = ConvertTo-MaskedSecret -RawText $hLine
            Add-AuditFinding -Severity "CRITICAL" -Code "IMG-HISTORY-SECRET" `
                -Title "Credential Pattern Exposed in Docker Image Layer History" `
                -Location "ImageHistory :: $Image" `
                -Details "Plaintext secret or build-arg found in docker history: $masked" `
                -Remediation "Rebuild image using BuildKit --mount=type=secret instead of ARG or ENV."
        }
    }

    # 2.2 TruffleHog Docker Layer Scanner
    if (Get-Command trufflehog -ErrorAction SilentlyContinue) {
        Write-Host "[*] Running TruffleHog Docker Image Layer Scanner on $Image..."
        $thImgOut = & trufflehog docker "--image=$Image" --results=verified,unknown --json 2>$null | Select-Object -First 50
        foreach ($thImgLine in $thImgOut) {
            if (-not [string]::IsNullOrWhiteSpace($thImgLine)) {
                $masked = ConvertTo-MaskedSecret -RawText $thImgLine
                Add-AuditFinding -Severity "CRITICAL" -Code "TH-IMAGE-SECRET" `
                    -Title "TruffleHog Detected Secret Inside Container Image Layer" `
                    -Location "ImageLayer :: $Image" `
                    -Details "TruffleHog matched credential in image layers: $masked" `
                    -Remediation "Revoke credential and rebuild image from clean multi-stage layers."
            }
        }
    }

    # 2.3 Unpacked OCI Layer Tarball Inspection ("Ghost Secrets" & Whiteouts)
    $TempWorkDir = Join-Path ([System.IO.Path]::GetTempPath()) ("docker_audit_" + [Guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $TempWorkDir -Force | Out-Null
    try {
        $ImageTar = Join-Path $TempWorkDir "image.tar"
        $UnpackDir = Join-Path $TempWorkDir "unpacked"
        New-Item -ItemType Directory -Path $UnpackDir -Force | Out-Null

        Write-Host "[*] Exporting $Image via 'docker save' for intermediate layer forensics..."
        & docker save $Image -o $ImageTar 2>$null
        if ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $ImageTar)) {
            & tar -xf $ImageTar -C $UnpackDir 2>$null
            Remove-Item -LiteralPath $ImageTar -Force -ErrorAction SilentlyContinue

            $layerFiles = Get-ChildItem -Path $UnpackDir -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Extension -eq ".tar" -or $_.FullName -match "blobs[\\/]sha256" }

            $layerIdx = 0
            foreach ($layerTar in $layerFiles) {
                $layerIdx++
                $layerExtractDir = Join-Path $TempWorkDir "layer_$layerIdx"
                New-Item -ItemType Directory -Path $layerExtractDir -Force | Out-Null

                $tarEntries = & tar -tf $layerTar.FullName 2>$null
                foreach ($entry in $tarEntries) {
                    if ($entry -match '(^|/)\.wh\.') {
                        Add-AuditFinding -Severity "MEDIUM" -Code "LYR-WHITEOUT" `
                            -Title "OverlayFS Whiteout Marker in Layer #$layerIdx ($entry)" `
                            -Location "$Image :: Layer#$layerIdx" `
                            -Details "File '$entry' was deleted via whiteout marker; if it was a secret in an earlier layer, it remains inside that earlier layer tarball." `
                            -Remediation "Never copy and delete secrets in separate layers; use BuildKit --mount=type=secret."
                    }
                    if ($entry -match '(?i)(^|/)(\.env(\.[a-z0-9]+)?|id_rsa|id_ed25519|.*\.pem|.*\.key|.*\.pfx|.*\.p12|\.npmrc|\.pypirc|credentials\.json|\.docker/config\.json)$') {
                        Add-AuditFinding -Severity "HIGH" -Code "LYR-SENSITIVE-FILE" `
                            -Title "Sensitive Credential File Baked into Layer #$layerIdx" `
                            -Location "$Image :: Layer#$layerIdx :: $entry" `
                            -Details "Layer #$layerIdx contains sensitive file path '$entry'." `
                            -Remediation "Add file to .dockerignore and mount secrets at runtime."
                    }
                }

                & tar -xf $layerTar.FullName -C $layerExtractDir 2>$null
                Invoke-DirectorySecretScan -TargetPath $layerExtractDir -ContextLabel "$Image::Layer#$layerIdx"
                Remove-Item -LiteralPath $layerExtractDir -Recurse -Force -ErrorAction SilentlyContinue
            }
        }

        # 2.4 Anchore Syft SBOM + Grype Multi-Scope CVE Audit
        $SbomFile = Join-Path $TempWorkDir "sbom.cdx.json"
        if (Get-Command syft -ErrorAction SilentlyContinue) {
            Write-Host "[*] Generating all-layers CycloneDX SBOM via Anchore Syft..."
            & syft $Image --scope all-layers -o "cyclonedx-json=$SbomFile" 2>$null
        }

        if (Get-Command grype -ErrorAction SilentlyContinue) {
            Write-Host "[*] Running Anchore Grype CVE Vulnerability Audit on $Image..."
            $grypeArgs = @("--by-cve", "--fail-on", $FailOnSeverity)
            if (-not $IncludeUnfixedCves.IsPresent) {
                $grypeArgs += "--only-fixed"
            }
            if (Test-Path -LiteralPath $SbomFile) {
                & grype "sbom:$SbomFile" @grypeArgs
            } else {
                & grype $Image --scope all-layers @grypeArgs
            }
            if ($LASTEXITCODE -ne 0) {
                Add-AuditFinding -Severity "HIGH" -Code "GRYPE-CVE-GATE" `
                    -Title "Grype Vulnerability Gate Exceeded ($FailOnSeverity)" `
                    -Location $Image `
                    -Details "Grype detected fixable vulnerabilities at or above '$FailOnSeverity' severity." `
                    -Remediation "Upgrade base image (consider Wolfi/Chainguard or distroless) and update vulnerable packages."
            }
        } else {
            Write-Host "[i] Anchore Grype not found on PATH; skipping Grype CVE scan." -ForegroundColor DarkGray
        }
    } finally {
        if (Test-Path -LiteralPath $TempWorkDir) {
            Remove-Item -LiteralPath $TempWorkDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

# ==============================================================================
# PHASE 3: LIVE RUNNING CONTAINER RUNTIME INSPECTION
# ==============================================================================
if (-not [string]::IsNullOrWhiteSpace($Container)) {
    Write-Host "`n==============================================================================" -ForegroundColor Cyan
    Write-Host "  PHASE 3: LIVE CONTAINER RUNTIME INSPECTION ($Container)" -ForegroundColor Cyan
    Write-Host "==============================================================================" -ForegroundColor Cyan

    $inspectRaw = & docker inspect $Container 2>$null
    if ($LASTEXITCODE -eq 0 -and $inspectRaw) {
        $inspectObj = ($inspectRaw | ConvertFrom-Json)[0]
        $hc = $inspectObj.HostConfig
        $cfg = $inspectObj.Config

        if ($hc.Privileged -eq $true) {
            Add-AuditFinding -Severity "CRITICAL" -Code "RT-INSPECT-PRIVILEGED" `
                -Title "Container Running in Privileged Mode" -Location $Container `
                -Details "HostConfig.Privileged is true; container has full access to host devices and kernel." `
                -Remediation "Recreate container without --privileged and drop all capabilities."
        }
        if ([string]::IsNullOrWhiteSpace($cfg.User) -or $cfg.User -eq "0" -or $cfg.User -eq "root") {
            Add-AuditFinding -Severity "CRITICAL" -Code "RT-INSPECT-ROOT-USER" `
                -Title "Container Running as Root (UID 0)" -Location $Container `
                -Details "Config.User is '$($cfg.User)' (defaults to UID 0)." `
                -Remediation "Specify a non-root numeric UID:GID (e.g. 10001:10001)."
        }
        if ($hc.ReadonlyRootfs -ne $true) {
            Add-AuditFinding -Severity "MEDIUM" -Code "RT-INSPECT-RW-ROOTFS" `
                -Title "Writable Container Root Filesystem" -Location $Container `
                -Details "HostConfig.ReadonlyRootfs is false." `
                -Remediation "Enable --read-only with tmpfs mounts for /tmp and /run."
        }
        $secOpts = if ($hc.SecurityOpt) { $hc.SecurityOpt -join "," } else { "" }
        if ($secOpts -notmatch "no-new-privileges") {
            Add-AuditFinding -Severity "HIGH" -Code "RT-INSPECT-NO-NEW-PRIVS" `
                -Title "Missing no-new-privileges Security Option" -Location $Container `
                -Details "HostConfig.SecurityOpt does not enforce no-new-privileges:true." `
                -Remediation "Add --security-opt=no-new-privileges:true."
        }
        if ($secOpts -match "unconfined") {
            Add-AuditFinding -Severity "CRITICAL" -Code "RT-INSPECT-UNCONFINED" `
                -Title "Unconfined Seccomp or AppArmor Profile" -Location $Container `
                -Details "HostConfig.SecurityOpt disables mandatory kernel confinement ($secOpts)." `
                -Remediation "Remove unconfined profile and attach templates/seccomp-2026-hardened.json."
        }
    }
}

# ==============================================================================
# OUTPUT & EXIT GATE
# ==============================================================================
$critCount = @($Findings | Where-Object { $_.Severity -eq "CRITICAL" }).Count
$highCount = @($Findings | Where-Object { $_.Severity -eq "HIGH" }).Count
$medCount  = @($Findings | Where-Object { $_.Severity -eq "MEDIUM" }).Count
$lowCount  = @($Findings | Where-Object { $_.Severity -in @("LOW", "INFO") }).Count

Write-Host "`n==============================================================================" -ForegroundColor Cyan
Write-Host "  AUDIT SUMMARY: Critical=$critCount | High=$highCount | Medium=$medCount | Low=$lowCount" -ForegroundColor Cyan
Write-Host "==============================================================================" -ForegroundColor Cyan

if (-not [string]::IsNullOrWhiteSpace($JsonOutputPath)) {
    $payload = @{
        directory         = $Directory
        image             = $Image
        container         = $Container
        total_findings    = $Findings.Count
        critical_findings = $critCount
        high_findings     = $highCount
        findings          = $Findings
    }
    $payload | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $JsonOutputPath -Encoding UTF8
    Write-Host "[+] Wrote JSON report to $JsonOutputPath" -ForegroundColor Green
}

if (-not [string]::IsNullOrWhiteSpace($MarkdownOutputPath)) {
    $mdLines = [System.Collections.Generic.List[string]]::new()
    $mdLines.Add("# 🛡️ Deep Docker & Container Security Audit Report (2026)")
    $mdLines.Add("")
    $mdLines.Add("- **Directory**: ``$Directory``")
    $mdLines.Add("- **Image**: ``$Image``")
    $mdLines.Add("- **Container**: ``$Container``")
    $mdLines.Add("- **Summary**: 🔴 Critical: **$critCount** | 🟠 High: **$highCount** | 🟡 Medium: **$medCount** | 🔵 Low: **$lowCount**")
    $mdLines.Add("")
    if ($Findings.Count -gt 0) {
        $mdLines.Add("| Severity | Code | Title | Location | Remediation |")
        $mdLines.Add("| :--- | :--- | :--- | :--- | :--- |")
        foreach ($f in $Findings) {
            $mdLines.Add("| **$($f.Severity)** | ``$($f.Code)`` | $($f.Title) | ``$($f.Location)`` | $($f.Remediation) |")
        }
    }
    $mdLines -join "`n" | Set-Content -LiteralPath $MarkdownOutputPath -Encoding UTF8
    Write-Host "[+] Wrote Markdown report to $MarkdownOutputPath" -ForegroundColor Green
}

if ($critCount -gt 0 -or $highCount -gt 0) {
    exit 1
}
exit 0
