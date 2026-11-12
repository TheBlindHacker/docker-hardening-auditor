"""
Unit tests for Docker & Container Hardening Security Auditor (v2.0 — 2026 Edition).
"""

import sys
from pathlib import Path

# Add scripts directory to path
scripts_dir = Path(__file__).parent.parent / "scripts"
sys.path.insert(0, str(scripts_dir))

from audit_container import (  # noqa: E402
    audit_dockerfile,
    audit_docker_compose,
    calculate_shannon_entropy,
    decode_capabilities,
    scan_file_for_secrets,
)


def test_decode_capabilities() -> None:
    # 0x0000000000200000 = bit 21 = CAP_SYS_ADMIN
    caps = decode_capabilities("0x0000000000200000")
    assert "CAP_SYS_ADMIN" in caps

    # Bit 0 = CAP_CHOWN
    caps_chown = decode_capabilities("0x1")
    assert "CAP_CHOWN" in caps_chown


def test_audit_insecure_dockerfile(tmp_path: Path) -> None:
    df = tmp_path / "Dockerfile"
    df.write_text(
        """
FROM node:latest
EXPOSE 22
ARG API_SECRET_TOKEN
ENV DB_PASSWORD=supersecret
RUN apt-get update && apt-get install -y doas && chmod 777 /app
WORKDIR /proc/self/fd/8
ADD local.tar /app/
""",
        encoding="utf-8",
    )

    findings = audit_dockerfile(df)
    codes = {f.code for f in findings}

    assert "DF-TAG-LATEST" in codes
    assert "DF-EXPOSE-SSH" in codes
    assert "DF-ARG-SECRET" in codes
    assert "DF-ENV-SECRET" in codes
    assert "DF-PRIV-ESC-BIN" in codes
    assert "DF-CHMOD-777" in codes
    assert "DF-CVE-2024-21626" in codes
    assert "DF-NO-USER" in codes
    assert "DF-NO-HEALTHCHECK" in codes


def test_audit_hardened_templates() -> None:
    templates_dir = Path(__file__).parent.parent / "templates"
    df_hardened = templates_dir / "Dockerfile.hardened"
    dc_hardened = templates_dir / "docker-compose.hardened.yml"

    df_findings = audit_dockerfile(df_hardened)
    crit_high_df = [f for f in df_findings if f.severity in ("CRITICAL", "HIGH")]
    assert len(crit_high_df) == 0

    dc_findings = audit_docker_compose(dc_hardened)
    crit_high_dc = [f for f in dc_findings if f.severity in ("CRITICAL", "HIGH")]
    assert len(crit_high_dc) == 0


def test_audit_insecure_compose(tmp_path: Path) -> None:
    dc = tmp_path / "docker-compose.yml"
    dc.write_text(
        """
version: '3'
services:
  app:
    image: nginx
    privileged: true
    network_mode: host
    security_opt:
      - seccomp:unconfined
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    ports:
      - "80:80"
""",
        encoding="utf-8",
    )

    findings = audit_docker_compose(dc)
    codes = {f.code for f in findings}

    assert "DC-PRIVILEGED" in codes
    assert "DC-HOST-NAMESPACE" in codes
    assert "DC-UNCONFINED-MAC" in codes
    assert "DC-DANGEROUS-MOUNT" in codes
    assert "DC-EXPOSED-PORT" in codes
    assert "DC-NO-NEW-PRIVILEGES" in codes
    assert "DC-NO-CAP-DROP" in codes
    assert "DC-WRITABLE-ROOTFS" in codes
    assert "DC-NO-RESOURCE-LIMITS" in codes


def test_secret_and_whiteout_scanner(tmp_path: Path) -> None:
    # 1. Test OverlayFS whiteout marker detection
    wh_file = tmp_path / ".wh..env"
    wh_file.write_text("", encoding="utf-8")
    wh_findings = scan_file_for_secrets(wh_file)
    assert any(f.code == "LYR-WHITEOUT-FILE" for f in wh_findings)

    # 2. Test structural regex secret detection (constructed dynamically in test)
    env_file = tmp_path / "layer_config.cfg"
    mock_akia = "AK" + "IA" + "1234567890ABCDEF"
    env_file.write_text(f"aws_id = {mock_akia}\n", encoding="utf-8")
    sec_findings = scan_file_for_secrets(env_file)
    assert any(f.code == "SEC-AWS-AKIA" for f in sec_findings)

    # 3. Test Shannon entropy calculator
    high_ent = calculate_shannon_entropy("aB3$xY9!mK2#pL8@qR5%vN7^zW1&cF4*")
    low_ent = calculate_shannon_entropy("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    assert high_ent > 4.25
    assert low_ent == 0.0
