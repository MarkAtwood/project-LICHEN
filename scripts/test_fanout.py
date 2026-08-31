# SPDX-License-Identifier: GPL-3.0-or-later
"""Unit tests for fanout.py error diagnosis. No network, no LLM."""
from __future__ import annotations

import sys
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import fanout  # noqa: E402


def test_connect_error_names_endpoint_and_override() -> None:
    exc = httpx.ConnectError("Connection refused")
    message = fanout.describe_error(exc)
    assert "endpoint unreachable" in message
    assert fanout.LITELLM_URL in message
    assert "LITELLM_URL" in message


def test_timeout_names_endpoint_even_with_empty_message() -> None:
    # httpx timeout exceptions usually stringify empty; the diagnosis must
    # still name the endpoint (this was the cryptic-failure mode being fixed).
    exc = httpx.ReadTimeout("")
    message = fanout.describe_error(exc)
    assert "endpoint unreachable or timed out" in message
    assert fanout.LITELLM_URL in message
    assert "ReadTimeout" in message


def test_zero_agents_does_not_claim_all_failed(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(fanout, "fanout", lambda prompts, model: [])
    monkeypatch.setattr(fanout.asyncio, "run", lambda coro: coro)
    fanout.main(["task", "--agents", "0"])  # vacuous: no failure claim, exit 0
    out = capsys.readouterr().out
    assert "Fanning out to 0 agents" in out


def test_404_names_url_path_and_model_hints() -> None:
    request = httpx.Request("POST", f"{fanout.LITELLM_URL}/chat/completions")
    response = httpx.Response(404, request=request)
    exc = httpx.HTTPStatusError(
        "Client error '404 Not Found'", request=request, response=response
    )
    message = fanout.describe_error(exc)
    assert "404" in message
    assert "/chat/completions" in message
    assert "LITELLM_MODEL" in message


def test_other_status_is_reported_with_code() -> None:
    request = httpx.Request("POST", f"{fanout.LITELLM_URL}/chat/completions")
    response = httpx.Response(503, request=request)
    exc = httpx.HTTPStatusError(
        "Service Unavailable", request=request, response=response
    )
    message = fanout.describe_error(exc)
    assert "503" in message


def test_unknown_exception_passes_through() -> None:
    message = fanout.describe_error(ValueError("boom"))
    assert "ValueError" in message
    assert "boom" in message


def test_main_exits_nonzero_when_every_agent_fails(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        fanout, "fanout", lambda prompts, model: [httpx.ConnectError("refused")] * 2
    )
    monkeypatch.setattr(fanout.asyncio, "run", lambda coro: coro)
    with pytest.raises(SystemExit) as excinfo:
        fanout.main(["task", "--agents", "2"])
    assert excinfo.value.code != 0
    assert "all 2 agent calls failed" in str(excinfo.value)


def test_main_succeeds_when_any_agent_succeeds(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        fanout,
        "fanout",
        lambda prompts, model: [
            httpx.ConnectError("refused"),
            {"label": "agent-1", "response": "ok"},
        ],
    )
    monkeypatch.setattr(fanout.asyncio, "run", lambda coro: coro)
    fanout.main(["task", "--agents", "2"])  # must not raise SystemExit
    out = capsys.readouterr().out
    assert "ERROR:" in out
    assert "=== agent-1 ===" in out
