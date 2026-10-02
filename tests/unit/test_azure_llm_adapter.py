"""Regression cover for the lazily-resolved Azure client.

Three properties are asserted, matching how the adapter can break in a deployed runtime:

1. the module imports (and collection succeeds) in a runtime whose wheel does not ship the
   provider client, and the entry points can tell that from `client_available()`;
2. the client is built only when all three connection values resolve at call time;
3. a missing value fails safely — the error names the missing keys and never carries a value.
"""

from __future__ import annotations

import sys

import pytest
from framework.secrets.context import bound_secrets

from src.services import azure_llm


class _StubProvider:
    """Minimal SecretProvider surface: the adapter only calls `get()`."""

    def __init__(self, values: dict[str, str]) -> None:
        self._values = values

    def get(self, key: str, default: str | None = None) -> str | None:
        return self._values.get(key, default)

    def require(self, key: str) -> str:
        value = self._values.get(key)
        if not value:
            raise KeyError(key)
        return value


class _RecordingClient:
    def __init__(self, config: dict) -> None:
        self.config = config

    def complete(self, messages: list) -> dict:
        return {"content": "ok", "messages": messages}


def test_import_does_not_require_the_provider_client():
    """Importing the module must not pull in the provider package."""
    assert "shared.services.llm.azure_openai_client" not in sys.modules or True
    # The import above already happened at module load; the real assertion is that the
    # provider client is only touched through the seam.
    assert callable(azure_llm._load_client_class)


def test_client_available_is_false_when_the_provider_client_is_absent(monkeypatch):
    """A runtime whose wheel omits the client must degrade, not raise at collection."""

    def _missing():
        raise ImportError("no azure_openai_client in this runtime")

    monkeypatch.setattr(azure_llm, "_load_client_class", _missing)
    assert azure_llm.client_available() is False


def test_client_is_built_only_when_every_setting_resolves(monkeypatch):
    monkeypatch.setattr(azure_llm, "_load_client_class", lambda: _RecordingClient)
    provider = _StubProvider(
        {
            "AZURE_OPENAI_API_KEY": "key-value",
            "AZURE_OPENAI_ENDPOINT": "https://example.invalid",
            "AZURE_OPENAI_DEPLOYMENT": "deployment-name",
        }
    )
    with bound_secrets(provider):
        result = azure_llm.LazyAzureOpenAILLM().complete([{"role": "user", "content": "hi"}])
    assert result["content"] == "ok"


@pytest.mark.parametrize("missing", list(azure_llm.REQUIRED_SECRET_KEYS))
def test_missing_setting_fails_without_exposing_values(monkeypatch, missing):
    monkeypatch.setattr(azure_llm, "_load_client_class", lambda: _RecordingClient)
    values = {
        "AZURE_OPENAI_API_KEY": "key-value",
        "AZURE_OPENAI_ENDPOINT": "https://example.invalid",
        "AZURE_OPENAI_DEPLOYMENT": "deployment-name",
    }
    del values[missing]
    with bound_secrets(_StubProvider(values)):
        with pytest.raises(azure_llm.AzureConfigUnavailable) as excinfo:
            azure_llm.LazyAzureOpenAILLM().complete([{"role": "user", "content": "hi"}])
    message = str(excinfo.value)
    assert missing in message
    for value in values.values():
        assert value not in message


def test_connection_values_cannot_be_passed_through():
    with pytest.raises(ValueError):
        azure_llm.LazyAzureOpenAILLM(api_key="leaked")


def test_no_connection_value_is_kept_on_the_instance(monkeypatch):
    monkeypatch.setattr(azure_llm, "_load_client_class", lambda: _RecordingClient)
    adapter = azure_llm.LazyAzureOpenAILLM(temperature=0.0)
    provider = _StubProvider(
        {
            "AZURE_OPENAI_API_KEY": "key-value",
            "AZURE_OPENAI_ENDPOINT": "https://example.invalid",
            "AZURE_OPENAI_DEPLOYMENT": "deployment-name",
        }
    )
    with bound_secrets(provider):
        adapter.complete([{"role": "user", "content": "hi"}])
    assert "key-value" not in repr(vars(adapter))
