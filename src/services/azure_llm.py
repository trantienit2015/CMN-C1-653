"""Lazily-resolved Azure OpenAI client for the deployed entry points.

The Marketplace runner constructs the graph with no arguments and provisions secrets
*afterwards*, so no connection value can be resolved while the graph is being built. This
wrapper keeps the existing `config["llm"]` injection seam and defers resolution to the moment
`complete()` / `stream()` is called, when the runner has bound the provider and
`current_secrets()` returns the same provider `InvocationContext.from_state()` exposes as
`ctx.secrets`.

- No connection value is stored on the instance; each call resolves and discards them.
- The provider client is imported inside the method: the wheel installed from the package
  registry does not ship `azure_openai_client`, so a module-level import would break collection
  in that environment. `client_available()` reports whether the class can be imported at all, so
  an entry point can decline to inject and keep the existing `llm=None` degradation.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Iterator

from framework.secrets.context import current_secrets
from shared.services.llm.base_llm import BaseLLM

# Supplied by the deployment as per-agent settings; read under these exact names.
REQUIRED_SECRET_KEYS = (
    "AZURE_OPENAI_API_KEY",
    "AZURE_OPENAI_ENDPOINT",
    "AZURE_OPENAI_DEPLOYMENT",
)

# Only static model behaviour may be passed through. An allow-list is used rather than a
# deny-list so that a connection value under an alias cannot end up stored on the instance.
ALLOWED_PASSTHROUGH_KEYS = frozenset({"temperature", "max_tokens", "max_retries", "timeout", "top_p", "seed"})


def _load_client_class() -> Any:
    """Import the provider client lazily; tests patch this seam."""
    from shared.services.llm.azure_openai_client import AzureOpenAIClient

    return AzureOpenAIClient


def client_available() -> bool:
    """Whether the provider client can be imported in this runtime."""
    try:
        _load_client_class()
    except ImportError:
        return False
    return True


class AzureConfigUnavailable(RuntimeError):
    """A connection value could not be resolved. The value itself is never in the message."""


class LazyAzureOpenAILLM(BaseLLM):
    """`BaseLLM` implementation that rebuilds the client on every call."""

    def __init__(self, **passthrough: Any) -> None:
        unexpected = sorted(set(passthrough) - ALLOWED_PASSTHROUGH_KEYS)
        if unexpected:
            raise ValueError(
                f"LazyAzureOpenAILLM: {unexpected} cannot be passed through; "
                f"only {sorted(ALLOWED_PASSTHROUGH_KEYS)} are accepted and connection values are "
                "resolved per call from the bound secret provider."
            )
        self._passthrough = dict(passthrough)
        self._tools: tuple[Any, ...] = ()

    def _build_client(self) -> Any:
        # Check the connection values before importing: in a runtime whose wheel omits the
        # provider client, an import error would otherwise mask a plain missing-secret case.
        secrets = current_secrets()
        resolved = {key: secrets.get(key) for key in REQUIRED_SECRET_KEYS}
        missing = [key for key, value in resolved.items() if not value]
        if missing:
            raise AzureConfigUnavailable(
                f"LazyAzureOpenAILLM: {missing} could not be resolved; check the per-agent "
                "settings supplied by the deployment."
            )
        client = _load_client_class()(
            {
                "api_key": resolved["AZURE_OPENAI_API_KEY"],
                "azure_endpoint": resolved["AZURE_OPENAI_ENDPOINT"],
                "azure_deployment": resolved["AZURE_OPENAI_DEPLOYMENT"],
                **self._passthrough,
            }
        )
        return client.bind_tools(list(self._tools)) if self._tools else client

    def complete(self, messages: list[Any]) -> dict[str, Any]:
        # The client is resolved through an untyped dependency, so the return is
        # annotated here to keep this module's own contract checkable.
        completion: dict[str, Any] = self._build_client().complete(messages)
        return completion

    def stream(self, messages: list[Any]) -> Iterator[str]:
        chunks: Iterator[str] = self._build_client().stream(messages)
        return chunks

    def bind_tools(self, tools: list[Any]) -> "LazyAzureOpenAILLM":
        # Return a bound copy so the shared instance keeps no mutable state.
        bound = LazyAzureOpenAILLM(**self._passthrough)
        bound._tools = tuple(deepcopy(tool) for tool in tools)
        return bound


__all__ = ["AzureConfigUnavailable", "LazyAzureOpenAILLM", "REQUIRED_SECRET_KEYS", "client_available"]
