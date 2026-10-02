"""AGENTIC STAR Marketplace entry point — the container's ``CMD``.

Entry adapter only, in the same sense ``src/api/server.py`` is one. The runner owns the
lifecycle: it constructs the graph class, compiles it, builds the SecretProvider, provisions
secrets, then runs one Marketplace execution (identity, input, progress events, terminal
delivery, exit) and exits.

The runner constructs the graph itself, so ``config/config.yaml`` is loaded here and handed
over explicitly — without it every runtime parameter would fall back to its framework default
on this path only. The file is read the same way ``src/api/server.py`` reads it, so both entry
paths resolve identical values.

``agent_name`` / ``namespace`` mirror the values ``src/api/server.py`` passes to
``secrets_factory``, so secrets resolve from one place whichever transport started the agent.
"""

from pathlib import Path

import yaml
from shared.bootstrap.marketplace_app import run_agent_marketplace

from src.services.azure_llm import LazyAzureOpenAILLM, client_available
from src.graph.graph import Graph

# cli.py sits next to config/ both in the repository and in the image
# (/app/cli.py + /app/config/config.yaml), so one expression covers both.
_CONFIG_PATH = Path(__file__).resolve().parent / "config" / "config.yaml"

# Identity for the Marketplace runner. Mirrors what src/api/server.py hands to
# secrets_factory so both entry paths resolve secrets from the same location; an empty
# or defaulted value here would silently point the Marketplace path elsewhere.
_AGENT_NAME = "cmn-c1-653"
_NAMESPACE = "cmn"

# Add overrides here to set values without editing config/config.yaml.
extend_config: dict = {}

if __name__ == "__main__":
    _config = yaml.safe_load(_CONFIG_PATH.read_text(encoding="utf-8")) or {} if _CONFIG_PATH.exists() else {}
    _runtime_config = {**_config, **extend_config}
    # The runner provisions secrets after construction, so the client cannot be built here;
    # the adapter resolves its connection values per call instead. Inject it only when the
    # provider client exists in this runtime, otherwise keep the deterministic path.
    if client_available():
        _runtime_config["llm"] = LazyAzureOpenAILLM()
    run_agent_marketplace(
        Graph,
        agent_name=_AGENT_NAME,
        namespace=_NAMESPACE,
        config=_runtime_config,
    )
