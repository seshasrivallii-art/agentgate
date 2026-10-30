import os

import httpx
import pytest

GATEWAY = os.environ.get("GATEWAY_URL", "http://localhost:8000")


def _stack_up() -> bool:
    try:
        return httpx.get(f"{GATEWAY}/healthz", timeout=2).status_code == 200
    except httpx.HTTPError:
        return False


def pytest_collection_modifyitems(config, items):
    if any("stack" in item.keywords for item in items) and not _stack_up():
        skip = pytest.mark.skip(reason="stack not reachable; run `docker compose --profile test run --rm tests`")
        for item in items:
            if "stack" in item.keywords:
                item.add_marker(skip)
