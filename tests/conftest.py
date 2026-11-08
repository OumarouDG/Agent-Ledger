"""Test tiers: unit tests run by default; tests marked `live` call real AWS and run only with --live."""

import pytest


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--live",
        action="store_true",
        default=False,
        help="Run tests marked @pytest.mark.live against the workshop AWS account.",
    )


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if config.getoption("--live"):
        return
    skip_live = pytest.mark.skip(reason="live test: needs AWS credentials; run with --live")
    for item in items:
        if "live" in item.keywords:
            item.add_marker(skip_live)
