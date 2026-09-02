"""Release-level contracts for the v0.7.0-dev engineering baseline."""

from __future__ import annotations

from pathlib import Path

from openclaw_guard import __version__
from openclaw_guard.main import _select_launch_web, build_parser
from openclaw_guard.policy.catalog import PolicyBundle


ROOT = Path(__file__).parents[1]


def test_product_and_package_versions_share_the_v070_development_line():
    assert __version__ == "0.7.0-dev"
    assert 'version = "0.7.0.dev0"' in (ROOT / "pyproject.toml").read_text(encoding="utf-8")


def test_pmkb_bundle_components_are_all_on_110():
    bundle = PolicyBundle.load(ROOT / "policies" / "permissions")
    assert bundle.version == "1.1.0"


def test_fastapi_is_the_only_cli_web_selector():
    args = build_parser().parse_args(["run"])
    launcher = _select_launch_web(args)
    assert launcher.__module__ == "openclaw_guard.web"
