"""Release guard: the version is the same everywhere it is stated."""

import json
import re
from pathlib import Path

import franscor
from franscor._version import __version__

ROOT = Path(__file__).resolve().parents[3]


def test_versions_agree_across_python_and_typescript():
    pyproject = (ROOT / "packages" / "sdk-python" / "pyproject.toml").read_text("utf-8")
    package = json.loads((ROOT / "packages" / "sdk-typescript" / "package.json").read_text("utf-8"))
    detect = (ROOT / "packages" / "sdk-typescript" / "src" / "detect.ts").read_text("utf-8")
    versions = {
        "franscor.__version__": franscor.__version__,
        "_version.py": __version__,
        "pyproject.toml": re.search(r'^version = "([^"]+)"', pyproject, re.M).group(1),
        "package.json": package["version"],
        "detect.ts": re.search(r"SDK_VERSION = '([^']+)'", detect).group(1),
    }
    assert len(set(versions.values())) == 1, versions


def test_changelog_has_an_entry_for_this_version():
    changelog = (ROOT / "CHANGELOG.md").read_text("utf-8")
    assert f"## {__version__}" in changelog
