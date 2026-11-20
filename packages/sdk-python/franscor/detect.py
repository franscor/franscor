"""Environment detection. Reads package metadata only — never imports or runs
project code. An installed framework does not mean an agent is running, so
detection reports *what could be adapted*, and adapters decide what is.
"""

from __future__ import annotations

import os
import platform
import sys
from importlib import metadata
from pathlib import Path
from typing import Any, Dict, Optional

from ._version import FSP_VERSION, __version__

# framework -> (distribution names, adapter status in this release)
FRAMEWORKS: Dict[str, tuple] = {
    "langchain": (("langchain-core", "langchain"), "available"),
    "langgraph": (("langgraph",), "available"),   # graphs exposed via LangChain tool/runnable duck-typing
    "crewai": (("crewai",), "planned"),
    "autogen": (("autogen-core", "autogen-agentchat", "pyautogen", "ag2"), "available"),
    "openai-agents": (("openai-agents",), "available"),
    "mcp": (("mcp",), "available"),       # franscor.bridges.mcp
    "a2a": (("a2a-sdk",), "available"),   # franscor.bridges.a2a
}


def _version(dist: str) -> Optional[str]:
    try:
        return metadata.version(dist)
    except metadata.PackageNotFoundError:
        return None


def find_config(start: Optional[Path] = None) -> Optional[Path]:
    here = (start or Path.cwd()).resolve()
    for folder in (here, *here.parents):
        candidate = folder / "franscor.toml"
        if candidate.is_file():
            return candidate
    return None


def detect(start: Optional[Path] = None) -> Dict[str, Any]:
    frameworks = {}
    for name, (dists, adapter) in FRAMEWORKS.items():
        found = next(((d, v) for d in dists if (v := _version(d))), None)
        frameworks[name] = {
            "installed": bool(found),
            "distribution": found[0] if found else None,
            "version": found[1] if found else None,
            "adapter": adapter,
        }
    config = find_config(start)
    return {
        "sdk": {"name": "franscor", "version": __version__, "fsp": FSP_VERSION},
        "runtime": {
            "language": "python",
            "version": platform.python_version(),
            "implementation": platform.python_implementation(),
            "platform": sys.platform,
            "async": True,
        },
        "frameworks": frameworks,
        "config": str(config) if config else None,
        "hub_url": os.environ.get("FRANSCOR_HUB_URL"),
        "transports": ["websocket"],
    }
