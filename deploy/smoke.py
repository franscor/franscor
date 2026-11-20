"""Smoke test for a running federation: an agent on hub A serves, an agent on hub B
delegates to it through the federation link, end-to-end encrypted.

    python deploy/smoke.py ws://127.0.0.1:7701 ws://127.0.0.1:7702
"""

import asyncio
import sys
import tempfile
from pathlib import Path

import franscor
from franscor.capabilities import Capability


async def main(url_a: str, url_b: str) -> int:
    home = Path(tempfile.mkdtemp(prefix="franscor-smoke-"))
    worker = await franscor.connect("smoke-worker", hub_url=url_a, home=home / "a", org="acme",
                                    visibility="public", accept_orgs=["acme", "globex"],
                                    load_plugins=False, encryption="required",
                                    tools=[Capability("smoke.echo", lambda text: {"echo": text}, risk="R0")])
    boss = await franscor.connect("smoke-boss", hub_url=url_b, home=home / "b", org="globex",
                                  load_plugins=False, encryption="required")
    try:
        for _ in range(50):
            if await boss.discover("smoke.echo"):
                break
            await asyncio.sleep(0.2)
        else:
            print("FAIL: worker on hub A not discoverable from hub B", file=sys.stderr)
            return 1
        out = await boss.delegate("smoke.echo", {"text": "across the federation"})
        assert out == {"echo": "across the federation"}, out
        print("OK: cross-hub, end-to-end encrypted delegation")
        return 0
    finally:
        await boss.close()
        await worker.close()


if __name__ == "__main__":
    sys.exit(asyncio.run(main(sys.argv[1], sys.argv[2])))
