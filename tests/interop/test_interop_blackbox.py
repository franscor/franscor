"""Cross-language black box test (FSP 0.2 §3): a Python hub audits real traffic
between a Python agent and a TypeScript agent, a peer hub cosigns the checkpoint,
and the Node.js CLI — a third party with public keys only — verifies the export,
refuses an edited one, and checks that a later export extends the earlier one.

Requires: the TypeScript SDK built (`npm run build`), Node >= 22.
"""

import asyncio
import json
import os
import subprocess
from pathlib import Path

import pytest

import franscor
from franscor.capabilities import clear_registry
from franscor.hub import Hub
from franscor.identity import Identity

ROOT = Path(__file__).resolve().parents[2]
TS_WORKER = ROOT / "examples" / "interop" / "ts_permit_worker.mjs"
TS_CLI = ROOT / "packages" / "sdk-typescript" / "dist" / "cli.js"

pytestmark = pytest.mark.skipif(not TS_CLI.exists(), reason="build the TypeScript SDK first")


async def until(predicate, timeout=10.0):
    for _ in range(int(timeout / 0.05)):
        if predicate():
            return
        await asyncio.sleep(0.05)
    raise AssertionError("condition not reached")


async def _event(proc, name, timeout=20):
    while True:
        line = await asyncio.wait_for(proc.stdout.readline(), timeout)
        if not line:
            raise AssertionError("TS worker exited early: " + (await proc.stderr.read()).decode(errors="replace"))
        event = json.loads(line)
        if event["event"] == name:
            return event["data"]


def node_cli(*args):
    return subprocess.run(["node", str(TS_CLI), "audit", *args], capture_output=True, text=True, timeout=30)


async def test_node_cli_verifies_a_python_hub_black_box(tmp_path):
    clear_registry()
    hub_id, peer_id = Identity.generate(), Identity.generate()
    peer = await Hub("127.0.0.1", 0, identity=peer_id, allowed_peers=[hub_id.agent_id], audit=True,
                     checkpoint_interval=3600).start()
    hub = await Hub("127.0.0.1", 0, identity=hub_id, allowed_peers=[peer_id.agent_id], peers=[peer.url],
                    audit=tmp_path / "audit", checkpoint_interval=3600).start()
    await until(lambda: hub_id.agent_id in peer.links and peer_id.agent_id in hub.links)
    env = {**os.environ, "FRANSCOR_HUB_URL": hub.url, "FRANSCOR_HOME": str(tmp_path / "ts")}
    proc = await asyncio.create_subprocess_exec("node", str(TS_WORKER), env=env,
                                                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    py = await franscor.connect("ops", org="acme", hub_url=hub.url, home=tmp_path / "py",
                                load_plugins=False, reconnect=False)
    outsider = await franscor.connect("outsider", org="initech", hub_url=hub.url, home=tmp_path / "x",
                                      load_plugins=False, reconnect=False)
    try:
        ts_id = (await _event(proc, "connected"))["agentId"]
        assert await py.delegate("invoice.total", {"lines": [40, 2]}, to=ts_id) == {"total": 42}
        with pytest.raises(franscor.TaskError):        # the TS agent only accepts acme and globex
            await outsider.delegate("invoice.total", {"lines": [1]}, to=ts_id, timeout=3, retries=0)
        first = await hub.checkpoint()
        await until(lambda: peer_id.agent_id in hub.audit.cosignatures.get(first["tree_size"], {}))
        (tmp_path / "first.json").write_text(json.dumps(hub.audit.export()), "utf-8")

        await py.delegate("invoice.total", {"lines": [1]}, to=ts_id)
        second = await hub.checkpoint()
        await until(lambda: peer_id.agent_id in hub.audit.cosignatures.get(second["tree_size"], {}))
        (tmp_path / "second.json").write_text(json.dumps(hub.audit.export(since=first["tree_size"])), "utf-8")
        (tmp_path / "hub.pem").write_text(hub_id.public_pem, "utf-8")
        (tmp_path / "peer.pem").write_text(peer_id.public_pem, "utf-8")

        ok = node_cli("verify", str(tmp_path / "first.json"), "--hub-key", str(tmp_path / "hub.pem"),
                      "--witness-key", str(tmp_path / "peer.pem"))
        report = json.loads(ok.stdout)
        assert ok.returncode == 0 and report["valid"], ok.stdout + ok.stderr
        assert report["witnesses"] == [peer_id.agent_id]
        entries = [json.loads(e["leaf"]) for e in json.loads((tmp_path / "first.json").read_text())["entries"]]
        assert [(e["frame"], e["decision"]) for e in entries] == [
            ("task.request", "allowed"), ("task.result", "allowed"), ("task.request", "blocked")]
        assert entries[2]["from"] == outsider.agent_id and entries[2]["code"] == "FSP-1201"
        later = node_cli("verify", str(tmp_path / "second.json"), "--hub-key", str(tmp_path / "hub.pem"),
                         "--previous", str(tmp_path / "first.json"))
        assert later.returncode == 0 and json.loads(later.stdout)["extends_previous"], later.stdout

        edited = json.loads((tmp_path / "first.json").read_text())
        edited["entries"][0]["leaf"] = edited["entries"][0]["leaf"].replace('"allowed"', '"masked"')
        (tmp_path / "edited.json").write_text(json.dumps(edited), "utf-8")
        bad = node_cli("verify", str(tmp_path / "edited.json"), "--hub-key", str(tmp_path / "hub.pem"))
        assert bad.returncode == 1 and not json.loads(bad.stdout)["valid"]
        # And the Python CLI agrees on the exported directory.
        import sys
        py_cli = subprocess.run([sys.executable, "-m", "franscor.cli", "audit", "verify", str(tmp_path / "second.json"),
                                 "--hub-key", str(tmp_path / "hub.pem"), "--previous", str(tmp_path / "first.json")],
                                capture_output=True, text=True, timeout=30)
        assert py_cli.returncode == 0 and json.loads(py_cli.stdout)["extends_previous"]
        await py.send(ts_id, "shutdown", None)
        await _event(proc, "evidence")
        assert await asyncio.wait_for(proc.wait(), 10) == 0
    finally:
        if proc.returncode is None:
            proc.kill()
        await outsider.close()
        await py.close()
        await hub.stop()
        await peer.stop()
