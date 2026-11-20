"""Cross-language Permit test (FSP 0.2 §2): a Python agent of a partner hub
delegates to a TypeScript agent behind a hub with a peering file.

* the receiving (Python) hub issues the permit and refuses what it does not cover;
* the TypeScript agent verifies the permit itself and records its ID in evidence;
* the Node CLI verifies a Python-issued permit offline;
* a TypeScript agent in `permit="require"` mode refuses a partner agent that
  arrives without a permit (hub without a peering file).

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
from franscor.evidence import read_log, verify_chain
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


async def _setup(tmp_path, peering):
    clear_registry()
    a_id, b_id = Identity.generate(), Identity.generate()
    path = None
    if peering:
        path = tmp_path / "peering.json"
        path.write_text(json.dumps({"fsp": "0.2", "type": "peering", "peers": [{
            "hub_id": a_id.agent_id, "name": "globex", "rules": [{
                "orgs": ["globex"], "capabilities": ["invoice.total"], "scopes": ["invoices:read"],
                "rate_per_min": 30, "max_depth": 0, "ttl": "10m"}]}]}))
    b = await Hub("127.0.0.1", 0, identity=b_id, allowed_peers=[a_id.agent_id], peering=path).start()
    a = await Hub("127.0.0.1", 0, identity=a_id, allowed_peers=[b_id.agent_id], peers=[b.url]).start()
    await until(lambda: a_id.agent_id in b.links and b_id.agent_id in a.links)
    env = {**os.environ, "FRANSCOR_HUB_URL": b.url, "FRANSCOR_HOME": str(tmp_path / "ts"),
           "FRANSCOR_PERMIT": "require"}
    proc = await asyncio.create_subprocess_exec("node", str(TS_WORKER), env=env,
                                                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    ts_id = (await _event(proc, "connected"))["agentId"]
    boss = await franscor.connect("boss", org="globex", hub_url=a.url, home=tmp_path / "boss",
                                  load_plugins=False, reconnect=False)
    local = await franscor.connect("ops", org="acme", hub_url=b.url, home=tmp_path / "ops",
                                   load_plugins=False, reconnect=False)
    await until(lambda: ts_id in a.remote)
    return a, b, proc, ts_id, boss, local


async def _teardown(a, b, proc, boss, local, ts_id):
    try:
        await local.send(ts_id, "shutdown", None)
        final = await _event(proc, "evidence")
        assert await asyncio.wait_for(proc.wait(), 10) == 0
        return final
    finally:
        if proc.returncode is None:
            proc.kill()
        await local.close()
        await boss.close()
        await a.stop()
        await b.stop()


async def test_typescript_agent_honours_permits_issued_by_its_python_hub(tmp_path):
    a, b, proc, ts_id, boss, local = await _setup(tmp_path, peering=True)
    final = None
    try:
        out = await boss.delegate("invoice.total", {"lines": [10, 5]}, to=ts_id, scopes=["invoices:read"])
        assert out == {"total": 15}
        with pytest.raises(franscor.TaskError) as err:      # not in the permit: refused by the hub
            await boss.delegate("payment.send", {"amount": 1}, to=ts_id, timeout=3, retries=0)
        assert err.value.code == "FSP-1201"
        # A local agent of the same hub needs no permit, even in "require" mode.
        assert await local.delegate("payment.send", {"amount": 2}, to=ts_id) == {"sent": 2}
        permit = next(iter(b.permits.issued.values()))
        (tmp_path / "permit.json").write_text(json.dumps(permit), "utf-8")
        (tmp_path / "hub.pem").write_text(b.identity.public_pem, "utf-8")
        cli = subprocess.run(["node", str(TS_CLI), "permit", "verify", str(tmp_path / "permit.json"),
                              "--hub-key", str(tmp_path / "hub.pem"), "--capability", "invoice.total"],
                             capture_output=True, text=True, timeout=30)
        assert cli.returncode == 0 and json.loads(cli.stdout)["valid"], cli.stdout + cli.stderr
        cli = subprocess.run(["node", str(TS_CLI), "permit", "verify", str(tmp_path / "permit.json"),
                              "--hub-key", str(tmp_path / "hub.pem"), "--capability", "payment.send"],
                             capture_output=True, text=True, timeout=30)
        assert cli.returncode == 1 and json.loads(cli.stdout)["code"] == "FSP-1112"
    finally:
        final = await _teardown(a, b, proc, boss, local, ts_id)
    assert final["stats"]["served"] == {"completed": 2}
    records = read_log(Path(final["path"]))
    assert verify_chain(records).valid
    by_requester = {r["execution"]["requester"]: r["execution"] for r in records}
    assert by_requester[boss.agent_id]["permit_id"] == permit["permit_id"]
    assert "permit_id" not in by_requester[local.agent_id]
    intermesh = pytest.importorskip("intermesh.assurance.evidence")
    assert intermesh.verify_chain(records).valid   # still InterMesh Action Evidence v0.1


async def test_typescript_agent_requires_a_permit_from_partner_agents(tmp_path):
    a, b, proc, ts_id, boss, local = await _setup(tmp_path, peering=False)
    final = None
    try:
        with pytest.raises(franscor.TaskError) as err:
            await boss.delegate("invoice.total", {"lines": [1]}, to=ts_id, timeout=5, retries=0)
        assert err.value.code == "FSP-1109"
    finally:
        final = await _teardown(a, b, proc, boss, local, ts_id)
    records = read_log(Path(final["path"]))
    assert records[-1]["authorization"]["rule"] == "permit-required"
