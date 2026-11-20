"""Critical acceptance test: a Python agent and a TypeScript agent connect
through FRANSCOR without changing their business logic, then register,
discover each other, exchange messages, delegate tasks both ways, hit the
authorization boundary, and produce evidence that each language verifies.

Requires: the TypeScript SDK built (`npm run build`), Node >= 22.
"""

import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import franscor
from franscor.capabilities import Capability, clear_registry
from franscor.evidence import read_log, verify_chain
from franscor.hub import Hub

ROOT = Path(__file__).resolve().parents[2]
TS_AGENT = ROOT / "examples" / "interop" / "ts_agent.mjs"
TS_CLI = ROOT / "packages" / "sdk-typescript" / "dist" / "cli.js"


def _otel_exporter():
    """In-memory OpenTelemetry pipeline, if the SDK is installed."""
    try:
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import SimpleSpanProcessor
        from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
    except ImportError:
        return None
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    trace.set_tracer_provider(provider)
    return exporter


EXPORTER = _otel_exporter()


# Existing Python business logic, unchanged.
def stats(values: list) -> dict:
    return {"count": len(values), "mean": sum(values) / len(values), "max": max(values)}


def reset() -> dict:
    return {"reset": True}


async def _events(proc, until: str, timeout: float = 20):
    seen = {}
    while until not in seen:
        line = await asyncio.wait_for(proc.stdout.readline(), timeout)
        if not line:
            err = (await proc.stderr.read()).decode(errors="replace")
            raise AssertionError(f"TS agent exited early: {err}")
        event = json.loads(line)
        seen[event["event"]] = event["data"]
    return seen


@pytest.mark.skipif(not TS_CLI.exists(), reason="build the TypeScript SDK first")
async def test_python_and_typescript_agents_interoperate(tmp_path):
    clear_registry()
    hub = await Hub("127.0.0.1", 0).start()
    hub.tap = []  # every frame the hub receives, to prove it never sees payloads
    env = {**os.environ, "FRANSCOR_HUB_URL": hub.url, "FRANSCOR_HOME": str(tmp_path / "ts"),
           "FRANSCOR_PASSPORT": "require"}
    if EXPORTER is not None:
        env["FRANSCOR_TEST_OTEL"] = "1"
        EXPORTER.clear()
    py = await franscor.connect("py-analyst", hub_url=hub.url, home=tmp_path / "py",
                                tools=[Capability("math.stats", stats, "mean/max", risk="R1"),
                                       Capability("admin.reset", reset, "reset", risk="R5")],
                                load_plugins=False, reconnect=False, passport="require")
    outsider = await franscor.connect("intruder", org="globex", hub_url=hub.url,
                                      home=tmp_path / "x", load_plugins=False, reconnect=False)
    proc = await asyncio.create_subprocess_exec(
        "node", str(TS_AGENT), env=env,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    try:
        events = await _events(proc, "ready")
        ts_id = events["connected"]["agentId"]
        # 1-2. registered and discovered each other, across languages
        assert events["discovered"] == [{"name": "py-analyst", "language": "python"}]
        peers = await py.discover("text.analyze")
        assert [p["agent_id"] for p in peers] == [ts_id]
        assert peers[0]["runtime"]["language"] == "typescript"
        # 3-5. TS -> Python delegation with floats, structured result
        assert events["delegated"]["output"] == {"count": 3, "mean": 8 / 3, "max": 4}
        # Python -> TS delegation
        out = await py.delegate("text.analyze", {"text": "agents talk across languages"})
        assert out == {"words": 4, "upper": "AGENTS TALK ACROSS LANGUAGES", "avg_len": 6.25}
        # 6. authorization: R5 on Python side refused without approval handler
        assert events["refused"] == {"status": "approval_rejected", "code": "FSP-1402"}
        # R4 on TS side: TS approval handler says no
        with pytest.raises(franscor.TaskError) as err:
            await py.delegate("ledger.write", {})
        assert err.value.status == "approval_rejected"
        # another org cannot see or reach the TS agent
        assert await outsider.discover("text.analyze") == []
        with pytest.raises(franscor.TaskError) as err:
            await outsider.delegate("text.analyze", {"text": "x"}, to=ts_id, timeout=3)
        assert err.value.code == "FSP-1200"
        # Key rotation on the TypeScript side, recognized by the Python hub.
        await py.send(ts_id, "rotate", None)
        rotated = (await _events(proc, "rotated"))["rotated"]
        assert rotated["old"] == ts_id and rotated["new"] != ts_id and rotated["status"] == "connected"
        assert ts_id in hub.revoked
        assert [p["agent_id"] for p in await py.discover("text.analyze")] == [rotated["new"]]
        assert (await py.delegate("text.analyze", {"text": "still here"}))["words"] == 2

        # Passports: both sides run in "require" mode, so every task above carried
        # a hub-issued passport. The Node CLI verifies a Python-issued passport offline.
        assert events["connected"]["passport"].startswith("pp_")
        (tmp_path / "hub.pem").write_text(hub.identity.public_pem, "utf-8")
        (tmp_path / "py-passport.json").write_text(json.dumps(py.passport), "utf-8")
        cli = subprocess.run(["node", str(TS_CLI), "passport", "verify", str(tmp_path / "py-passport.json"),
                              "--hub-key", str(tmp_path / "hub.pem")], capture_output=True, text=True, timeout=30)
        assert cli.returncode == 0 and json.loads(cli.stdout)["valid"], cli.stdout + cli.stderr
        # Revocation reaches the TypeScript agent, which refuses the revoked passport.
        await hub.revoke_passport(py.passport["passport_id"], reason="interop revocation")
        await asyncio.sleep(0.3)
        with pytest.raises(franscor.TaskError) as err:
            await py.delegate("text.analyze", {"text": "revoked"}, retries=0)
        assert err.value.code == "FSP-1108"
        (tmp_path / "crl.json").write_text(json.dumps(hub.passports.crl), "utf-8")
        cli = subprocess.run(["node", str(TS_CLI), "passport", "verify", str(tmp_path / "py-passport.json"),
                              "--hub-key", str(tmp_path / "hub.pem"), "--crl", str(tmp_path / "crl.json")],
                             capture_output=True, text=True, timeout=30)
        assert cli.returncode == 1 and json.loads(cli.stdout)["code"] == "FSP-1108"

        # 3. plain message: tells the TS agent to report and stop
        await py.send(rotated["new"], "shutdown", None)
        final = await _events(proc, "evidence")
        assert await asyncio.wait_for(proc.wait(), 10) == 0
        assert final["evidence"]["stats"]["served"] == {"completed": 2, "approval_rejected": 1, "rejected": 1}

        # 7. evidence: TS records (one chain per key) verified by Python and by InterMesh
        intermesh = pytest.importorskip("intermesh.assurance.evidence")
        chains = {}
        for f in (tmp_path / "ts" / "evidence").glob("*.jsonl"):
            records = read_log(f)
            assert verify_chain(records).valid
            assert intermesh.verify_chain(records).valid
            chains[records[0]["agent_id"]] = [r["execution"]["status"] for r in records]
        assert chains == {ts_id: ["executed", "approval_rejected"], rotated["new"]: ["executed", "blocked"]}

        # E2E encryption across languages: the hub saw no task input or output.
        wire = "\n".join(str(f) for f in hub.tap)
        for plaintext in ("agents talk across languages", "AGENTS TALK", "still here", "1.5, 2.5"):
            assert plaintext not in wire
        assert '"sealed"' in wire

        # Tracing: one trace spans both languages, in both directions.
        if EXPORTER is not None:
            py_spans = EXPORTER.get_finished_spans()
            ts_client = events["delegated"]["client_spans"][0]
            py_server = next(s for s in py_spans if s.name == "franscor.task"
                             and s.attributes["franscor.capability"] == "math.stats")
            assert format(py_server.context.trace_id, "032x") == ts_client["traceId"]
            assert format(py_server.parent.span_id, "016x") == ts_client["spanId"]
            py_client = next(s for s in py_spans if s.name == "franscor.delegate"
                             and s.attributes["franscor.capability"] == "text.analyze")
            ts_server = [s for s in final["evidence"]["server_spans"]
                         if s["traceId"] == format(py_client.context.trace_id, "032x")]
            assert ts_server and ts_server[0]["parentSpanId"] == format(py_client.context.span_id, "016x")
        # Python records verified by the TypeScript CLI
        cli = subprocess.run(["node", str(TS_CLI), "verify", str(py.evidence.path)],
                             capture_output=True, text=True, timeout=30)
        report = json.loads(cli.stdout)
        assert cli.returncode == 0 and report["valid"] and report["count"] == 2, cli.stderr
    finally:
        if proc.returncode is None:
            proc.kill()
        await outsider.close()
        await py.close()
        await hub.stop()
