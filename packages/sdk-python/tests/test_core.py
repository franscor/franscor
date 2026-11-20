import copy
import json

import pytest

from franscor import errors as E
from franscor.canonical import CanonicalError, canonical_json
from franscor.envelope import seal, verify
from franscor.evidence import EvidenceLog, read_log, verify_chain
from franscor.identity import Identity, agent_id_from_pem


@pytest.mark.parametrize("value, expected", [
    (1.5, "1.5"), (2.0, "2"), (0.1, "0.1"), (-0.000001, "-0.000001"),
    (1e-7, "1e-7"), (9007199254740991.0, "9007199254740991"), (1.5e-10, "1.5e-10"),
    (123456789.125, "123456789.125"), (1.25e-300, "1.25e-300"),
    (5e-324, "5e-324"), (-0.0, "0"),
])
def test_floats_match_ecmascript(value, expected):
    assert canonical_json(value) == expected


def test_canonical_sorting_and_unicode():
    assert canonical_json({"b": 1, "a": ["é", None, True]}) == '{"a":["é",null,true],"b":1}'


def test_rejects_unsafe_values():
    for bad in (float("nan"), float("inf"), 2**53, 1e20, 1e21, {1: "x"}):
        with pytest.raises(CanonicalError):
            canonical_json(bad)


def test_identity_is_self_certifying(tmp_path):
    a = Identity.load_or_create("alpha", tmp_path)
    b = Identity.load_or_create("alpha", tmp_path)
    assert a.agent_id == b.agent_id == agent_id_from_pem(a.public_pem)
    assert "PRIVATE" not in repr(a)
    with pytest.raises(ValueError):
        Identity.path_for("../evil", tmp_path)


def test_envelope_tamper_and_spoof():
    me, other = Identity.generate(), Identity.generate()
    env = seal(me, "message", {"topic": "t", "data": 1}, to=other.agent_id)
    verify(env, me.public_pem)
    forged = copy.deepcopy(env)
    forged["body"]["data"] = 2
    with pytest.raises(E.FSPError) as err:
        verify(forged, me.public_pem)
    assert err.value.code == E.BAD_SIGNATURE
    with pytest.raises(E.FSPError) as err:
        verify(env, other.public_pem)
    assert err.value.code == E.ID_MISMATCH
    stale = seal(me, "message", {}, ts=1)
    with pytest.raises(E.FSPError) as err:
        verify(stale, me.public_pem)
    assert err.value.code == E.STALE


def test_evidence_chain_detects_removal(tmp_path):
    ident = Identity.generate()
    log = EvidenceLog(tmp_path / "ev.jsonl", ident, "acme")
    for i in range(3):
        log.append(agent_id=ident.agent_id, org="acme", capability="x.y", risk=2,
                   decision="allow", rule="accepted", status="executed",
                   task_id=f"task-{i}", requester=ident.agent_id, input_hash="0" * 64)
    records = read_log(tmp_path / "ev.jsonl")
    assert verify_chain(records, ident.public_pem).valid
    assert not verify_chain([records[0], records[2]]).valid
    records[1]["execution"]["status"] = "blocked"
    assert not verify_chain(records).valid
    # A reopened log continues the chain.
    EvidenceLog(tmp_path / "ev.jsonl", ident, "acme").append(
        agent_id=ident.agent_id, org="acme", capability="x.y", risk=2, decision="allow",
        rule="accepted", status="executed", task_id="task-3", requester=ident.agent_id,
        input_hash=None)
    assert verify_chain(read_log(tmp_path / "ev.jsonl")).valid


def test_evidence_is_intermesh_compatible(tmp_path):
    intermesh = pytest.importorskip("intermesh.assurance.evidence")
    ident = Identity.generate()
    log = EvidenceLog(tmp_path / "ev.jsonl", ident, "acme")
    for i in range(2):
        log.append(agent_id=ident.agent_id, org="acme", capability="pay.send", risk=4,
                   decision="approval", rule="r", status="approval_rejected",
                   task_id=str(i), requester=ident.agent_id, input_hash="a" * 64)
    report = intermesh.verify_chain(read_log(tmp_path / "ev.jsonl"))
    assert report.valid, report.errors
