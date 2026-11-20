"""The committed vectors must match what this implementation produces today."""

import importlib.util
import json
from pathlib import Path

VECTORS = Path(__file__).resolve().parents[3] / "protocol" / "vectors"


def test_vectors_are_current():
    spec = importlib.util.spec_from_file_location("gen", VECTORS / "generate.py")
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    committed = json.loads((VECTORS / "vectors.json").read_text("utf-8"))
    assert gen.build() == committed


def test_schemas_accept_the_vectors():
    jsonschema = __import__("pytest").importorskip("jsonschema")
    v = json.loads((VECTORS / "vectors.json").read_text("utf-8"))
    schemas = VECTORS.parent / "schemas"
    load = lambda n: json.loads((schemas / f"{n}.json").read_text("utf-8"))  # noqa: E731
    jsonschema.validate(v["envelope"]["value"], load("envelope"))
    task = load("task")
    jsonschema.validate(v["envelope"]["value"]["body"], {**task["$defs"]["request"], "$defs": task["$defs"]})
    for key in ("rotation", "revocation"):
        jsonschema.validate(v[key], load("statements"))
    jsonschema.validate(v["card"], load("agent-card"))
    jsonschema.validate(v["sealed"]["value"], {**task, **task["$defs"]["sealed"]})
    jsonschema.validate(v["passport"], load("passport"))
    jsonschema.validate(v["passport_crl"], load("passport-crl"))
    jsonschema.validate(v["permit"], load("permit"))
    for e in v["audit"]["bundle"]["entries"]:
        jsonschema.validate(json.loads(e["leaf"]), load("audit-entry"))
    registry_schemas = {f"{n}.json": load(n) for n in ("audit-checkpoint", "audit-cosignature")}
    from referencing import Registry, Resource
    registry = Registry().with_resources(
        (uri, Resource.from_contents(doc)) for uri, doc in registry_schemas.items())
    bundle_schema = {**load("audit-bundle"), "$id": "audit-bundle.json"}
    jsonschema.Draft202012Validator(bundle_schema, registry=registry).validate(v["audit"]["bundle"])
