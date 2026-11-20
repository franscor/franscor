"""Measure, don't claim: connect time, delegation latency and throughput.

    python franscor/benchmarks/bench_python.py [--n 500] [--concurrency 32]

Everything runs on loopback in one process (hub + two agents), so this
measures SDK + protocol overhead (signing, verification, routing, evidence
writes), not network latency.
"""

import argparse
import asyncio
import statistics
import tempfile
import time
from pathlib import Path

import franscor
from franscor.capabilities import Capability
from franscor.hub import Hub


async def main(n: int, concurrency: int) -> None:
    home = Path(tempfile.mkdtemp(prefix="franscor-bench-"))
    hub = await Hub("127.0.0.1", 0, rate=1e6, burst=1e6).start()
    t0 = time.perf_counter()
    worker = await franscor.connect("worker", hub_url=hub.url, home=home / "w", load_plugins=False,
                                    tools=[Capability("echo", lambda x: x, risk="R0")])
    connect_ms = (time.perf_counter() - t0) * 1000
    boss = await franscor.connect("boss", hub_url=hub.url, home=home / "b", load_plugins=False)
    target = worker.agent_id

    for _ in range(20):  # warm-up
        await boss.delegate("echo", {"x": 1}, to=target)

    lat = []
    for i in range(n):
        s = time.perf_counter()
        await boss.delegate("echo", {"i": i, "v": 0.5}, to=target)
        lat.append((time.perf_counter() - s) * 1000)

    sem = asyncio.Semaphore(concurrency)

    async def one(i):
        async with sem:
            await boss.delegate("echo", {"i": i}, to=target)

    s = time.perf_counter()
    await asyncio.gather(*(one(i) for i in range(n)))
    throughput = n / (time.perf_counter() - s)

    lat.sort()
    print(f"connect (detect+adapters+identity+handshake): {connect_ms:.1f} ms")
    print(f"sequential delegate round-trip, n={n}: p50 {statistics.median(lat):.2f} ms, "
          f"p95 {lat[int(n * 0.95) - 1]:.2f} ms, p99 {lat[int(n * 0.99) - 1]:.2f} ms")
    print(f"concurrent delegate throughput (concurrency {concurrency}): {throughput:.0f} tasks/s")
    await boss.close()
    await worker.close()
    await hub.stop()


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--n", type=int, default=500)
    p.add_argument("--concurrency", type=int, default=32)
    a = p.parse_args()
    asyncio.run(main(a.n, a.concurrency))
