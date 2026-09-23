"""v4 performance tests: batch ingestion path + throughput benchmark."""

from __future__ import annotations

import json
import time

from modules.log_ingest import BatchIngester, parse_syslog_line


def _burst(n: int):
    return [
        f"<13>Sep 22 10:{i % 60:02d}:{(i * 7) % 60:02d} host{i % 5} "
        f"sshd[{1000 + i}]: Failed password for root from 203.0.113.{i % 250}"
        for i in range(n)
    ]


def test_batch_ingester_delivers_everything():
    seen = []
    ing = BatchIngester(sink=seen.append, batch_size=200, flush_interval_s=0.05)
    ing.start()
    try:
        lines = _burst(1000)
        ing.submit_many(lines)
        flushed = ing.flush(timeout_s=10.0)
        assert flushed == 1000
        assert len(seen) == 1000
        assert all(e["event"] == "SYSLOG" for e in seen)
    finally:
        ing.stop()
    stats = ing.stats()
    assert stats["submitted"] == 1000 and stats["batches"] >= 1


def test_batch_ingester_submit_never_blocks_on_slow_sink():
    def slow_sink(event):
        time.sleep(0.002)  # 2ms per event — slow sink

    ing = BatchIngester(sink=slow_sink, batch_size=50, flush_interval_s=0.05)
    ing.start()
    try:
        t0 = time.perf_counter()
        ing.submit_many(_burst(200))
        submit_s = time.perf_counter() - t0
        assert submit_s < 1.0, f"submit blocked for {submit_s:.2f}s on a slow sink"
        ing.flush(timeout_s=15.0)
    finally:
        ing.stop()


def test_ingest_throughput_benchmark(capsys):
    """Measure and REPORT the batch ingest rate (events/sec)."""
    seen = []
    ing = BatchIngester(sink=seen.append, batch_size=500, flush_interval_s=0.1)
    ing.start()
    try:
        lines = _burst(20_000)
        t0 = time.perf_counter()
        ing.submit_many(lines)
        ing.flush(timeout_s=30.0)
        dt = time.perf_counter() - t0
    finally:
        ing.stop()
    rate = len(seen) / max(dt, 1e-6)
    print(f"\n[BENCHMARK] batch ingest: {len(seen)} events in {dt:.2f}s = {rate:,.0f} events/sec")
    assert len(seen) == 20_000
    assert rate > 1_000, f"throughput {rate:.0f} ev/s below 1k floor"


def test_siem_batch_append_single_fsync(tmp_path, monkeypatch, siem_ctx):
    """append_events_batch writes N events with one file open."""
    engine = siem_ctx["engine"]
    engine.log_path = tmp_path / "batch.log"  # keep it off the real stream file
    events = [
        {"ts": time.time(), "event": "HEARTBEAT", "msg": f"beat {i}"}
        for i in range(50)
    ]
    n = engine.append_events_batch(events)
    assert n == 50
    assert engine.append_events_batch([]) == 0
    content = engine.log_path.read_text(encoding="utf-8")
    assert content.count("HEARTBEAT") == 50
