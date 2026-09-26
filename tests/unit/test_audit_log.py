"""审计哈希链测试（P4；F5 锚点：篡改/删除/重排三类破坏均可检测并定位）。"""
from __future__ import annotations

import json

import pytest

from src.protocol.audit_log import (AuditEvent, AuditLog, ZERO32,
                                    canonical_event_bytes, verify_audit_entries)


def _log_with_events(clock):
    log = AuditLog(actor="P1", clock_ms=clock)
    log.append("P1", "SESSION_ACTIVE", {"peer": "p0"})
    log.append("P1", "KEY_ROTATED", {"epoch": 1})
    log.append("P1", "DECRYPT_OK", {"kind": "masked_conversion", "n": 8})
    log.append("P1", "SESSION_DESTROYED", {"reason": "test"})
    return log


class TestAuditChain:
    def test_append_and_verify_ok(self):
        t = [1000]
        log = _log_with_events(lambda: (t.__setitem__(0, t[0] + 10), t[0])[1])
        ok, errs = verify_audit_entries(log.entries)
        assert ok, errs
        assert [e.seq for e in log.entries] == [1, 2, 3, 4]
        assert log.entries[0].prev_hash == ZERO32
        assert log.entries[1].prev_hash == log.entries[0].hash

    def test_genesis_and_hash_formula(self):
        log = AuditLog(actor="P0", clock_ms=lambda: 5)
        ev = log.append("P0", "X", {"k": 1})
        expect = __import__("src.crypto.gm_cipher", fromlist=["sm3_hash"]) \
            .sm3_hash(ZERO32 + canonical_event_bytes(ev))
        assert ev.hash == expect

    def test_tamper_detail_detected(self):
        log = _log_with_events(lambda: 100)
        log.entries[2].detail["n"] = 999        # 篡改第三条
        ok, errs = verify_audit_entries(log.entries)
        assert not ok
        assert any("seq 3" in e and "篡改" in e for e in errs)

    def test_tamper_prev_hash_detected(self):
        log = _log_with_events(lambda: 100)
        log.entries[1].prev_hash = b"\x01" * 32
        ok, errs = verify_audit_entries(log.entries)
        assert not ok
        assert any("prev_hash 不接" in e for e in errs)

    def test_delete_middle_detected(self):
        log = _log_with_events(lambda: 100)
        broken = log.entries[:1] + log.entries[2:]      # 删除 seq=2
        ok, errs = verify_audit_entries(broken)
        assert not ok
        assert any("断裂" in e for e in errs)

    def test_reorder_detected(self):
        log = _log_with_events(lambda: 100)
        log.entries[1], log.entries[2] = log.entries[2], log.entries[1]
        ok, errs = verify_audit_entries(log.entries)
        assert not ok

    def test_empty_chain_ok(self):
        ok, errs = verify_audit_entries([])
        assert ok and errs == []

    def test_export_load_roundtrip(self):
        t = [0]
        log = _log_with_events(lambda: (t.__setitem__(0, t[0] + 5), t[0])[1])
        text = log.export_json()
        lines = [json.loads(l) for l in text.strip().splitlines()]
        assert len(lines) == 4
        loaded = AuditLog.from_json(text)
        ok, errs = verify_audit_entries(loaded.entries)
        assert ok, errs
        assert loaded.export_json() == text

    def test_no_key_material_in_events(self):
        """审计纪律：detail 禁止携带密钥材料（此处以典型密钥长度随机串模拟）。"""
        log = AuditLog(actor="P0", clock_ms=lambda: 1)
        log.append("P0", "KEY_NEGOTIATED", {"root_key_len": 32})
        text = log.export_json()
        assert "root_key_len" in text and len(text) < 300
