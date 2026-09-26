"""规格锚定测试（P2 更新）：协议层骨架仍 NotImplementedError；密码层为 P2
实现，参数锚定断言改为 P2 实测修订值（docs/01 §5.3 表 7 修订版）。

本测试是规格的"可执行锚点"——规格文档修订而未同步代码时在此失败。
"""
from __future__ import annotations

import dataclasses
import inspect

import pytest

from src.crypto.ckks_ops import (PARAMS_DEEP19, PARAMS_MODE_A, PARAMS_MODE_B,
                                 CKKSContext)
from src.model.ops.packing import DEFAULT_SPEC, PackingScheme, PackingSpec
from src.model.ops.nonlinear_approx import (EXP_SPEC, GELU_SPEC, INV_SQRT_SPEC,
                                            INV_SPEC, MAX_SPEC)
from src.protocol import messages as M
from src.protocol.audit_log import AuditLog
from src.protocol.auth import Authenticator, NodeIdentity
from src.protocol.keylifecycle import ROTATE_INTERVAL_ROUNDS, KeyLifecycleState
from src.protocol.session import SecureChannel, Session, SessionState


# ---- 枚举与状态机完整性（P4 实现，锚点不变）----

class TestEnums:
    def test_session_states(self):
        assert {s.name for s in SessionState} == {
            "IDLE", "NEGOTIATED", "ACTIVE", "ROTATING", "DESTROYED", "ERROR"}
        assert {s.name for s in KeyLifecycleState} == {
            "IDLE", "NEGOTIATED", "ACTIVE", "ROTATING", "DESTROYED"}

    def test_msg_types_structure(self):
        ctrl = {m for m in M.MsgType if 0x0100 <= m.value < 0x0200}
        data = {m for m in M.MsgType if 0x0200 <= m.value < 0x0300}
        err = {m for m in M.MsgType if m.value >= 0x0300}
        assert {"HELLO", "AUTH_CHALLENGE", "AUTH_RESPONSE", "KEY_NEGOTIATE",
                "KEY_ROTATE", "KEY_DESTROY"} <= {m.name for m in ctrl}
        assert {"INFER_REQUEST", "INFER_RESULT", "THRESHOLD_PARTIAL",
                "CONVERT_MASKED_CT", "RECRYPT_SHARES"} <= {m.name for m in data}
        assert err == {M.MsgType.ERR}

    def test_error_codes_cover_five_attacks(self):
        codes = {e.name for e in M.ErrorCode}
        assert {"CERT_INVALID", "CERT_EXPIRED", "AUTH_FAILURE",
                "MAC_INVALID", "SEQ_REPLAY", "TS_EXPIRED",
                "DECRYPT_FAILURE"} <= codes

    def test_ratchet_constants_documented(self):
        from src.protocol import keylifecycle as K
        assert "SM3" in K.RATCHET_RULE and "H_transcript" in K.RATCHET_RULE
        assert ROTATE_INTERVAL_ROUNDS == 64


# ---- 消息字段级定义（docs/01 §3 字段表的代码映射）----

class TestMessages:
    def test_common_header_field_widths_documented(self):
        h = M.CommonHeader(msg_type=int(M.MsgType.HELLO),
                           session_id=b"\x01" * M.SESSION_ID_LEN, seq=7,
                           timestamp_ms=1_700_000_000_000, payload_len=10)
        assert h.version == M.PROTOCOL_VERSION == 1
        assert len(h.session_id) == 16

    def test_envelope_and_payload_registry(self):
        env = M.MessageEnvelope(
            header=M.CommonHeader(msg_type=int(M.MsgType.AUTH_RESPONSE)),
            payload_type="AuthResponsePayload",
            payload=dataclasses.asdict(M.AuthResponsePayload()),
            auth_kind=int(M.AuthKind.SM2_SIG))
        assert env.payload_type in M.PAYLOAD_REGISTRY
        assert M.PAYLOAD_REGISTRY["RecryptSharesPayload"] is M.RecryptSharesPayload
        recrypt = M.RecryptSharesPayload()
        assert recrypt.enc_masked_share is not None and recrypt.enc_mask is not None

    def test_convert_payload_carries_mask_semantics(self):
        conv = M.ConvertMaskedCtPayload()
        assert hasattr(conv, "masked_ct") and hasattr(conv, "level")
        rec = M.RecryptSharesPayload()
        assert hasattr(rec, "enc_masked_share") and hasattr(rec, "enc_mask")

    def test_all_payloads_are_dataclasses(self):
        for name, cls in M.PAYLOAD_REGISTRY.items():
            assert dataclasses.is_dataclass(cls), name
            dataclasses.asdict(cls())


# ---- 协议层骨架 NotImplementedError（P4 实现；P2 已实现密码层，不再断言）----

NOT_IMPL_TARGETS = [
    ("SecureChannel", lambda: SecureChannel(),
     ["establish", "send_message", "recv_message", "current_seq"]),
    ("Session", lambda: Session(b"\x00" * 16, role=1),
     ["transition", "transcript_hash"]),
    ("Authenticator", lambda: Authenticator(b"\x00" * 65, NodeIdentity()),
     ["verify_cert", "issue_challenge", "respond", "verify_response"]),
    ("KeyManager", lambda: __import__("src.protocol.keylifecycle",
                                      fromlist=["KeyManager"]).KeyManager(),
     ["negotiate_root", "derive_channel_keys", "ratchet", "destroy",
      "audit_state"]),
    ("AuditLog", lambda: AuditLog(), ["append", "verify_chain", "export_json"]),
]


def _call_with_dummies(fn, *args):
    sig = inspect.signature(fn)
    n_required = len(args) if args else sum(
        1 for p in sig.parameters.values()
        if p.default is inspect.Parameter.empty
        and p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD))
    try:
        fn(*([None] * n_required if not args else list(args)))
    except NotImplementedError:
        return
    except Exception as exc:
        raise AssertionError(f"接口抛出了非 NotImplementedError 异常: {exc!r}")
    raise AssertionError("接口在实现阶段到来前不应有实现逻辑")


class TestProtocolSkeletonNotImplemented:
    @pytest.mark.parametrize("label,factory,methods", NOT_IMPL_TARGETS,
                             ids=[t[0] for t in NOT_IMPL_TARGETS])
    def test_methods_raise_not_implemented(self, label, factory, methods):
        try:
            obj = factory()
        except NotImplementedError:
            return  # 构造即未实现（CKKSContext）
        for name in methods:
            _call_with_dummies(getattr(obj, name))

    def test_serialize_envelope_not_implemented(self):
        _call_with_dummies(M.serialize_envelope, M.MessageEnvelope())


# ---- CKKS 参数表锚定（docs/01 §5.3 表 7，P2 实测修订值）----

class TestCKKSParamsSpec:
    def test_mode_b_segment(self):
        """P2 探针实测：本栈 SEAL 校验上限 2^15 → mode-b 主线 16384 槽。"""
        p = PARAMS_MODE_B
        assert p.poly_modulus_degree == 1 << 15
        assert p.coeff_mod_bit_sizes == (60, 40, 40, 60)
        assert len(p.coeff_mod_bit_sizes) - 2 == 2      # 段内最深两个线性层
        assert p.scale_log2 == 40
        assert sum(p.coeff_mod_bit_sizes) == 200
        assert p.slots == 1 << 14

    def test_deep19_regression_chain(self):
        """本栈最大深度链：19 层 = 880bit ≤ 881（128-bit classical@2^15）。"""
        p = PARAMS_DEEP19
        assert p.poly_modulus_degree == 1 << 15
        assert len(p.coeff_mod_bit_sizes) - 2 == 19
        assert sum(p.coeff_mod_bit_sizes) == 880

    def test_mode_a_theoretical(self):
        """评审 A/探针结论：2^17 被本栈拒绝，mode-a 仅保留理论参数。"""
        assert PARAMS_MODE_A.poly_modulus_degree == 1 << 17
        assert "不可实例化" in PARAMS_MODE_A.name or "OPENFHE" in PARAMS_MODE_A.name
        assert len(PARAMS_MODE_A.coeff_mod_bit_sizes) - 2 == 84

    def test_mode_b_actually_instantiates(self):
        ctx = CKKSContext(PARAMS_MODE_B, public_only=True)
        assert ctx.slot_count == 1 << 14

    def test_mode_a_fails_to_instantiate(self):
        with pytest.raises(ValueError):
            CKKSContext(PARAMS_MODE_A)


# ---- 打包与近似规格锚定（docs/01 §6/§7，P2 修订值）----

class TestOpsSpec:
    def test_packing_default_spec(self):
        assert DEFAULT_SPEC.block_elems == 768
        assert DEFAULT_SPEC.gap == 2
        assert DEFAULT_SPEC.slots == 1 << 14
        assert DEFAULT_SPEC.blocks_per_ct == 10
        assert int(PackingScheme.DIAGONAL_BSGS) == 1

    def test_poly_specs_shapes(self):
        """P2-R1 B1 实测校准后的规格锚定（P1 理论界作废，见 minimax.py）。"""
        assert GELU_SPEC.name == "gelu_deg15" and len(GELU_SPEC.coeffs) == 16
        assert GELU_SPEC.depth == 4 and GELU_SPEC.num_mults == 13
        assert GELU_SPEC.max_error <= 5.5e-3            # 实测 5.067e-3（P1 目标 5e-3 的 +1.3%，域内最优）
        assert EXP_SPEC.name == "exp_deg9_onesided"
        assert EXP_SPEC.domain == (-10.0, 0.0)           # max 减法后的单侧域
        assert EXP_SPEC.depth == 4 and EXP_SPEC.num_mults == 4
        assert EXP_SPEC.max_error <= 3e-3                # 实测 6.8e-5
        assert MAX_SPEC.depth == 1 and MAX_SPEC.num_mults == 2
        assert INV_SPEC.extra["newton_rounds"] == 7      # P1 的 3-4 轮不收敛
        assert INV_SQRT_SPEC.extra["newton_rounds"] == 3
        assert INV_SQRT_SPEC.max_error < 0.2

    def test_linear_signature_takes_spec(self):
        from src.model.ops.packing import linear_cipher
        sig = inspect.signature(linear_cipher)
        assert "spec" in sig.parameters and "diagonals" in sig.parameters
