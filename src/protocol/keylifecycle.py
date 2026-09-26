"""密钥全生命周期管理接口（docs/01 §8；F5/F6 的实现载体，P4 填充）。

ratchet 规则（docs/01 §8.3）：
    K_{i+1} = SM3(K_i ‖ H_transcript_i)      双方向独立密钥链
    H_transcript_i = SM3(H_{i-1} ‖ msg_header_i)   会话消息头哈希链
前向安全论证：SM3 单向性 ⇒ 攻破 K_{i+1} 不可恢复 K_i；销毁即覆写（S3）。
"""
from __future__ import annotations

import enum

RATCHET_RULE = "K_{i+1} = SM3(K_i || H_transcript_i)"
TRANSCRIPT_RULE = "H_i = SM3(H_{i-1} || msg_header_i)"
ROTATE_INTERVAL_ROUNDS = 64      # 每 64 条业务消息触发一次 ratchet（可配置）


class KeyLifecycleState(enum.IntEnum):
    """密钥生命周期状态（与 SessionState 分离但联动守卫）。"""

    IDLE = 0
    NEGOTIATED = 1        # 根会话密钥已派生，通道密钥未启用
    ACTIVE = 2            # 通道密钥使用中
    ROTATING = 3          # 轮换事务进行中（新旧密钥并存窗口）
    DESTROYED = 4         # 已覆写销毁（终态）


class KeyManager:
    """会话密钥全生命周期：协商 → 派生 → ratchet 轮换 → 覆写销毁。

    实现纪律（S3）：随机数一律 os.urandom/secrets；密钥以 bytearray 驻留，
    销毁 = 显式清零 + 状态置 DESTROYED + 审计事件；禁止硬编码任何密钥。
    """

    def __init__(self) -> None:
        self.state = KeyLifecycleState.IDLE
        self.epoch = 0

    def negotiate_root(self, transcript: bytes) -> None:
        """SM2DH 协商 → SM3-KDF 派生根会话密钥（状态 IDLE→NEGOTIATED）。"""
        raise NotImplementedError("P4 实现（F5）")

    def derive_channel_keys(self, session_id: bytes) -> None:
        """根密钥 → 双方向 SM4-GCM 通道密钥（NEGOTIATED→ACTIVE）。"""
        raise NotImplementedError("P4 实现")

    def ratchet(self, transcript_hash: bytes) -> None:
        """K_{i+1} = SM3(K_i ‖ H_i)（ACTIVE→ROTATING→ACTIVE；旧密钥立即覆写）。"""
        raise NotImplementedError("P4 实现（F5/F6：销毁后旧密钥必须解密失败）")

    def destroy(self, reason: str) -> None:
        """任意状态 → DESTROYED：覆写全部密钥材料并写审计（终态不可逆）。"""
        raise NotImplementedError("P4 实现")

    def audit_state(self) -> dict:
        """供审计日志记录的密钥状态快照（不含密钥材料本身）。"""
        raise NotImplementedError("P4 实现")
