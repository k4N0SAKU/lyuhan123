"""会话与传输通道接口（docs/01 §4 时序与 §2 拓扑的实现载体，P4 填充实现）。"""
from __future__ import annotations

import enum

from src.common.netmeter import NetworkMeter
from src.protocol.messages import MessageEnvelope


class SessionState(enum.IntEnum):
    """会话状态机（docs/01 §8.1 状态转换表；非法转换必须拒绝并审计）。"""

    IDLE = 0            # 已建连，未认证
    NEGOTIATED = 1      # SM2 双向认证 + 密钥协商完成，通道密钥已派生
    ACTIVE = 2          # 正常业务收发
    ROTATING = 3        # ratchet 轮换进行中（双方向独立计数）
    DESTROYED = 4       # 密钥已覆写销毁（终态，禁止复用）
    ERROR = 5           # 可恢复错误计数超限 / 不可恢复错误


class SecureChannel:
    """SM4-GCM 加密通道（每方向独立密钥 + 序列号 + 时间戳防重放）。

    实现要点（P4）：
    - 发送封装层必须经 NetworkMeter 统一字节计数（陷阱 5，含协议头）；
    - 收到 seq 回退/重复 → ERR_SEQ_REPLAY；|Δt| > 30s → ERR_TS_EXPIRED；
    - GCM 校验失败 → ERR_MAC_INVALID 并写审计告警（F4）。
    """

    def __init__(self, meter: NetworkMeter | None = None) -> None:
        self.meter = meter if meter is not None else NetworkMeter()

    def establish(self, transport_sock, peer_static_pub: bytes) -> None:
        """SM2 双向认证 + SM2DH 协商 → 派生双方向 SM4-GCM 密钥（§8.2）。"""
        raise NotImplementedError("P4 实现（F3）")

    def send_message(self, envelope: MessageEnvelope) -> None:
        raise NotImplementedError("P4 实现")

    def recv_message(self, timeout_s: float = 30.0) -> MessageEnvelope:
        raise NotImplementedError("P4 实现（超时 → ERR_TIMEOUT，§4.3）")

    def current_seq(self, direction: str) -> int:
        """direction: 'send' | 'recv'；用于重放窗口检查的测试观测点。"""
        raise NotImplementedError("P4 实现")


class Session:
    """一次端到端推理会话的生命周期容器（状态机守卫，F5）。"""

    def __init__(self, session_id: bytes, role: int) -> None:
        self.session_id = session_id
        self.role = role
        self.state = SessionState.IDLE

    def transition(self, target: SessionState) -> None:
        """状态转换守卫：合法转换表见 docs/01 §8.1；非法转换抛 StateError 并审计。"""
        raise NotImplementedError("P4 实现（F5）")

    def transcript_hash(self) -> bytes:
        """SM3 消息头哈希链 H_i = SM3(H_{i-1} ‖ msg_header)，ratchet 输入之一。"""
        raise NotImplementedError("P4 实现")
