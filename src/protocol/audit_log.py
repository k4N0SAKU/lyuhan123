"""SM3 哈希链审计日志接口（docs/01 8.6 节；F5 审计防篡改的实现载体，P4 填充）。

链式结构：entry_i.hash = SM3(entry_{i-1}.hash + canonical(entry_i))
验证：重算全链比对；改动任一条目 -> verify_chain() 返回 False（F5）。
"""
from __future__ import annotations

from dataclasses import dataclass, field

ZERO32 = bytes(32)


@dataclass
class AuditEvent:
    """审计事件（canonical 编码后入链；禁止记录密钥材料明文）。"""

    seq: int = 0                             # 链内单调序号
    ts_ms: int = 0                           # UTC 毫秒
    actor: str = ""                          # "P0" / "P1" / "P2" / "system"
    event: str = ""                          # 事件类型（如 AUTH_OK / KEY_ROTATED / DESTROYED）
    detail: dict = field(default_factory=dict)
    prev_hash: bytes = ZERO32
    hash: bytes = ZERO32


class AuditLog:
    def append(self, actor: str, event: str, detail: dict | None = None) -> AuditEvent:
        """追加事件并接入哈希链（canonical 序列化 -> SM3）。"""
        raise NotImplementedError("P4 实现")

    def verify_chain(self) -> bool:
        """全链重算校验；任一条目被改 -> False（F5 审计防篡改测试）。"""
        raise NotImplementedError("P4 实现")

    def export_json(self) -> str:
        raise NotImplementedError("P4 实现")
