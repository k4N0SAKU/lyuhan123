"""消息格式定义（P1 规格的权威代码载体；docs/01 §3 与本模块字段一一对应）。

P1 阶段约束：本模块只含 dataclass / 枚举 / 常量，任何方法实现一律
``raise NotImplementedError``，由 P3（数据面）/P4（控制面）阶段填充。

字段宽度约定（docs/01 §3.1）：
- version: u8；msg_type: u16；seq: u64（会话内每方向单调递增，从 0 起）；
- timestamp_ms: u64（发送方 UTC 毫秒）；session_id: 16 字节随机会话标识。
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field

PROTOCOL_VERSION = 1

# 端口约定（docs/01 §2；IANA 未注册段 17400-17449）
PORT_KEYNODE = 17401     # P1 密钥服务节点（认证 + 密钥管理 + 门限解密参与）
PORT_INFERnode = 17402   # P2 推理服务节点
PORT_KEYNODE_INTERNAL = 17403  # P1 ↔ P2 内部通道（MPC 交互/审计副本）

SESSION_ID_LEN = 16
NONCE_LEN = 32


class MsgType(enum.IntEnum):
    """消息类型。0x01xx 控制面（认证/密钥），0x02xx 数据面（推理），0x03xx 错误。"""

    # ---- 控制面：认证 ----
    HELLO = 0x0101                  # 节点握手：身份声明 + 随机数
    CERT_EXCHANGE = 0x0102          # 证书交换（结构化签名对象，S4 演示级）
    AUTH_CHALLENGE = 0x0103         # 挑战
    AUTH_RESPONSE = 0x0104          # 应答（SM2 签名 over 会话杂凑）
    AUTH_RESULT = 0x0105            # 双向认证结论
    # ---- 控制面：密钥管理 ----
    KEY_NEGOTIATE = 0x0111          # SM2 密钥协商（临时公钥 + 签名）
    KEY_ACK = 0x0112                # 协商确认
    KEY_ROTATE = 0x0113             # ratchet 轮换通知（epoch + transcript hash）
    KEY_DESTROY = 0x0114            # 销毁指令
    HEARTBEAT = 0x0115              # 存活探测
    # ---- 数据面：模式 A ----
    INFER_REQUEST = 0x0201          # P0→P2：CKKS 密文输入 + 打包元数据
    INFER_RESULT = 0x0202           # P2→P0：密文 logits + P2 签名
    THRESHOLD_PARTIAL = 0x0203      # 门限部分份额（扩展方向保留；主线 D5 修订为
                                    # P0 掩码解密，不使用，见 docs/01 §8.4）
    # ---- 数据面：模式 B 密文↔分享转换（docs/01 §7.4）----
    CONVERT_MASKED_CT = 0x0211      # P2→P0：ct(x)+Enc(r)，P0 单钥解密（D5 修订）
    CONVERT_SHARE = 0x0212          # P0→P1：掩码解密值 y₁=x+r 分发；P2 本地持 −r
    MPC_OPEN = 0x0221               # Beaver 乘法 open（d 或 e 的分享）
    MPC_RESULT_SHARE = 0x0222       # MPC 结果分享
    RECRYPT_SHARES = 0x0231         # 分享→密文：Enc(a1+s) 与 Enc(s)
    # ---- 错误 ----
    ERR = 0x0300                    # 错误通告（载荷 ErrorPayload）


class ErrorCode(enum.IntEnum):
    """错误码（docs/01 §3.4；对应 F3~F6 攻击测试的拒绝原因）。"""

    AUTH_FAILURE = 1            # 挑战应答失败
    CERT_INVALID = 2            # 无证书/伪造证书（F3）
    CERT_EXPIRED = 3            # 过期证书（F3）
    MAC_INVALID = 4             # GCM 校验失败/消息被篡改（F4）
    SEQ_REPLAY = 5              # 序列号回退/重复 → 重放（F6）
    TS_EXPIRED = 6              # 时间戳超出容差窗（F6）
    DECRYPT_FAILURE = 7         # 门限解密失败（份额不匹配/销毁后解密）
    STATE_ILLEGAL = 8           # 状态机非法转换
    TIMEOUT = 9                 # 交互超时
    INTERNAL = 10


class AuthKind(enum.IntEnum):
    """envelope 的认证方式：传输层 AEAD 标签 或 应用层 SM2 签名。"""

    NONE = 0        # 仅允许在 HELLO 之前不存在（实际不允许 NONE 用于业务消息）
    AEAD_TAG = 1    # SM4-GCM tag（通道密钥保护，P4 实现）
    SM2_SIG = 2     # SM2 签名（关键控制面消息：认证/轮换/销毁/结果）


@dataclass
class CommonHeader:
    """所有消息的公共头（docs/01 §3.1 字段表）。"""

    version: int = PROTOCOL_VERSION          # u8
    msg_type: int = 0                        # u16，取 MsgType 值
    session_id: bytes = b"\x00" * SESSION_ID_LEN   # 16B，随机会话标识
    seq: int = 0                             # u64，单调递增
    timestamp_ms: int = 0                    # u64，发送方 UTC 毫秒
    payload_len: int = 0                     # u32，载荷字节数


@dataclass
class MessageEnvelope:
    """传输信封：公共头 + 载荷 + 认证字段。

    完整性/机密性分层（docs/01 §2.3）：数据面消息在 SM4-GCM 通道内传输
    （AEAD_TAG 覆盖 header+payload）；关键控制面消息附加 SM2_SIG。
    """

    header: CommonHeader = field(default_factory=CommonHeader)
    payload_type: str = ""                   # 载荷 dataclass 类名
    payload: dict = field(default_factory=dict)    # 载荷的规范化字典
    auth_kind: int = AuthKind.AEAD_TAG.value
    auth_value: bytes = b""                  # tag / 签名


# ---- 控制面载荷 ----

@dataclass
class HelloPayload:
    node_id: str = ""
    role: int = 0                            # 0=P0 客户端, 1=P1 密钥节点, 2=P2 推理节点
    nonce: bytes = b"\x00" * NONCE_LEN
    supported_versions: tuple = (PROTOCOL_VERSION,)


@dataclass
class CertExchangePayload:
    """演示级结构化签名证书（S4）：{身份, 公钥, 有效期, CA 签名}。"""

    subject_id: str = ""
    subject_pub: bytes = b""                 # SM2 公钥（未压缩 65B）
    not_before_ms: int = 0
    not_after_ms: int = 0
    ca_sig: bytes = b""                      # CA 对前述字段的 SM2 签名


@dataclass
class AuthChallengePayload:
    challenge_nonce: bytes = b"\x00" * NONCE_LEN
    expires_ms: int = 0                      # 挑战有效期（防拖延重放）


@dataclass
class AuthResponsePayload:
    challenge_nonce: bytes = b"\x00" * NONCE_LEN
    responder_nonce: bytes = b"\x00" * NONCE_LEN
    sig: bytes = b""                         # SM2 签名 over SM3(挑战‖应答者随机数‖会话上下文)


@dataclass
class AuthResultPayload:
    ok: bool = False
    error_code: int = 0                      # 失败时取 ErrorCode
    sig: bytes = b""


@dataclass
class KeyNegotiatePayload:
    """SM2 密钥协商（SM2DH）消息；KDF 用 SM3（docs/01 §8.2）。"""

    ephemeral_pub: bytes = b""               # SM2 临时公钥
    epoch: int = 0                           # 目标会话纪元
    sig: bytes = b""                         # 对 ephemeral_pub‖epoch‖transcript_hash 的签名


@dataclass
class KeyAckPayload:
    epoch: int = 0
    confirm_tag: bytes = b"\x00" * 16        # SM3-KDF 派生确认值（密钥一致性检查）


@dataclass
class KeyRotatePayload:
    epoch_new: int = 0
    transcript_hash: bytes = b"\x00" * 32    # SM3 消息头哈希链值 H_i
    sig: bytes = b""


@dataclass
class KeyDestroyPayload:
    epoch: int = 0
    reason: str = "session_end"
    sig: bytes = b""


# ---- 数据面载荷 ----

@dataclass
class InferRequestPayload:
    """P0→P2 密文推理请求（模式 A/B 通用）。"""

    request_id: bytes = b"\x00" * 16
    mode: int = 0                            # 0=模式A 全密文, 1=模式B 混合
    ciphertext: bytes = b""                  # 序列化 CKKS 密文（嵌入层输出）
    cipher_meta: dict = field(default_factory=dict)   # {level, scale_log2, slots, packing}
    model_id: str = ""                       # "gpt2" / "bert-base-chinese-sentiment"
    max_new_tokens: int = 0                  # 仅 GPT-2


@dataclass
class InferResultPayload:
    """P2→P0 密文结果；仅 P0 持钥且最终输出属其角色（t=1, D5 修订）。"""

    request_id: bytes = b"\x00" * 16
    ciphertext: bytes = b""                  # logits（分类）/单步 logits（生成）
    cipher_meta: dict = field(default_factory=dict)
    sig: bytes = b""                         # P2 对 SM3(ciphertext‖meta) 的签名


@dataclass
class ThresholdPartialPayload:
    """门限解密部分份额（扩展方向保留，主线不使用——docs/01 §8.4 D5 修订）。

    主线中 P0 单钥解密掩码值并分发 y₁；本载荷仅在真门限扩展路线启用。"""

    request_id: bytes = b"\x00" * 16
    holder: int = 0                          # 0=P0, 1=P1
    partial: bytes = b""                     # 部分解密值
    commitment: bytes = b"\x00" * 32         # SM3(partial)，防份额替换


# ---- 模式 B：密文↔分享转换（docs/01 §7.4，再随机化为评审重点）----

@dataclass
class ConvertMaskedCtPayload:
    """P2 请求把密文 x 转为加法分享：ct′ = ct(x)+Enc_pk(r)，r 为 P2 fresh 采样。

    发送方向：P2→P0（D5 修订：P0 单钥掩码解密）；P0 只见 x+r（OTP）。"""

    request_id: bytes = b"\x00" * 16
    masked_ct: bytes = b""                   # ct(x) ⊕ Enc_pk(r)（同态加法）
    level: int = 0
    seq_in_layer: int = 0


@dataclass
class ConvertSharePayload:
    """掩码解密值的分发视图：P0 解密 y=x+r 后把 y₁=y 分发 P1；P2 本地持 −r。"""

    request_id: bytes = b"\x00" * 16
    share: bytes = b""                       # 定点编码的 (x+r)
    holder: int = 0


@dataclass
class MpcOpenPayload:
    """Beaver 乘法 open 阶段：一方公开 d = x - a（或 e = y - b）的分享。"""

    request_id: bytes = b"\x00" * 16
    gate_id: int = 0                         # 乘法门编号（匹配离线三元组）
    opened: bytes = b""                      # 定点分享值


@dataclass
class MpcResultSharePayload:
    request_id: bytes = b"\x00" * 16
    gate_id: int = 0
    share: bytes = b""


@dataclass
class RecryptSharesPayload:
    """分享→密文（再随机化出口）：P1 发送 Enc_pk(a1+s) 与 Enc_pk(s)，s 为 P1
    fresh 采样；P2 在密文域相减得 Enc(a1)，加自身分享 a2 得 ct(结果)。
    P2 从不获得 s 的明文，P1 从不获得 a2。"""

    request_id: bytes = b"\x00" * 16
    enc_masked_share: bytes = b""            # Enc_pk(a1 + s)，fresh 顶层密文
    enc_mask: bytes = b""                    # Enc_pk(s)
    level_target: int = 0


@dataclass
class ErrorPayload:
    error_code: int = 0                      # ErrorCode
    failed_seq: int = 0                      # 触发错误的消息 seq
    detail: str = ""


PAYLOAD_REGISTRY = {
    "HelloPayload": HelloPayload, "CertExchangePayload": CertExchangePayload,
    "AuthChallengePayload": AuthChallengePayload,
    "AuthResponsePayload": AuthResponsePayload,
    "AuthResultPayload": AuthResultPayload,
    "KeyNegotiatePayload": KeyNegotiatePayload, "KeyAckPayload": KeyAckPayload,
    "KeyRotatePayload": KeyRotatePayload, "KeyDestroyPayload": KeyDestroyPayload,
    "InferRequestPayload": InferRequestPayload,
    "InferResultPayload": InferResultPayload,
    "ThresholdPartialPayload": ThresholdPartialPayload,
    "ConvertMaskedCtPayload": ConvertMaskedCtPayload,
    "ConvertSharePayload": ConvertSharePayload,
    "MpcOpenPayload": MpcOpenPayload, "MpcResultSharePayload": MpcResultSharePayload,
    "RecryptSharesPayload": RecryptSharesPayload, "ErrorPayload": ErrorPayload,
}


def serialize_envelope(envelope: MessageEnvelope) -> bytes:
    """规范化序列化（字段序固定，供签名/哈希；docs/01 §3.3）。"""
    raise NotImplementedError("P4 实现（对应 S7：序列化与签名绑定）")


def deserialize_envelope(data: bytes) -> MessageEnvelope:
    raise NotImplementedError("P4 实现")
