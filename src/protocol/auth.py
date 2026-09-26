"""SM2 双向身份认证接口（docs/01 §4.1 / §8.2；F3 的实现载体，P4 填充）。"""
from __future__ import annotations

from dataclasses import dataclass

from src.protocol.messages import (AuthChallengePayload, AuthResponsePayload,
                                   CertExchangePayload)


@dataclass
class NodeIdentity:
    """演示级结构化签名证书对应的节点身份（S4：商用需替换为 GM X.509 证书链）。"""

    node_id: str = ""
    role: int = 0
    static_pub: bytes = b""                  # SM2 静态公钥（65B 未压缩）
    cert: CertExchangePayload | None = None


class Authenticator:
    """挑战-应答双向认证（防中间人：证书绑定 + 随机挑战 + transcript 签名）。

    拒绝矩阵（F3 测试用例）：
    - 无证书 / CA 签名不匹配 → CERT_INVALID
    - not_after < now → CERT_EXPIRED
    - 签名验证失败 / 挑战 nonce 不回填 → AUTH_FAILURE
    """

    def __init__(self, ca_pub: bytes, local_identity: NodeIdentity) -> None:
        self.ca_pub = ca_pub
        self.local = local_identity

    def verify_cert(self, cert: CertExchangePayload, now_ms: int) -> None:
        """校验 CA 签名与有效期；失败抛 AuthError(ErrorCode.CERT_*)。"""
        raise NotImplementedError("P4 实现（F3）")

    def issue_challenge(self) -> AuthChallengePayload:
        """os.urandom 生成挑战（S3：随机数纪律）。"""
        raise NotImplementedError("P4 实现")

    def respond(self, challenge: AuthChallengePayload) -> AuthResponsePayload:
        raise NotImplementedError("P4 实现")

    def verify_response(self, response: AuthResponsePayload,
                        expected_nonce: bytes, peer_cert: CertExchangePayload) -> None:
        raise NotImplementedError("P4 实现")
