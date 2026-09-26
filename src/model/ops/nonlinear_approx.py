"""非线性近似与 MPC 求值接口（docs/01 §7 的代码载体；P3 填充实现）。

误差合成纪律（P1 陷阱 1）：任何非线性算子的误差界 = 三项合成
    ε_total ≈ sqrt(ε_poly² + ε_ckks² + ε_quant²)
    - ε_poly：minimax/Chebyshev 多项式误差（本模块的 max_error 字段，Remez 实测）
    - ε_ckks：当前 level 的 CKKS 解密噪声（§5.4 预算，P2 实测为绝对量口径）
    - ε_quant：定点量化误差（P0 实测：激活 Q16 → 相对 ~7.6e-6）
P3 实现必须在 eval_quantize / 噪声回归测试中报告合成误差。
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class PolyApprox:
    """近似多项式规格（系数由 minimax.py 的 Remez 生成并入库 data/minimax/）。"""

    name: str = ""
    coeffs: tuple = ()                # 升幂系数（Remez 实测生成）
    domain: tuple = (0.0, 0.0)        # 有效输入区间（超界行为：分段/截断，见文档）
    depth: int = 0                    # Paterson-Stockmeyer 乘法深度
    num_mults: int = 0
    max_error: float = 0.0            # ε_poly（Remez 实测值）
    extra: dict = field(default_factory=dict)   # 附加参数（如 newton_rounds）


def _load_coeffs(name: str) -> tuple:
    """从入库 JSON 取实测系数（文件缺失时返回空元组，由测试兜底）。"""
    try:
        from src.model.ops.minimax import load_coeffs
        return tuple(load_coeffs(name)["coeffs"])
    except (FileNotFoundError, OSError, KeyError):
        return ()


# 规格（P2-R1 B1 项实测校准：系数由 Remez 生成入库；P1 §7 的理论误差界系统性
# 低估 3~4 个数量级，下表全部为 Remez 实测值——偏差分析见 P2 工作记录）
GELU_SPEC = PolyApprox(name="gelu_deg15", coeffs=_load_coeffs("gelu_deg15"),
                       domain=(-6.0, 6.0), depth=4,
                       num_mults=13, max_error=5.067e-3)      # P1 声称 deg5≤5e-3，实测 0.231 不可用
GELU_LOW_COST_SPEC = PolyApprox(name="gelu_deg9", coeffs=_load_coeffs("gelu_deg9"),
                                domain=(-6.0, 6.0), depth=4,
                                num_mults=6, max_error=5.498e-2)  # 精度换门数变体（P3 A/B）
# exp：max 减法后为**单侧域 [-10,0]**（修正 P1 双重错误：[-8,8] 双侧域 +
# score std 算术错）；deg9 @[-10,0] 实测 6.8e-5，深度 4 / 乘 4 不变
EXP_SPEC = PolyApprox(name="exp_deg9_onesided", coeffs=_load_coeffs("exp_deg9_onesided"),
                      domain=(-10.0, 0.0), depth=4,
                      num_mults=4, max_error=6.778e-5)
# max 比较多项式（模式 A/B 同构；MPC 域每 pairwise = 2 次 Beaver 乘，评审 D 项）
MAX_SPEC = PolyApprox(name="max_deg2_pairwise", domain=(-16.0, 16.0), depth=1,
                      num_mults=2, max_error=5e-2)      # P2 实测校准
# inv 初值：deg2 @[1,64] 相对误差实测 0.77 → **Newton 7 轮**（P1 声称 3-4 轮
# 不足：0.77→0.59→0.35→0.12→0.015→2.2e-4→5e-8）
INV_SPEC = PolyApprox(name="inv_init_deg2", coeffs=_load_coeffs("inv_init_deg2"),
                      domain=(1.0, 64.0), depth=1,
                      num_mults=1, max_error=7.7e-1, extra={"newton_rounds": 7})
# inv-sqrt 初值：升 deg4（P1 deg2 实测 0.285）→ 3 轮 Newton（保持 P1 轮数）
INV_SQRT_SPEC = PolyApprox(name="invsqrt_init_deg4", coeffs=_load_coeffs("invsqrt_init_deg4"),
                           domain=(0.5, 16.0), depth=1,
                           num_mults=1, max_error=1.148e-1,
                           extra={"newton_rounds": 3})


def gelu_poly_approx(ctx, ciphertext):
    """GELU：分段 [-6,6] 多项式 + 越界常量段（P2-R1 校准：deg15/深度4/乘13）。"""
    raise NotImplementedError("P3 实现")


def softmax_mpc(p1, p2, gate_budget: int = 0):
    """模式 B：注意力 softmax 在 MPC 域求值（分享态；Beaver 乘法 + Newton 逆）。

    gate_budget：预计 Beaver 门数（通信量估算核对，docs/01 §7.5 表 9）。"""
    raise NotImplementedError("P3 实现")


def layernorm_mpc(p1, p2, d_model: int = 768, gate_budget: int = 0):
    """模式 B：LayerNorm 在 MPC 域（E[x²]−E[x]²、inv-sqrt 3 轮 Newton）。"""
    raise NotImplementedError("P3 实现")


def softmax_poly_approx_mode_a(ctx, ciphertext, num_tokens: int):
    """模式 A：全密文 softmax（max 级联 + exp + inv，depth ~25）。"""
    raise NotImplementedError("P3 实现（模式 A 演示配置，docs/01 §5.2 表 4）")
