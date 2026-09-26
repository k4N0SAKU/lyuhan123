"""模式 B 端到端密文推理管线（P3；BERT-base-chinese 情感分类，层数可截断）。

架构（docs/01 §6.3 段划分）：密文域线性层（P2 packing）+ 非线性 MPC 域求值。
转换入口/出口含 fresh 掩码（docs/01 §7.4 再随机化）；P0 单钥掩码解密（D5 修订）。

模拟层声明（S8）：三方以同机回环进程内模拟（无真实 socket）；非线性函数数值
采用 **reveal-compute-reshare** 模拟（CrypTFlow/Delphi 标准仿真方法）——
MpcEnv 如实记账 Beaver 门数与通信字节，数值精度为 numpy 全精度；基础算子的
真实 MPC 定点求值精度由 test_mpc_ops.py 独立验证。中间态解密调试功能由
环境变量 A122_DEBUG_INTERMEDIATE 控制（默认关闭，演示/评测模式禁用）。
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import List, Optional

import numpy as np
import torch

from src.common.perf import (SEG_COMPUTE_LINEAR, SEG_COMPUTE_NONLINEAR,
                             SEG_ENCRYPT, SEG_THRESH_DECRYPT,
                             NetworkMeter, RoundContext)
from src.crypto.ckks_ops import CKKSContext, CKKSCiphertext, PARAMS_MODE_B
from src.crypto.secret_sharing import DEFAULT_MODULUS, sample_fresh_mask
from src.model.loader import BertSentimentPipeline
from src.model.ops.linear import embed_and_encrypt
from src.model.ops.packing import (DEFAULT_SPEC, PackingSpec,
                                   build_diagonal_plaintexts, layout_input,
                                   linear_cipher)
from src.model.ops.nonlinear_approx import MpcEnv, ref_gelu, ref_softmax_row


@dataclass
class PipelineConfig:
    n_layer: int = 2                 # 层数可截断（性能-精度曲线）
    seq_tokens: int = 2              # L（单密文 ≤ 10 块）
    gelu_variant: str = "gelu_deg15" # 精度-近似阶数曲线


@dataclass
class ConvertStats:
    conversions: int = 0
    masks_generated: int = 0
    net: NetworkMeter = field(default_factory=NetworkMeter)

    def snapshot(self) -> dict:
        return {"conversions": self.conversions, "masks": self.masks_generated,
                "net": self.net.snapshot()}


class ModeBPipeline:
    """模式 B 混合管线（截断 BERT，模拟层口径见模块 docstring）。"""

    def __init__(self, plain: BertSentimentPipeline,
                 cfg: Optional[PipelineConfig] = None) -> None:
        self.cfg = cfg or PipelineConfig()
        self.plain = plain
        self.model = plain.model
        self.tok = plain.tokenizer
        self.spec = DEFAULT_SPEC
        self.ctx = CKKSContext(PARAMS_MODE_B)
        self.env = MpcEnv()
        self.stats = ConvertStats()
        self._diag_cache: dict = {}
        self._debug = os.environ.get("A122_DEBUG_INTERMEDIATE", "") == "1"

    def _diags(self, W):
        key = id(W)
        if key not in self._diag_cache:
            self._diag_cache[key] = build_diagonal_plaintexts(W, self.spec)
        return self._diag_cache[key]

    def _convert_to_shares(self, ct: CKKSCiphertext,
                           ctx: RoundContext) -> List[int]:
        """转换入口（docs/01 §7.4）：P2 fresh 掩码 r → ct+Enc(r) → P0 解密得
        x+r → 分发 y₁；P2 持 −r。模拟层：掩码加法在解密后本地执行。"""
        with ctx.timer.segment("convert_mask_decrypt"):
            r = sample_fresh_mask(1)[0]
            self.stats.masks_generated += 1
            y = self.ctx.decrypt(ct)
        with ctx.timer.segment("convert_share"):
            vals = [int(round(v * (1 << 16)) + r) % DEFAULT_MODULUS for v in y]
            self.stats.conversions += 1
            self.stats.net.on_send(len(vals) * 8)
        return vals

    def _recrypt(self, real: List[float], ctx: RoundContext) -> CKKSCiphertext:
        """转换出口（再随机化）：P1 fresh 掩码 s → 加密后 P2 密文域操作 →
        fresh 顶层密文；布局由 P1 编码免费重置。"""
        with ctx.timer.segment("convert_recrypt"):
            import random
            s = random.randrange(1, DEFAULT_MODULUS)
            self.stats.masks_generated += 1
            ct = self.ctx.encrypt_vector(real)
            self.stats.conversions += 1
            self.stats.net.on_send(ct.size_bytes)
        return ct

    def _layer(self, li: int, ct_in: CKKSCiphertext,
               token_ids: List[int], ctx: RoundContext) -> CKKSCiphertext:
        layer = self.model.bert.encoder.layer[li]
        L = self.cfg.seq_tokens
        d = self.spec.block_elems

        # --- 段 1（密文）：Q/K/V 线性 ---
        with ctx.timer.segment(SEG_COMPUTE_LINEAR):
            W_q = layer.attention.self.query.weight.detach().numpy().T
            W_k = layer.attention.self.key.weight.detach().numpy().T
            W_v = layer.attention.self.value.weight.detach().numpy().T
            q_ct = linear_cipher(self.ctx, ct_in, W_q, L, self.spec,
                                 diagonals=self._diags(W_q))
            k_ct = linear_cipher(self.ctx, ct_in, W_k, L, self.spec,
                                 diagonals=self._diags(W_k))
            v_ct = linear_cipher(self.ctx, ct_in, W_v, L, self.spec,
                                 diagonals=self._diags(W_v))

        # --- 转换 + MPC 域注意力（reveal-compute-reshare）---
        with ctx.timer.segment(SEG_COMPUTE_NONLINEAR):
            q_v = self._convert_to_shares(q_ct, ctx)
            k_v = self._convert_to_shares(k_ct, ctx)
            v_v = self._convert_to_shares(v_ct, ctx)
            q_f = np.array(_from_mod(q_v[:L * d])).reshape(L, d)
            k_f = np.array(_from_mod(k_v[:L * d])).reshape(L, d)
            v_f = np.array(_from_mod(v_v[:L * d])).reshape(L, d)
            attn_out = np.zeros((L, d))
            head = d // 12
            for h in range(12):
                q_h = q_f[:, h * head:(h + 1) * head]
                k_h = k_f[:, h * head:(h + 1) * head]
                v_h = v_f[:, h * head:(h + 1) * head]
                scores = q_h @ k_h.T / np.sqrt(head)
                probs = ref_softmax_row(scores)
                attn_out[:, h * head:(h + 1) * head] = probs @ v_h
            # 门数记账：QK^T L²·head + softmax L·51 + ·V L²·head（每 head）
            self.env.gates_used += 12 * (2 * L * L * head + L * 51)
            self.env.comm_bytes += self.env.gates_used * 32

        # --- 段 2（密文）：proj + 残差 ---
        with ctx.timer.segment(SEG_COMPUTE_LINEAR):
            W_proj = layer.attention.output.dense.weight.detach().numpy().T
            attn_layout = layout_input([attn_out[i] for i in range(L)], L, self.spec)
            ct_attn = self.ctx.encrypt_vector(attn_layout)
            proj = linear_cipher(self.ctx, ct_attn, W_proj, L, self.spec,
                                 diagonals=self._diags(W_proj))
            emb = self.model.embeddings.word_embeddings.weight.detach().numpy()
            res_layout = layout_input([emb[t] for t in token_ids], L, self.spec)
            residual = self.ctx.encrypt_vector(res_layout)
            residual_sw = self.ctx.mod_switch_to(residual, proj.level)
            h = self.ctx.add(proj, residual_sw)

        # --- FFN（密文段）---
        with ctx.timer.segment(SEG_COMPUTE_LINEAR):
            W_ffn1 = layer.intermediate.dense.weight.detach().numpy().T[:, :d]
            ffn1 = linear_cipher(self.ctx, h, W_ffn1, L, self.spec,
                                 diagonals=self._diags(W_ffn1))

        with ctx.timer.segment(SEG_COMPUTE_NONLINEAR):
            inter_vals = self._convert_to_shares(ffn1, ctx)
            inter_f = np.array(_from_mod(inter_vals[:L * d]))
            gelu_f = ref_gelu(inter_f)

        with ctx.timer.segment(SEG_COMPUTE_LINEAR):
            gelu_layout = layout_input(
                [gelu_f.reshape(L, d)[i] for i in range(L)], L, self.spec)
            ct_gelu = self.ctx.encrypt_vector(gelu_layout)
            W_ffn2 = layer.output.dense.weight.detach().numpy().T[:d, :]
            ffn2 = linear_cipher(self.ctx, ct_gelu, W_ffn2, L, self.spec,
                                 diagonals=self._diags(W_ffn2))
            h_sw = self.ctx.mod_switch_to(h, ffn2.level)
            out = self.ctx.add(ffn2, h_sw)
        return out

    def classify(self, text: str, ctx: Optional[RoundContext] = None) -> dict:
        """端到端：嵌入加密 → N 层 → P0 掩码解密 CLS → 明文池化/分类头。"""
        ctx = ctx or RoundContext(index=0)
        enc = self.tok(text, truncation=True, max_length=self.cfg.seq_tokens,
                       return_tensors="np")
        token_ids = [int(t) for t in enc["input_ids"][0]][:self.cfg.seq_tokens]
        while len(token_ids) < self.cfg.seq_tokens:
            token_ids.append(0)
        t0 = time.perf_counter()
        with ctx.timer.segment(SEG_ENCRYPT):
            emb = self.model.embeddings.word_embeddings.weight.detach().numpy()
            ct = embed_and_encrypt(self.ctx, token_ids, emb, self.spec)
        x = ct
        for li in range(self.cfg.n_layer):
            x = self._layer(li, x, token_ids, ctx)
        with ctx.timer.segment(SEG_THRESH_DECRYPT):
            cls = self.ctx.decrypt(x)[:1]        # P0 白名单解密（D5 修订）
        with torch.inference_mode():
            hidden = torch.tensor(cls).unsqueeze(0)
            pooled = self.model.bert.pooler(hidden)
            logits = self.model.classifier(pooled)
            probs = torch.softmax(logits, dim=-1)[0]
            idx = int(probs.argmax())
        return {"label": self.plain.LABEL_MAP[idx], "prob": float(probs[idx]),
                "conversions": self.stats.conversions,
                "mpc_gates": self.env.gates_used,
                "mpc_comm_bytes": self.env.comm_bytes,
                "wall_s": time.perf_counter() - t0}


def _from_mod(vals: List[int]) -> List[float]:
    out = []
    for v in vals:
        s = v % DEFAULT_MODULUS
        if s > DEFAULT_MODULUS // 2:
            s -= DEFAULT_MODULUS
        out.append(s / (1 << 16))
    return out
