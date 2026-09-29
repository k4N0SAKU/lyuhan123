# A1-22：面向大模型隐私保护的密码方案软件设计实现

第十一届全国密码技术竞赛复赛 A1-22 题参赛系统。目标：**在不泄露原始用户数据的前提下完成大模型推理**——用户输入在本地加密/秘密分享后，网络上与推理节点中只流转密文或分享值，推理结果经掩码解密返回客户端；全栈国密（SM2/SM3/SM4-GCM）支撑身份认证、完整性校验与密钥全生命周期管理。

**当前进度：P6 性能与基线对比完成（待团队评审）。** 四项资源指标实测（代码规模 9,949 行/节点峰值内存/端到端与分段耗时/每连接流量，JSON 可追溯）+ 五维基线对比（本机明文锚点 + SPU/PUMA/MPCFormer/BumbleBee 文献口径，逐项标来源与不可比因素）+ 创新点 A/B：**C2 参数自适应**（conv_fp16+emb_q22 = 一致率 1.000 @ 体积 −34.1%（312.7 MiB）；逐张量阈值/层级升级选择器失效为诚实负结果）、**C3 双实现**（row-sum 慢 5.1×，对角线+BSGS 胜出）。复现：`bash scripts/reproduce.sh`（干净目录 6 步一次通过，证据 reproduce_logs/）。 docs/02 定稿（敌手能力表、假设核对表 A-1~A-9、攻击→机制→代码→测试三列表、半诚实模拟器简化证明）+ docs/03 攻击测试报告：五类攻击自动化断言（窃听/中间人/结果篡改/重放/合谋），30 项判定 = 28 防御成功 + 2 边界演示（模式 B t=2 合谋为预先声明的构造边界）+ 0 失败；F8 对模式 A、B 分别执行。**P4 认证与密钥全生命周期已评审通过（2026-09-27）**。 国密协议栈落地：SM2 证书双向认证（离线 CA 供给）、SM2DH 会话协商、SM4-GCM 安全通道（seq/时间戳/ratchet 周期更新）、密钥登记表两遍覆写销毁、SM3 哈希链审计；D5 转换真实路径在管线落地（P2 密文域加 Enc(r)→P0 白名单①掩码解密→P2 持 -r；出口 P1 掩码→P2 密文域合成 fresh 密文；最终输出白名单②解密），三节点编排 e2e（进程内+多进程）+ 攻击预埋（篡改/重放/伪造证书）全绿。测试双口径：默认 212+3xfail / slow 13。P3-R1：管线与明文截断参考一致、四口径精度回归、results/ 全量恢复、[K] 220 prompts 扩测达标。仓库为 2026-09-26 搬迁事故后重建版（docs/phases/搬迁事故报告.md）。

## 系统形态（规划）

| 节点 | 角色 |
|---|---|
| P0 客户端 | 唯一接触明文输入与最终结果的一方；持完整 CKKS 私钥（掩码解密白名单，D5 修订） |
| P1 密钥服务节点 | 身份认证中枢、会话密钥全生命周期、审计、MPC 参与方 |
| P2 推理服务节点 | 持有模型，只接触密文/分享值，密文域计算 |

计算路线（决策 D1）：**CKKS 同态加密为主线 + 秘密分享/MPC 兜底**，模式 A（纯密文，本栈不可全演示→理论推演+段级验证）/ 模式 B（混合，主线）。

## 环境要求

- Windows / Linux，**Python 3.10+**（验证版本 3.10.4）；CPU-only 口径（无 GPU 环境，时延数据随 JSON 环境块输出）
- 首次联网下载依赖与模型（~1.5GB）；模型下载自动探测 huggingface.co / hf-mirror.com
- **本仓库位于 `D:\safetensors\密码技术竞赛\`**（D 盘根目录 ACL 受限，safetensors 为团队交换目录）

## 快速开始

**一键复现（P6：干净目录 6 步一次通过，见 docs/06-复现手册.md）**：

```bash
cd D:/safetensors/密码技术竞赛/a122-llm-privacy
bash scripts/reproduce.sh    # 装环境→模型→明文基线→密态推理 e2e→攻击测试
```

手动分步：

```bash
cd D:/safetensors/密码技术竞赛/a122-llm-privacy
python -m venv .venv && source .venv/Scripts/activate
pip install -r requirements.txt

python -m src.common.envinfo                # 环境自检（CKKS/SM3 冒烟）
python -m benchmarks.download_models        # 模型下载（HF/镜像自动探测）
python -m benchmarks.finetune_bert          # 微调 BERT 情感分类头（~3min，FP32 acc 99.0%）
python -m benchmarks.demo_plaintext         # 一条命令明文推理 Demo
python -m benchmarks.run_ci                 # 本地全量质量门（自检→测试→基线→断言）
```

单项实验：

```bash
python -m benchmarks.eval_quantize                                   # 定点化精度（阈值断言）
python -m benchmarks.perf_runner --workload gpt2 --rounds 20         # 生成基线
python -m benchmarks.run_full_bench --quick                          # P6 四指标+矩阵冒烟
python -m benchmarks.run_full_bench --parts cipher_matrix --cipher-rounds 20  # 密文矩阵（~4h）
python -m pytest                                                     # 快速测试（不含 slow）
python -m pytest -o addopts= tests                                   # 全量测试
```

## 目录导览

| 路径 | 内容 |
|---|---|
| `docs/00~06` | 赛题原文 / 架构与协议规格 / 威胁模型 / 性能与基线对比 / 创新点报告 / 复现手册 |
| `docs/phases/` | P0~P6 阶段工作记录 + 工作总览（全量台账）+ 阶段任务登记 |
| `src/crypto/` | CKKS（sealapi）/国密 SM2/SM3/SM4-GCM/秘密分享/Beaver |
| `src/protocol/` | 认证/会话通道/密钥生命周期/审计链/**转换真实路径**（D5） |
| `src/nodes/` | 三节点角色 + 离线供给工具 + 生命周期编排（进程内/多进程） |
| `src/model/` | BERT/GPT-2 管线（密文模式 B）/量化/打包/近似 |
| `benchmarks/` | perf_runner / eval_quantize / run_full_bench（P6 总基准）/ security_estimator |
| `tests/` | unit（含 P4 协议族）/ attack（五类攻击套件）/ e2e（管线+生命周期） |
| `deliverables/` | p0~p5.zip + sha256（GitHub 同步） |

## 当前能力（实测）

| 项 | 结果 | 证据 |
|---|---|---|
| 明文 GPT-2 贪心生成 | 单轮（16 token）P50=792.4ms / P95=856.5ms（20 轮 CPU，权威口径 2026-09-25 04:17 UTC） | `results/gpt2_plaintext_baseline_*.json` |
| 明文 BERT 情感分类 | 单轮 P50=38.4ms / P95=49.0ms；FP32 acc=99.0% | 同上 `bert_*` |
| 定点化（激活 Q16 + GPT-2 权重 Q22 / BERT 权重 INT8） | token 一致率 **100%**；分类下降 **0.00pp** | `results/quantize_eval_*.json` |
| CKKS 参数（P2 实测） | 本栈 SEAL 上限 2^15 → mode-b 16384 槽/密文 1.64MB；mode-a 不可实例化（团队决策项） | `docs/01` §5.3 |
| 密码原语（P2） | 精度回归 2 层 3.8e-9/14 层 7.1e-9；线性层 768×768×L2=4.15s；RFC 8998 外部锚定 | `results/primitives_*.json` |
| 测试 | **双口径全绿**：默认 242+3xfail / 攻击全套 38 零告警（P5-R1 后） | `run_ci` / `attack_verdicts.json` |

测量口径声明：同机重跑存在 ~1.6× 机器状态波动；基线稳定性协议（固定线程/同时段/多轮区间/envinfo 负载记录）P6 已执行（run_full_bench 线程锁定 + envinfo 写入 JSON）。

## 性能数据纪律（决策 D8）

- 所有性能结论只允许由 benchmark 脚本生成到 `benchmarks/results/`（`write_report` 强制绝对路径归一化）；
- 报告模式 `a122-perf/1` / `a122-quantize-eval/1`，UTC 时间戳；
- 文档引用的每个数字必须与 results/ JSON 一致，禁止手填。

## 阶段路线

| 阶段 | 目标 | 状态 |
|---|---|---|
| P0 | 环境、明文基线、定点化预研、性能框架 | ✅ |
| P1 | 架构与协议规格（R1 修订闭环） | ✅ |
| P2 | 密码原语层（R1 修订闭环，待核验签字） | ✅ |
| P3 | 密文推理管线（模式 A/B、S6、F2） | 🚧 进行中 |
| P4~P7 | 控制面 / 攻击测试 / 性能对比 / 交付 | - |

## 仓库结构

```
a122-llm-privacy/
├── docs/          # 00 赛题存档、01 规格（重建版）、02 威胁模型、phases/、review/
├── src/           # common / crypto（P2 实现）/ protocol（P4）/ model / nodes / demo
├── tests/         # unit（127）+ e2e（4）+ attack（P5）
├── benchmarks/    # perf_runner / eval_quantize / finetune_bert / primitive_bench / run_ci / package_phase
└── data/          # sentiment 数据集（入库）、models（不入库）、minimax 系数
```
