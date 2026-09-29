# A1-22 · 面向大模型隐私保护的密码方案

> 第十一届全国密码技术竞赛复赛 A1-22 题参赛作品 ｜ 全栈国密 ｜ P0~P7 全链交付，评审验收关闭

**一句话**：用户输入在本地加密，大模型推理全程只见密文与秘密分享——
政务/企业敏感文本的情感研判结果经"白名单掩码解密"返回客户端，推理节点
自始至终拿不到明文；SM2/SM3/SM4-GCM 管住身份认证、完整性校验与密钥
全生命周期。

|  |  |
|---|---|
| 密码栈 | CKKS（TenSEAL/SEAL）· 模 2^k 加法秘密分享 · Beaver 三元组 · 国密 SM2/SM3/SM4-GCM |
| 模型 | BERT-base-chinese 情感二分类（演示主线）· GPT-2 124M（生成口径） |
| 形态 | 三方节点（P0 客户端 / P1 密钥节点 / P2 推理节点）+ 离线 CA + FastAPI 演示系统 |
| 规模 | 代码 9,949 行 · 测试 243 passed + 16 deselected + 3 xfailed · 数据字典 93 条四检全绿 |

## 核心数字（每个都可回读 JSON，见"证据纪律"）

| 主张 | 数字 | 证据 |
|---|---|---|
| 密文推理精度 | **99.00%**（n=200，vs FP32 差 0.00pp） | `benchmarks/results/pipeline_accuracy_*.json` |
| C2 量化最优点 | 一致率 **1.000** @ 体积 **−34.1%**（312.7 MiB） | `p6_full_bench.json::c2_selector` |
| C3 双实现选型 | row-sum 慢 **5.1×**（诚实负结果，对角线+BSGS 胜出） | `docs/05-创新点报告.md` |
| 攻击测试 | 五类攻击自动化，**28 防御成功 + 2 边界演示 + 0 失败** | `benchmarks/results/attack_verdicts.json` |
| 演示稳定性 | 连续 **10 轮**零故障，全程流量 346,472,232 B（330.4 MiB） | `benchmarks/results/p7_demo_stability.json` |

## 系统架构

```
              ┌────────── 离线 CA（证书/密钥分发）──────────┐
              ▼
  P0 客户端 ⇄(SM2 双向认证 + SM4-GCM 通道)⇄ P1 密钥节点 ⇄ P2 推理节点
  │  ①本地加密输入（明文不出 P0）        ②密文/秘密分享经通道流转
  │  ③CKKS 线性层（对角线+BSGS 打包）    ④非线性=minimax 多项式+MPC
  │  ⑤Beaver 三元组在线乘法              ⑥白名单掩码解密（只出"正/负面"标签）
  └─ ⑦ SM3 哈希链审计 + 会话密钥销毁覆写（零化）
```

- **模式 A**（纯秘密分享 MPC）：本栈如实申报不可实例化，攻击测试仍对两模式分别执行；
- **模式 B**（CKKS 密文主线，含密文↔分享转换）：演示与评测采用，D5 白名单解密执行点。

## 快速开始

```bash
# 环境：Windows / Linux，Python 3.10+，CPU-only；首次联网下载模型约 1.5GB
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt

python -m benchmarks.download_models    # 模型下载（HF/镜像自动探测）
python -m benchmarks.finetune_bert      # 微调 BERT 情感分类头（约 3 分钟）

python -m src.demo.app --port 8060      # 演示系统：http://127.0.0.1:8060/
```

**一键复现**（干净目录 6 步一次通过，见 `docs/06-复现手册.md`）：

```bash
bash scripts/reproduce.sh
```

**测试与质量门**：

```bash
python -m pytest -q                              # 243 passed + 16 deselected + 3 xfailed
python -m pytest -m slow -q                      # 演示稳定性 10 轮等慢速项
python scripts/check_docs_consistency.py         # 四检（数据字典/注入表/黑名单/互引）
```

## 证据纪律（这套项目的特色）

- **D8**：所有性能数字只允许由 benchmark 脚本写入 `benchmarks/results/`
  （UTC 时间戳 JSON），文档引用必须与 JSON 一致，禁止手填；
- **数据字典**：`docs/data_dict.json` 收录 93 条指针，每个主张都能回读
  到具体 JSON 字段（四检脚本校验）；
- **如实申报**：模式 A 不可实例化、t=2 合谋为预先声明的构造边界、公开
  数据集外部效度待补（`docs/00 §3` 差距 6）——均已登记，不做隐藏性声明。

## 文档导航

| 文档 | 内容 |
|---|---|
| `docs/00-方案概述.md` | 痛点/方案/差距（封面 v1.0，数据字典声明） |
| `docs/01-架构与协议规格.md` | 九章规格：拓扑/消息/时序/CKKS/打包/非线性/转换/密钥管理 |
| `docs/02-威胁模型与安全分析.md` | 敌手能力表、假设 A-1~A-9、半诚实模拟器论证 |
| `docs/03-攻击测试报告.md` | 五类攻击 30 项判定（28+2+0） |
| `docs/04-性能与基线对比.md` | 四项资源指标、五维对比（本机/SPU/PUMA/MPCFormer/BumbleBee） |
| `docs/05-创新点报告.md` | C2 参数自适应 / C3 双实现（含诚实负结果） |
| `docs/06-复现手册.md` | 一键复现 6 步链与证据 |
| `docs/phases/` | P0~P7 工作记录 + 项目总结报告 + 事故档案 |
| `docs/defense/` | PPT 提纲与讲稿 12 页、评委 Q&A 20 条 |
| `docs/code-walkthrough.md` | 模块代码导读（答辩速览地图） |
| `scripts/predefense/` | 答辩前两动作执行包（目标机 e2e ≥3 轮 + ChnSentiCorp 可选加分） |

## 阶段里程碑

| 阶段 | 目标 | 状态 |
|---|---|---|
| P0 | 环境、明文基线、定点化预研、性能框架 | ✅ 评审通过 |
| P1 | 架构与协议规格 | ✅ R1 修订闭环 |
| P2 | 密码原语层 | ✅ R1 修订闭环 |
| P3 | 密文推理管线（模式 A/B） | ✅ 评审通过 |
| P4 | 认证与密钥全生命周期 | ✅ 评审通过（2026-09-27） |
| P5 | 攻击测试 | ✅ R1 整改闭环 |
| P6 | 性能与基线对比 | ✅ R1/R2/R3 修订闭环 |
| P7 | 演示与交付 | ✅ 终检通过 + R1 修订验收（2026-09-29） |

## License

见 `LICENSE`（参赛作品版权声明）。第三方依赖（PyTorch、Transformers、
TenSEAL/SEAL、gmssl、FastAPI 等）遵循各自开源许可。
