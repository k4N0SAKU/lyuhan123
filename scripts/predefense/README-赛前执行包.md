# 赛前执行包 README（两动作，一键跑）

> 来源：P7 终检反馈 [L] 终裁"维持移交"+ 登记表 P7 节 [~] 留赛前项。
> 红线：**不修改任何演示代码与 src/ 文件**——两脚本只调用既有 API/管线，
> 证据走 D8（results/ + JSON），登记走 dict 动线（文档+四检）。

## 动作①：目标演示机 e2e ≥3 轮复跑（必做）

**为什么**：10 轮稳定性实测在开发机；答辩现场的机器（内存/CPU 不同）上
必须再确认一遍，双场景不 OOM、不 stall。

**怎么跑**（在目标演示机、仓库根目录、依赖模型齐备后）：

```bash
python predefense_e2e_3rounds.py            # 双场景（政务+企业）各 3 轮，模式 B
# 或：python predefense_e2e_3rounds.py --scenario gov --rounds 5
# 演示服务已在跑：python predefense_e2e_3rounds.py --external http://127.0.0.1:8060
```

**通过判定（与 10 轮稳定性同款口径，7 项）**：phase==DONE、轮数达标、
明文扫描逐轮 0 命中、白名单解密逐轮成功、审计链核验通过、密钥销毁全零
覆写、指标来自 perf 统计模块。证据自动写
`benchmarks/results/predefense_e2e_3rounds.json`（D8 通道）。

**跑完做什么**：控制台输出的验收单贴进答辩材料；登记表 P7 节 [~] 行
（演示环境性能裕量）的"留赛前：目标演示机 e2e ≥3 轮"改 [x] 并附 JSON 名。

**兜底**：实机确实不可得 → 同规格机器模拟 + 演示视频兜底（分镜脚本已有）。

**已验证程度（如实申报）**：本脚本在交付前用 mock 演示服务（模拟 API
状态机）做了全链实跑验证——双场景×3 轮、7 项判定、D8 证据写入全部通过
（EXIT=0）。**mock 结果不构成演示机证据**，正式验收数字必须来自目标机
实跑。

## 动作②：ChnSentiCorp 明文单口径轻量版（可选加分，不做不扣分）

**为什么**：当前精度主张全部自建集自参照；用公开集跑一次明文精度，把
00 §3 差距 6 的"公开集待补"推进为"明文口径已补"。

**条件**：答辩前 4~6 小时空档 + 演示已冻结（先做动作①再做这个）。

**怎么跑**：

```bash
python chnsenticorp_plaintext_eval.py        # n=200（与自建口径对齐，10~20 分钟）
python chnsenticorp_plaintext_eval.py --n all  # 全量 test 集
```

脚本自动取数（本地 data/chnsenticorp/ → HF/镜像自动下载 → 手动放置指引），
自动写证据 `benchmarks/results/chnsenticorp_plaintext_<UTC>.json`，
跑完**打印四段登记文**：data_dict 新条目、00 差距 6 追注、04 §6 来源列
追注、登记表 [L] 行状态——逐段粘贴即可。

**登记后必跑**：`python scripts/check_docs_consistency.py`（四检 EXIT=0，
否则新条目没对上账）。

**已验证程度（如实申报）**：本沙箱无 torch/模型，**未执行真实评测**——
符合终裁口径"不做不扣分"。脚本结构经 `--selftest` 验证（表头解析/
证据 JSON a122-perf/1/登记文格式全就绪）；真实数字必须在装好依赖的
机器上以正式模式取得，**禁止用 selftest 的示例数字**。

## 时间预算与顺序

1. 动作①：目标机上约 15~30 分钟（视 CPU）——**必做**；
2. 动作②：约 10~20 分钟评测 + 15 分钟登记与四检——有空档再做；
3. 都做完：跑一次 `bash scripts/reproduce.sh` 冒烟（可选）确认仓库健康。
