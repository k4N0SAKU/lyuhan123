#!/usr/bin/env python3
"""赛前动作②（可选加分项）：ChnSentiCorp 明文单口径轻量评测。

定位（P7 终检反馈 §三 终裁附带条件②）：补"外部效度锚点"的明文单口径——
用公开中文情感数据集 ChnSentiCorp 给微调 BERT 做一次明文精度评测，
把 00 §3 差距 6 的"公开集待补"推进为"明文口径已补"。
**明文单口径：不含量化/密文路径，不触碰演示代码（演示已冻结）。**

用法（在仓库根目录、依赖与模型齐备的机器上，约 10~20 分钟）：
  python chnsenticorp_plaintext_eval.py                  # n=200（与自建口径对齐）
  python chnsenticorp_plaintext_eval.py --n all          # 全量 test 集（~1200 条）
  python chnsenticorp_plaintext_eval.py --n 500
  python chnsenticorp_plaintext_eval.py --selftest       # 无 torch 也能跑：验
                                                         # 证解析/证据/登记文格式

数据获取（自动按序尝试，也可手动放置）：
  1) data/chnsenticorp/ 下已有 csv/tsv（列含 label 与 text）；
  2) 自动下载：huggingface.co / hf-mirror.com 的
     datasets/lansinuote/ChnSentiCorp/resolve/main/{test,dev,valid,eval}.csv
     （与 download_models.py 同款镜像探测；下载失败会给出手动放置指引）。

证据纪律（D8）：结果写 benchmarks/results/chnsenticorp_plaintext_<UTC>.json
（a122-perf/1，经 src.common.perf.write_report）；selftest 不入 results/。
评测口径：按文件顺序取前 n 条（不 shuffle，确定性可复跑）。
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import sys
import time
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent
DATA_DIR = REPO / "data" / "chnsenticorp"
MODEL_DIR = REPO / "data" / "models" / "bert-base-chinese-sentiment"

DATASET_CANDIDATES = [  # (文件名, 远程路径候选)
    ("test.csv", "datasets/lansinuote/ChnSentiCorp/resolve/main/test.csv"),
    ("dev.csv", "datasets/lansinuote/ChnSentiCorp/resolve/main/dev.csv"),
    ("valid.csv", "datasets/lansinuote/ChnSentiCorp/resolve/main/valid.csv"),
    ("eval.csv", "datasets/lansinuote/ChnSentiCorp/resolve/main/eval.csv"),
    ("test.tsv", "datasets/lansinuote/ChnSentiCorp/resolve/main/test.tsv"),
]
HF_HOSTS = ["https://hf-mirror.com", "https://huggingface.co"]


def log(msg: str) -> None:
    print(f"[chnsenticorp] {msg}")


# ---------------------------------------------------------------- 数据获取

def _parse_rows(text: str) -> list:
    """通用解析：csv/tsv，自动识别分隔符，要求列含 label 与 text。"""
    delim = "\t" if "\t" in text.splitlines()[0] else ","
    rdr = csv.DictReader(io.StringIO(text), delimiter=delim)
    rows, cols = [], (rdr.fieldnames or [])
    lab = next((c for c in cols if c and c.strip().lower() in
                ("label", "y", "class")), None)
    txt = next((c for c in cols if c and c.strip().lower() in
                ("text", "sentence", "content", "review")), None)
    if lab is None or txt is None:
        raise ValueError(f"表头缺 label/text 列：{cols}")
    for r in rdr:
        try:
            rows.append({"label": int(str(r[lab]).strip()),
                         "text": (r[txt] or "").strip()})
        except (TypeError, ValueError):
            continue
    return rows


def ensure_dataset() -> tuple:
    """返回 (rows, 来源描述)。本地优先，失败则联网下载。"""
    for name, _ in DATASET_CANDIDATES:
        p = DATA_DIR / name
        if p.exists() and p.stat().st_size > 1000:
            return _parse_rows(p.read_text(encoding="utf-8")), f"本地 data/chnsenticorp/{name}"
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    for name, remote in DATASET_CANDIDATES:
        for host in HF_HOSTS:
            url = f"{host}/{remote}"
            try:
                log(f"尝试下载 {url}")
                with urllib.request.urlopen(url, timeout=60) as r:
                    raw = r.read()
                rows = _parse_rows(raw.decode("utf-8", errors="replace"))
                if len(rows) >= 200:
                    (DATA_DIR / name).write_bytes(raw)
                    return rows, f"自动下载 {url} → data/chnsenticorp/{name}"
            except Exception as exc:
                log(f"  失败：{type(exc).__name__}")
    raise SystemExit(
        "❌ 数据集不可得。手动方案：从 huggingface.co/datasets/lansinuote/"
        "ChnSentiCorp 下载任一分割（train/dev/test.csv），放入 "
        "data/chnsenticorp/ 目录后重跑本脚本。")


# ---------------------------------------------------------------- 评测主体

def evaluate(n: int) -> dict:
    import torch
    from src.model.loader import BertSentimentPipeline, LABEL_MAP

    rows, src = ensure_dataset()
    total = len(rows)
    if n <= 0 or n >= total:
        picked, n = rows, total
    else:
        picked = rows[:n]
    log(f"数据 {src}；共 {total} 条，评测 {n} 条（顺序取前 n，不 shuffle）")

    torch.set_num_threads(max(1, (torch.get_num_threads() or 1)))
    pipe = BertSentimentPipeline(model_path=str(MODEL_DIR))

    inv = {v: k for k, v in LABEL_MAP.items()}          # "正面"→1, "负面"→0
    tp = tn = fp = fn = 0
    t0 = time.time()
    preds = pipe.predict([r["text"] for r in picked])
    for row, pr in zip(picked, preds):
        y, yhat = row["label"], inv.get(pr.get("label"), -1)
        if y == 1 and yhat == 1:
            tp += 1
        elif y == 0 and yhat == 0:
            tn += 1
        elif y == 0 and yhat == 1:
            fp += 1
        else:
            fn += 1
    elapsed = round(time.time() - t0, 1)
    acc = (tp + tn) / max(1, tp + tn + fp + fn)
    return {"source": src, "n": n, "dataset_total": total,
            "accuracy": round(acc, 4), "tp": tp, "tn": tn, "fp": fp, "fn": fn,
            "elapsed_s": elapsed,
            "torch_threads": torch.get_num_threads()}


def env_block() -> dict:
    import platform
    env = {"python": sys.version.split()[0], "platform": platform.platform()}
    try:
        import torch
        env["torch"] = torch.__version__
        env["torch_threads"] = torch.get_num_threads()
    except Exception:
        env["torch"] = "unknown"
    return env


# ---------------------------------------------------------------- 证据与登记

def write_evidence(res: dict, selftest: bool = False) -> Path:
    report = {
        "schema": "a122-perf/1", "kind": "chnsenticorp-plaintext-anchor",
        "workload": "bert_sentiment_chnsenticorp_plaintext",
        "config": {"model": "data/models/bert-base-chinese-sentiment",
                   "n": res["n"], "route": "明文单口径（无量化/密文）",
                   "sampling": "文件顺序前 n 条，不 shuffle"},
        "environment": env_block(),
        "result": res,
    }
    if selftest:
        out = Path(REPO).parent / "tmp" / "selftest_chnsenticorp.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=True, indent=2)
    else:
        out = (REPO / "benchmarks" / "results" /
               f"chnsenticorp_plaintext_{time.strftime('%Y%m%d_%H%M%S', time.gmtime())}.json")
        sys.path.insert(0, str(REPO))
        from src.common.perf import write_report
        write_report(report, out)
    return out


def registration_block(res: dict, evidence_path: Path) -> str:
    """执行后需要贴进文档的四段登记文（走 dict 动线，不动演示代码）。"""
    acc_pct = f"{res['accuracy'] * 100:.2f}"
    return f"""
================ 登记文（执行成功后逐段粘贴） ================
① docs/data_dict.json → entries 追加（93→94 条）：
    "chnsenticorp_plaintext.accuracy": {{
      "value": {res['accuracy']},
      "unit": "ratio",
      "source": "{Path(evidence_path).name}::result.accuracy"
    }}

② docs/00-方案概述.md §3 差距 6 追注（保留原"如实应答"句）：
    ——补充：明文单口径已于答辩前补测（ChnSentiCorp 前 {res['n']} 条，
    accuracy {acc_pct}%，{Path(evidence_path).name}）；
    量化/密文两口径仍为待补口径。

③ docs/04-性能与基线对比.md §6 满配精度行"来源"列括注追加：
    ；ChnSentiCorp 明文外部锚点 {acc_pct}%（n={res['n']}）

④ docs/phases/阶段任务登记.md P7 节 [L] 行改写状态：
    [~]（明文口径已补；量化/密文口径仍移交）+ 本行追加
    "答辩前轻量版已执行：{Path(evidence_path).name}"

登记后必跑：python scripts/check_docs_consistency.py（四检须全绿，
EXIT=0——含数据字典↔JSON 新条目一致性）。
============================================================
"""


# ---------------------------------------------------------------- selftest

def selftest() -> int:
    """无 torch 环境下的结构自检：解析、证据 JSON、登记文格式。"""
    fake_csv = "label,text\n1,这家酒店干净卫生服务好\n0,隔音差还乱收费\n" * 100
    rows = _parse_rows(fake_csv)
    assert len(rows) == 200 and rows[0]["label"] == 1, "解析失败"
    fake = {"source": "SELFTEST（无推理，仅验格式）", "n": 200,
            "dataset_total": 200, "accuracy": 0.965, "tp": 97, "tn": 96,
            "fp": 3, "fn": 4, "elapsed_s": 0.0, "torch_threads": 0}
    p = write_evidence(fake, selftest=True)
    back = json.loads(p.read_text(encoding="utf-8"))
    assert back["schema"] == "a122-perf/1" and back["result"]["n"] == 200
    assert "登记文" in registration_block(fake, p)
    print("✅ SELFTEST 通过：表头解析 / 证据 JSON（a122-perf/1）/ 登记文格式全就绪。")
    print("   注意：selftest 不含任何真实推理——正式数字必须在本机跑真模式取得。")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", default="200", help="评测条数：整数或 all")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if not MODEL_DIR.exists():
        raise SystemExit(
            f"❌ 模型缺失：{MODEL_DIR}\n先跑 python -m benchmarks.finetune_bert")
    n = 0 if args.n.lower() == "all" else int(args.n)   # 0 = 全量
    res = evaluate(n)
    p = write_evidence(res)
    print(f"\nChnSentiCorp 明文单口径结果：accuracy {res['accuracy']*100:.2f}%"
          f"（n={res['n']}，tp/tn/fp/fn={res['tp']}/{res['tn']}/{res['fp']}/{res['fn']}）")
    print(f"证据：{p}")
    print(registration_block(res, p))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
