"""lattice-estimator 安全参数复核（P2-R1 评审 B2/C 项——P3 决策数据包）。

参数对应 docs/01 §5.3 表 7（CKKS/RLWE 按 LWE 模型估计，n=poly 度，q=链总乘积；
secret 取均匀三元组（较 SEAL 稀疏秘密更保守），error 取 σ=3.2 离散高斯）：
    A) [60,40,40,60]        @ 2^15  （mode-b 主线，200bit）
    B) [60]+[40]*19+[60]    @ 2^15  （deep19 回归链，880bit）
    C) [60]+[40]*40+[60]    @ 2^16  （评审 C 项：NONE 级可用，决策参数，1720bit）
    D) [60]+[40]*84+[60]    @ 2^17  （mode-a 理论，3480bit）

依赖：malb/lattice-estimator（需 SageMath 环境，P3 首日 Docker/WSL 运行——
Windows 裸环境 sage.all 不可用，见 P2 工作记录 B2 项受阻声明）。
用法：python -m benchmarks.security_estimator [--quick]
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
OUT = REPO_ROOT / "benchmarks" / "results" / "security_estimator.json"


def _load_estimator():
    import glob
    candidates = []
    for base in ("C:/Users/27471/AppData/Local/Temp/le",
                 "/tmp/le", str(Path.home() / "AppData/Local/Temp/le")):
        candidates += glob.glob(base)
    for c in candidates:
        if (Path(c) / "estimator").is_dir():
            sys.path.insert(0, c)
            break
    from estimator import LWE  # noqa
    from estimator.nd import Ternary, DiscreteGaussian  # noqa（P4 实测 API：
    # 分布类在 estimator.nd 模块级，非 LWE.Ternary——P3 盲写口径已修正）
    LWE.Ternary = Ternary
    LWE.DiscreteGaussian = DiscreteGaussian
    return LWE


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--quick", action="store_true",
                        help="只跑决策关键参数 C（2^16/1720bit）")
    args = parser.parse_args()

    LWE = _load_estimator()
    from estimator.io import Logging
    import logging
    Logging.set_level(logging.WARNING)

    cases = {
        "A_modeb_2p15_200bit": dict(n=1 << 15, bits=200),
        "B_deep19_2p15_880bit": dict(n=1 << 15, bits=880),
        "C_decision_2p16_1720bit": dict(n=1 << 16, bits=1720),
        "D_modea_2p17_3480bit": dict(n=1 << 17, bits=3480),
    }
    if args.quick:
        cases = {k: v for k, v in cases.items()
                 if k.startswith("C") or k.startswith("A")}   # 决策组：A+C

    results = {}
    for name, c in cases.items():
        q = 2 ** c["bits"]
        params = LWE.Parameters(
            n=c["n"], q=q,
            Xs=LWE.Ternary,                        # 保守：均匀三元组（nd.Ternary 为单例）
            Xe=LWE.DiscreteGaussian(3.2),
            tag=name,
        )
        t0 = time.perf_counter()
        try:
            rep = LWE.estimate(params, deny_list=["arora-gb", "bkw"])
            best = min(v.get("rop", 2**64) for v in rep.values() if isinstance(v, dict))
            bits_sec = float(best).bit_length()
            results[name] = {"n": c["n"], "chain_bits": c["bits"],
                             "security_bits": bits_sec,
                             "wall_s": round(time.perf_counter() - t0, 1),
                             "detail": {k: (v.get("rop") if isinstance(v, dict) else v)
                                        for k, v in rep.items()}}
            print(f"{name}: n={c['n']} chain={c['bits']}bit -> ~{bits_sec}bit 安全 "
                  f"({results[name]['wall_s']}s)")
        except Exception as exc:
            results[name] = {"n": c["n"], "chain_bits": c["bits"], "error": repr(exc)}
            print(f"{name}: FAILED {exc!r}")

    OUT.write_text(json.dumps(results, indent=2, default=str), encoding="utf-8")
    print(f"-> {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
