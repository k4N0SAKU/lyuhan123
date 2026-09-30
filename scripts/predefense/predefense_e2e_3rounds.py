#!/usr/bin/env python3
"""赛前动作①：目标演示机 e2e ≥3 轮复跑确认（一键验收）。

背景（阶段任务登记 P7 节 [~] 留赛前项）：10 轮稳定性实测在开发机完成；
本脚本在【目标演示机】上把同一套出口条件复跑 ≥3 轮，产出可贴回的验收单。

判定口径与 tests/e2e/test_demo_stability.py 完全一致：
  phase==DONE、轮数达标、明文扫描逐轮 0 命中、白名单解密逐轮成功、
  审计链核验通过、密钥销毁全零覆写、wall_stats 来自 perf 统计模块。

用法（在仓库根目录、已装好依赖、模型已下载的机器上）：
  python predefense_e2e_3rounds.py                    # 双场景各 3 轮（默认）
  python predefense_e2e_3rounds.py --scenario gov --rounds 3
  python predefense_e2e_3rounds.py --external http://127.0.0.1:8060
                                                      # 演示已在跑时直连

纯标准库实现（不依赖 torch/psutil；有则增强环境块）。
证据写入 benchmarks/results/predefense_e2e_3rounds.json（走 D8 write_report，
不可用时降级为 json.dump 并注明）。
"""
from __future__ import annotations

import argparse
import json
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROUNDS_DEFAULT = 3
STALL_TOL_S = 60            # 单请求容忍（与稳定性口径一致：SEAL keygen GIL 尾部）
RUN_DEADLINE_S = 45 * 60    # 单次 run 总超时（与稳定性口径一致）
POLL_INTERVAL_S = 5

VERDICT_ROWS = [
    ("phase == DONE", lambda st, rounds, cfg: st.get("phase") == "DONE"),
    ("轮数 == 目标", lambda st, rounds, cfg: len(rounds) == cfg["rounds"]),
    ("明文扫描逐轮 0 命中", lambda st, rounds, cfg:
        all(r.get("plaintext_ok") for r in rounds)),
    ("白名单解密逐轮成功", lambda st, rounds, cfg:
        all(r.get("final_decrypt_ok") for r in rounds)),
    ("审计链核验通过", lambda st, rounds, cfg: st.get("audit_chain_ok") is True),
    ("密钥销毁全零覆写", lambda st, rounds, cfg: all(
        v for d in (st.get("destroy") or {}).values() for v in d.values())),
    ("指标来自 perf 统计模块", lambda st, rounds, cfg:
        (st.get("wall_stats") or {}).get("unit") == "ms"
        and (st.get("wall_stats") or {}).get("n") == cfg["rounds"]
        and bool(st.get("segment_stats"))),
]


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _get(base, path, timeout=STALL_TOL_S):
    t0 = time.time()
    with urllib.request.urlopen(base + path, timeout=timeout) as r:
        body = json.loads(r.read())
    ms = (time.time() - t0) * 1000
    return body, ms


def _post(base, path, payload, timeout=STALL_TOL_S):
    req = urllib.request.Request(
        base + path, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def _wait_idle(base, deadline_s=240):
    t0 = time.time()
    st = {"phase": "INIT", "busy": True}
    while time.time() - t0 < deadline_s:
        try:
            st, _ = _get(base, "/api/status")
            if not st.get("busy") and st.get("phase") in (
                    "DONE", "FAILED", "INIT", "MODE_A_UNAVAILABLE"):
                return st
        except Exception:
            time.sleep(2)
        time.sleep(2)
    return st


def _env_block() -> dict:
    import platform
    env = {"python": sys.version.split()[0], "platform": platform.platform(),
           "cpu_count": __import__("os").cpu_count(),
           "note": "目标演示机 e2e 复跑（赛前动作①）"}
    try:
        import psutil
        vm = psutil.virtual_memory()
        env["mem_total_gb"] = round(vm.total / 2**30, 1)
        env["mem_available_gb"] = round(vm.available / 2**30, 1)
    except Exception:
        pass
    try:
        import torch
        env["torch"] = torch.__version__
        env["torch_threads"] = torch.get_num_threads()
    except Exception:
        env["torch"] = "未探测（以 wall_stats 为准）"
    return env


def run_one(base, scenario, rounds):
    """跑一个场景（rounds 轮模式 B）→ 返回 (st, elapsed_s)。"""
    out = _post(base, "/api/run", {"scenario": scenario, "sample": 0,
                                   "rounds": rounds, "mode": "B"})
    if not out.get("accepted"):
        return {"phase": "REJECTED", "error": out}, 0.0
    t0 = time.time()
    st = {"phase": "RUNNING"}
    while time.time() - t0 < RUN_DEADLINE_S:
        try:
            st, _ = _get(base, "/api/status")
        except Exception:
            time.sleep(POLL_INTERVAL_S)
            continue
        if st.get("phase") in ("DONE", "FAILED", "MODE_A_UNAVAILABLE"):
            break
        time.sleep(POLL_INTERVAL_S)
    return st, round(time.time() - t0, 1)


def judge(st, rounds, cfg):
    rows = [(name, bool(fn(st, rounds, cfg))) for name, fn in VERDICT_ROWS]
    return rows, all(ok for _, ok in rows)


def print_sheet(scenario, rows, passed, st, elapsed):
    print(f"\n┌─ 验收单：场景 {scenario}（模式 B）")
    for name, ok in rows:
        print(f"│ {'✅' if ok else '❌'} {name}")
    ws = (st.get("wall_stats") or {})
    print(f"│ 耗时 {elapsed}s；单轮 P50={ws.get('p50')}ms / P95={ws.get('p95')}ms"
          f"（n={ws.get('n')}）")
    if st.get("error"):
        print(f"│ error: {st.get('error')}")
    print(f"└─ 结论：{'通过' if passed else '不通过'}")
    if not passed:
        print("  失败处置：先 stop 等 idle 再重试一次；复现即停——"
              "换演示机或视频兜底，别现场调试。")


def write_evidence(repo, report):
    out = repo / "benchmarks" / "results" / "predefense_e2e_3rounds.json"
    try:
        sys.path.insert(0, str(repo))
        from src.common.perf import write_report
        write_report(report, out)
        via = "src.common.perf.write_report（D8）"
    except Exception:
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=True, indent=2)
        via = "json.dump 降级（write_report 不可用）"
    print(f"\n证据已写入：{out}（经 {via}）")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", default="both",
                    choices=["gov", "enterprise", "both"])
    ap.add_argument("--rounds", type=int, default=ROUNDS_DEFAULT)
    ap.add_argument("--external", default="",
                    help="已运行的演示服务地址（如 http://127.0.0.1:8060）")
    ap.add_argument("--repo", default=".",
                    help="仓库根目录（默认当前目录）")
    args = ap.parse_args()
    repo = Path(args.repo).resolve()

    scenarios = ["gov", "enterprise"] if args.scenario == "both" else [args.scenario]
    proc = None
    base = args.external.rstrip("/")
    if not base:
        port = _free_port()
        base = f"http://127.0.0.1:{port}"
        print(f"启动演示服务：{base}（python -m src.demo.app）")
        proc = subprocess.Popen(
            [sys.executable, "-m", "src.demo.app", "--port", str(port)],
            cwd=str(repo), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(120):
            try:
                if _get(base, "/api/health", timeout=10)[0].get("ok"):
                    break
            except Exception:
                time.sleep(1)
        else:
            print("❌ 演示服务 120s 内未就绪（先跑：python -m benchmarks.download_models）")
            proc.terminate()
            return 2

    env = _env_block()
    all_pass, evidence_runs = True, []
    try:
        for sc in scenarios:
            _wait_idle(base)
            print(f"\n▶ 场景 {sc}：{args.rounds} 轮（模式 B）……")
            st, elapsed = run_one(base, sc, args.rounds)
            rounds = st.get("rounds") or []
            cfg = {"rounds": args.rounds, "scenario": sc, "mode": "B"}
            rows, passed = judge(st, rounds, cfg)
            print_sheet(sc, rows, passed, st, elapsed)
            all_pass = all_pass and passed
            evidence_runs.append({
                "scenario": sc, "rounds_target": args.rounds,
                "phase": st.get("phase"), "error": st.get("error"),
                "elapsed_s": elapsed, "passed": passed,
                "checks": [dict(name=n, ok=k) for n, k in rows],
                "wall_stats": st.get("wall_stats"),
                "segment_stats_keys": sorted((st.get("segment_stats") or {}).keys()),
                "traffic": st.get("traffic"), "memory": st.get("memory"),
                "rounds": rounds,
            })
            try:
                _post(base, "/api/stop", {})
            except Exception:
                pass
            _wait_idle(base)
    finally:
        if proc is not None:
            proc.terminate()
            try:
                proc.wait(15)
            except subprocess.TimeoutExpired:
                proc.kill()

    write_evidence(repo, {
        "schema": "a122-perf/1", "kind": "predefense-e2e-rehearsal",
        "workload": f"demo_{args.rounds}_rounds",
        "config": {"scenarios": scenarios, "rounds": args.rounds, "mode": "B",
                   "base": base},
        "environment": env,
        "result": {"all_passed": all_pass,
                   "runs": evidence_runs},
    })

    print("\n════════ 答辩前 e2e 复跑总结论 ════════")
    print(f"{'✅ 全部通过' if all_pass else '❌ 存在不通过项'}"
          f"（{args.scenario}，{args.rounds} 轮/场景）")
    if all_pass:
        print("下一步：把本输出贴进《目标演示机验收单》，登记表 [~] 行可勾 [x]。")
    return 0 if all_pass else 1


if __name__ == "__main__":
    raise SystemExit(main())
