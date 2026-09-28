"""把 p6_tables.md 的密文矩阵表注入 docs/04 占位符（P6：禁止手抄数字）。"""
from pathlib import Path

repo = Path(__file__).resolve().parents[1]
tables = (repo / "benchmarks/results/p6_tables.md").read_text(encoding="utf-8")
start = tables.index("## 2.")
end = tables.index("## 3.", start)
section = tables[start:end].rstrip()
doc = repo / "docs/04-性能与基线对比.md"
s = doc.read_text(encoding="utf-8")
ph = "<!-- P6-TABLES:cipher_matrix（由 run_full_bench.py --parts tables 生成后粘贴） -->"
if ph in s:
    s = s.replace(ph, section + "\n\n（上表由 run_full_bench.py --parts tables "
                                "自动生成并注入——禁止手抄数字，D8）")
    doc.write_text(s, encoding="utf-8")
    print("docs/04 cipher_matrix table injected")
else:
    already = "自动生成并注入" in s
    print("placeholder missing" if not already else "already injected")
