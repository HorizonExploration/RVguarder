#!/usr/bin/env python3
"""
OpenClaw Guard v0.2.0 AgentDojo 重测脚本

从 v0.1.0 AgentDojo 原始数据中提取 309 条测试用例，
用当前 Guard API 重测，生成端到端对比报告。
"""
import json
import time
import urllib.request
import urllib.error
import sys
from datetime import datetime
from pathlib import Path

GUARD_URL = "http://127.0.0.1:8780"
API_INGEST = f"{GUARD_URL}/api/actions/ingest"
API_HEALTH = f"{GUARD_URL}/api/health"
SCRIPT_DIR = Path(__file__).resolve().parent.parent
OUTPUT_DIR = SCRIPT_DIR / "实验结果"
OLD_DATA_PATH = OUTPUT_DIR / "agentdojo-原始数据_20260602_214829.json"
REQUEST_TIMEOUT = 60
REQUEST_DELAY = 0.05

def guard_ok():
    try:
        req = urllib.request.Request(API_HEALTH)
        with urllib.request.urlopen(req, timeout=5) as _:
            return True
    except Exception:
        return False

def ingest(message):
    payload = json.dumps({
        "action_type": "chat_message", "process_name": "openclaw",
        "user": "tester", "raw_user_intent": message,
        "source": "agentdojo-eval",
    }).encode("utf-8")
    req = urllib.request.Request(API_INGEST, data=payload,
        headers={"Content-Type": "application/json"}, method="POST")
    start = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            r = json.loads(resp.read().decode())
            r["_t"] = round(time.perf_counter() - start, 4)
            return r
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        return {"ok": False, "status": "error", "_t": round(time.perf_counter() - start, 4), "_http": e.code, "error": body[:200]}
    except Exception as e:
        return {"ok": False, "status": "error", "_t": round(time.perf_counter() - start, 4), "error": str(e)[:200]}

def classify(raw):
    dec = raw.get("decision")
    if isinstance(dec, dict):
        a = dec.get("action", "")
        if a in ("block",): return "block"
        if a in ("ask", "escalate"): return "ask"
        if a == "allow": return "allow"
    s = raw.get("status", "")
    if s == "blocked": return "block"
    if s in ("pending_approval",): return "ask"
    if s == "executed": return "allow"
    return "allow"

def extract_rules(raw):
    dec = raw.get("decision")
    if isinstance(dec, dict):
        r = dec.get("rule_ids", [])
        return r if isinstance(r, list) else []
    return []

def extract_semantic(raw):
    ev = raw.get("event") or {}
    md = ev.get("metadata") or {}
    return md.get("semantic") or {}

print("=" * 70)
print("  OpenClaw Guard v0.2.0 AgentDojo 重测")
print("  对比基线: v0.1.0 (2026-06-02, 309 cases)")
print("=" * 70)

if not guard_ok():
    print("[错误] Guard 不可达 http://127.0.0.1:8780")
    sys.exit(1)
print("[OK] Guard 运行正常\n")

print(f"加载旧实验数据: {OLD_DATA_PATH}")
with open(OLD_DATA_PATH) as f:
    old_data = json.load(f)
old_results = old_data.get("results", [])
print(f"  共 {len(old_results)} 条测试用例\n")

print("开始执行测试（可能耗时较长，请耐心等待）")
print("=" * 70)

new_results = []
total = len(old_results)
start_ts = time.perf_counter()

for i, old_case in enumerate(old_results, 1):
    msg = old_case["message"]
    cid = old_case["case_id"]
    atk = old_case["attack_type"]
    suite = old_case["suite"]
    expected = old_case["expected_allowed"]

    resp = ingest(msg)
    dec = classify(resp)
    rules = extract_rules(resp)
    sem = extract_semantic(resp)
    rt = resp.get("_t", 0)

    is_block = dec in ("block", "ask")
    correct = (is_block and not expected) or (not is_block and expected)
    mark = "✓" if correct else "✗"

    elapsed_total = time.perf_counter() - start_ts
    eta = (elapsed_total / i) * (total - i) if i > 0 else 0

    prefix = f"[{i:3d}/{total}]"
    print(f"  {prefix} [{suite:9s}] [{atk:40s}] {dec.upper():6s} {mark} ({rt:.3f}s) ETA:{eta:.0f}s")

    new_results.append({
        "case_id": cid, "suite": suite, "attack_type": atk,
        "message": msg, "expected_allowed": expected,
        "decision": dec, "matched_rules": rules,
        "semantic_scenario": sem.get("scenario", ""),
        "semantic_labels": sem.get("labels", []),
        "response_time_s": rt, "is_correct": correct,
    })

    if REQUEST_DELAY > 0:
        time.sleep(REQUEST_DELAY)

# 统计
total_time = time.perf_counter() - start_ts
print(f"\n{'='*70}")
print(f"  实验完成！耗时 {total_time:.0f}s")
print(f"{'='*70}")

# 汇总统计
decisions = {}
for r in new_results:
    decisions[r["decision"]] = decisions.get(r["decision"], 0) + 1

block_count = decisions.get("block", 0) + decisions.get("ask", 0)
correct_count = sum(1 for r in new_results if r["is_correct"])
fn_count = sum(1 for r in new_results if r["decision"] == "allow" and not r["expected_allowed"])
fp_count = sum(1 for r in new_results if r["decision"] in ("block", "ask") and r["expected_allowed"])
times = sorted([r["response_time_s"] for r in new_results])

# 按套件
by_suite = {}
for r in new_results:
    by_suite.setdefault(r["suite"], []).append(r)

# 按攻击类型
by_type = {}
for r in new_results:
    by_type.setdefault(r["attack_type"], []).append(r)

timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
results_file = OUTPUT_DIR / f"agentdojo-v0.2.0-重测数据_{timestamp}.json"
report_file = OUTPUT_DIR / f"agentdojo-v0.2.0-对比报告_{timestamp}.md"

with open(results_file, "w", encoding="utf-8") as f:
    json.dump({"results": new_results, "summary": {
        "total": total, "decisions": decisions,
        "interception_rate": round(block_count/total*100, 2),
        "hard_block_rate": round(decisions.get("block",0)/total*100, 2),
        "accuracy": round(correct_count/total*100, 2),
        "fn": fn_count, "fp": fp_count,
        "avg_time": round(sum(times)/len(times), 4),
        "p50": round(times[len(times)//2], 4),
        "p95": round(times[int(len(times)*0.95)], 4),
        "max_time": round(times[-1], 4),
        "min_time": round(times[0], 4),
    }}, f, ensure_ascii=False, indent=2)
print(f"[保存] {results_file.name}")

# ======= 报告 =======
lines = []
lines.append("# OpenClaw Guard v0.2.0 × AgentDojo 对比评测报告\n")
lines.append(f"**实验时间**: {datetime.now().isoformat()}\n")
lines.append(f"**测试用例**: {total} 条 (复用 v0.1.0 AgentDojo 测试集)\n")
lines.append(f"**攻击类型**: 12 种 (含 baseline)\n")
lines.append(f"**对比基线**: v0.1.0 (2026-06-02)\n\n")

lines.append("---\n")
lines.append("## 1. 总体指标对比\n\n")
lines.append("| 指标 | v0.1.0 | v0.2.0 (本次) | 变化 |\n")
lines.append("| :--- | ---: | ---: | ---: |\n")

v1 = {"int": 36.25, "hard": 0.0, "allow": 63.75, "avg_t": 2.0097, "p50": 2.6198, "p95": 4.3663, "fn_rate": 46.9, "fp": 2}
v2i = round(block_count/total*100, 2)
v2h = round(decisions.get("block",0)/total*100, 2)
v2a = round(decisions.get("allow",0)/total*100, 2)
v2fnr = round(fn_count/total*100, 2)
v2t = round(sum(times)/len(times), 4)
v2p50 = round(times[len(times)//2], 4)
v2p95 = round(times[int(len(times)*0.95)], 4)

def d(v2, v1):
    d = round(v2-v1, 2)
    return f"+{d}" if d>0 else str(d)
def e(v2,v1):
    d = round(v2-v1, 2)
    if d>0: return f"+{d} ✅"
    elif d<0: return f"{d} ⚠️"
    return "0"

lines.append(f"| 总体拦截率 (block+ask) | {v1['int']}% | **{v2i}%** | {e(v2i, v1['int'])} |\n")
lines.append(f"| 强硬阻断率 (block) | {v1['hard']}% | **{v2h}%** | {e(v2h, v1['hard'])} |\n")
lines.append(f"| 放行率 (allow) | {v1['allow']}% | **{v2a}%** | {e(v2a, v1['allow'])} |\n")
lines.append(f"| 漏报率 (FN) | {v1['fn_rate']}% | **{v2fnr}%** | {e(v2fnr, v1['fn_rate'])} |\n")
lines.append(f"| 误报数 (FP) | {v1['fp']} | **{fp_count}** | {e(fp_count, v1['fp'])} |\n")
lines.append(f"| 综合准确率 | 53.07% | **{round(correct_count/total*100,2)}%** | {e(round(correct_count/total*100,2), 53.07)} |\n")
lines.append(f"| 平均耗时 | {v1['avg_t']}s | **{v2t}s** | {e(v2t, v1['avg_t'])} |\n\n")

lines.append("| 决策 | v0.1.0 | v0.2.0 |\n")
lines.append("| :--- | ---: | ---: |\n")
lines.append(f"| block | 0 | **{decisions.get('block',0)}** |\n")
lines.append(f"| ask | 112 | **{decisions.get('ask',0)}** |\n")
lines.append(f"| allow | 197 | **{decisions.get('allow',0)}** |\n\n")

lines.append("---\n")
lines.append("## 2. 按套件对比\n\n")
lines.append("| 套件 | v0.1.0 拦截率 | v0.2.0 拦截率 | 变化 |\n")
lines.append("| :--- | ---: | ---: | ---: |\n")
v1_suite = {"workspace": 57.73, "banking": 0.0}
for sn, group in sorted(by_suite.items()):
    gb = sum(1 for r in group if r["decision"] in ("block","ask"))
    gint = round(gb/len(group)*100, 2)
    v1s = v1_suite.get(sn, 0)
    lines.append(f"| {sn} | {v1s}% | **{gint}%** | {e(gint, v1s)} |\n")

lines.append("\n---\n")
lines.append("## 3. 按攻击类型对比\n\n")
lines.append("| 攻击类型 | 用例数 | v0.1.0 拦截 | v0.2.0 拦截 | block | ask | 变化 |\n")
lines.append("| :--- | ---: | ---: | ---: | ---: | ---: | ---: |\n")
for at, group in sorted(by_type.items()):
    gb = sum(1 for r in group if r["decision"] in ("block","ask"))
    gblock = sum(1 for r in group if r["decision"]=="block")
    gask = sum(1 for r in group if r["decision"]=="ask")
    gint = round(gb/len(group)*100, 2)
    lines.append(f"| {at} | {len(group)} | 43.48% | **{gint}%** | {gblock} | {gask} | {e(gint, 43.48)} |\n")

lines.append("\n---\n")
lines.append("## 4. 语义能力评估（v0.2.0 新能力）\n\n")
sem_cnt = sum(1 for r in new_results if r.get("semantic_scenario"))
lines.append(f"| 指标 | 数值 |\n")
lines.append(f"| :--- | ---: |\n")
lines.append(f"| 语义场景产出率 | {round(sem_cnt/total*100,1)}% |\n")
scenes = {}
for r in new_results:
    s = r.get("semantic_scenario","")
    if s: scenes[s] = scenes.get(s,0)+1
if scenes:
    lines.append("\n**Top 语义场景**\n\n")
    lines.append("| 场景 | 命中次数 |\n")
    lines.append("| :--- | ---: |\n")
    for s, c in sorted(scenes.items(), key=lambda x:x[1], reverse=True)[:10]:
        lines.append(f"| {s} | {c} |\n")

lines.append("\n---\n")
lines.append("## 5. 漏报明细（危险操作未被拦截）\n\n")
fn_items = [r for r in new_results if r["decision"]=="allow" and not r["expected_allowed"]]
if fn_items:
    lines.append(f"共 {len(fn_items)} 条：\n\n")
    lines.append("| 用例 ID | 攻击类型 | 消息摘要 |\n")
    lines.append("| :--- | :--- | :--- |\n")
    for r in fn_items[:20]:
        msg_short = r["message"][:80].replace("\n"," ")
        lines.append(f"| {r['case_id']} | {r['attack_type']} | {msg_short} |\n")
    if len(fn_items) > 20:
        lines.append(f"| ... | ... | (剩余 {len(fn_items)-20} 条) |\n")
else:
    lines.append("**无漏报**\n")

lines.append("\n## 6. 误报明细（正常任务被误拦截）\n\n")
fp_items = [r for r in new_results if r["decision"] in ("block","ask") and r["expected_allowed"]]
if fp_items:
    lines.append(f"共 {len(fp_items)} 条：\n\n")
    lines.append("| 用例 ID | 消息摘要 | 决策 |\n")
    lines.append("| :--- | :--- | :--- |\n")
    for r in fp_items[:10]:
        msg_short = r["message"][:80].replace("\n"," ")
        lines.append(f"| {r['case_id']} | {msg_short} | {r['decision']} |\n")
    if len(fp_items) > 10:
        lines.append(f"| ... | (剩余 {len(fp_items)-10} 条) |\n")
else:
    lines.append("**无误报**\n")

lines.append("\n---\n")
lines.append("## 7. 性能分析\n\n")
lines.append("| 指标 | v0.1.0 | v0.2.0 |\n")
lines.append("| :--- | ---: | ---: |\n")
lines.append(f"| 最小耗时 | 0.0118s | {times[0]:.4f}s |\n")
lines.append(f"| 最大耗时 | 7.8427s | {times[-1]:.4f}s |\n")
lines.append(f"| 平均耗时 | {v1['avg_t']}s | {v2t}s |\n")
lines.append(f"| P50 | {v1['p50']}s | {v2p50}s |\n")
lines.append(f"| P95 | {v1['p95']}s | {v2p95}s |\n")

lines.append(f"\n---\n*报告生成: {datetime.now().isoformat()}*\n")

with open(report_file, "w", encoding="utf-8") as f:
    f.writelines(lines)
print(f"[保存] {report_file.name}")
print(f"\n{'='*70}")
print(f"  产物:")
print(f"    - 原始数据: {results_file.name}")
print(f"    - 对比报告: {report_file.name}")
print(f"{'='*70}")
