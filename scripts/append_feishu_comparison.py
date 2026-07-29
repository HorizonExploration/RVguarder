#!/usr/bin/env python3
"""Append comparison and future direction sections to Feishu document."""
import requests, json, time

with open('/home/yosoro126/.openclaw/openclaw.json') as f:
    cfg = json.load(f)
APP_ID = cfg['channels']['feishu']['appId']
APP_SECRET = cfg['channels']['feishu']['appSecret']

resp = requests.post("https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal",
    json={"app_id": APP_ID, "app_secret": APP_SECRET}, timeout=10)
token = resp.json()["tenant_access_token"]
headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
doc_token = "Z0g8drLN0oswSZxxViVcmm65ngd"

def txt(content, bold=False):
    """Simple text block."""
    return {
        "block_type": 2,
        "text": {
            "elements": [{"text_run": {"content": content, "text_element_style": {"bold": bold}}}],
            "style": {}
        }
    }

def h2(content):
    return {
        "block_type": 4,
        "heading2": {
            "elements": [{"text_run": {"content": content, "text_element_style": {"bold": True}}}],
            "style": {}
        }
    }

def h3(content):
    return {
        "block_type": 5,
        "heading3": {
            "elements": [{"text_run": {"content": content, "text_element_style": {"bold": True}}}],
            "style": {}
        }
    }

def h4(content):
    return {
        "block_type": 6,
        "heading4": {
            "elements": [{"text_run": {"content": content, "text_element_style": {"bold": True}}}],
            "style": {}
        }
    }

def div():
    return {"block_type": 22, "divider": {}}

# Bullet points as text blocks with "• " prefix
def bul(content):
    return txt("\u2022 " + content)

def empty():
    return txt("")

# ===== Build all blocks =====
blocks = []

# === SECTION: Comparison ===
blocks.append(h2("OpenClaw-RVGuarder vs Guardrail \u5bf9\u6bd4\u5206\u6790"))
blocks.append(empty())

# 一、定位与设计理念
blocks.append(h3("\u4e00\u3001\u5b9a\u4f4d\u4e0e\u8bbe\u8ba1\u7406\u5ff5"))
blocks.append(txt("Guardrail\uff08\u4ee5 Invariant Labs \u4e3a\u4ee3\u8868\uff09\uff1a", bold=True))
blocks.append(bul("\u5b9a\u4f4d\u662f\u901a\u7528 LLM Agent \u5b89\u5168\u9632\u62a4\u5c42\uff0c\u9762\u5411\u4efb\u4f55 LLM \u5e94\u7528"))
blocks.append(bul("\u6838\u5fc3\u673a\u5236\uff1a\u5728 LLM \u8c03\u7528\u524d\u63d2\u5165 Policy Services \u5c42\uff0c\u5bf9 Trace \u8fdb\u884c\u89c4\u5219\u68c0\u67e5"))
blocks.append(bul("\u7279\u5f81\uff1a\u4e0e\u5177\u4f53\u5e73\u53f0\u89e3\u8026\uff0c\u9002\u7528\u4e8e\u591a\u79cd Agent \u6846\u67b6"))
blocks.append(txt("OpenClaw-RVGuarder\uff08\u672c\u9879\u76ee\uff09\uff1a", bold=True))
blocks.append(bul("\u5b9a\u4f4d\u662f OpenClaw \u4e13\u5c5e\u7684\u975e\u4fb5\u5165\u5f0f\u5b89\u5168\u589e\u5f3a\u5ba2\u6237\u7aef"))
blocks.append(bul("\u6838\u5fc3\u673a\u5236\uff1a\u901a\u8fc7 OpenClaw \u539f\u751f Hook \u63a5\u5165 before_tool_call / after_tool_call"))
blocks.append(bul("\u7279\u5f81\uff1a\u6df1\u5ea6\u7ed1\u5b9a OpenClaw \u751f\u6001\uff0c\u5b8c\u6574\u95ed\u73af"))
blocks.append(empty())
blocks.append(txt("\u6838\u5fc3\u5dee\u5f02\uff1aGuardrail \u662f\u901a\u7528\u9632\u62a4\u5c42\uff08\u504f\u7b56\u7565\u5f15\u64ce\uff09\uff0cRVGuard \u662f\u9762\u5411\u7279\u5b9a\u5e73\u53f0\u7684\u6df1\u5ea6\u5b89\u5168\u63d2\u4ef6\uff08\u504f\u5168\u94fe\u8def\u6cbb\u7406\uff09\u3002"))

# 二、架构对比
blocks.append(h3("\u4e8c\u3001\u67b6\u6784\u5bf9\u6bd4"))
blocks.append(txt("Guardrail \u67b6\u6784\uff1a", bold=True))
blocks.append(bul("User \u2192 Gateway \u2192 API \u2192 Analysis / Policy Services \u2192 LLM"))
blocks.append(bul("\u5728 LLM \u8c03\u7528\u5c42\u4e0a\u6e38\u505a\u89c4\u5219\u68c0\u67e5"))
blocks.append(bul("\u89c4\u5219\u7531\u5f00\u53d1\u8005\u9884\u5b9a\u4e49\uff0c\u4ee5 DSL \u6216 JSON \u8868\u8fbe"))
blocks.append(txt("RVGuard \u67b6\u6784\uff1a", bold=True))
blocks.append(bul("User \u2192 OpenClaw \u2192 Guard Hook \u2192 SemanticEnhancer \u2192 DetectionEngine \u2192 RuntimeVerificationEngine \u2192 GuardController \u2192 \u6267\u884c/\u963b\u65ad"))
blocks.append(bul("\u6df1\u5ea6\u5d4c\u5165 OpenClaw \u5de5\u5177\u8c03\u7528\u8def\u5f84"))
blocks.append(bul("\u4e09\u5c42\u51b3\u7b56\uff1a\u8bed\u4e49\u5c42 + \u89c4\u5219\u5c42\uff0847\u6761\uff09+ RV\u5c42\uff086\u4e2a FSM \u76d1\u89c6\u5668\uff09"))

# 三、安全能力对比
blocks.append(h3("\u4e09\u3001\u5b89\u5168\u80fd\u529b\u5bf9\u6bd4"))
blocks.append(empty())
blocks.append(txt("\u3010\u5355\u6b65\u89c4\u5219\u68c0\u6d4b\u3011", bold=True))
blocks.append(bul("Guardrail: \u2705 \u652f\u6301\uff0c\u57fa\u4e8e\u9884\u5b9a\u4e49\u89c4\u5219"))
blocks.append(bul("RVGuard: \u2705 \u652f\u6301\uff0c47\u6761\u8bed\u4e49\u6807\u7b7e\u89c4\u5219 + 5\u6761\u529e\u516c\u7b56\u7565"))
blocks.append(txt("\u3010\u8bed\u4e49\u7406\u89e3\u3011", bold=True))
blocks.append(bul("Guardrail: \u274c \u4e3b\u8981\u4f9d\u8d56\u5173\u952e\u8bcd/\u6b63\u5219\u5339\u914d"))
blocks.append(bul("RVGuard: \u2705 \u53cc\u6a21\u5f0f\uff08LLM + \u672c\u5730\u89c4\u5219\u5316\u964d\u7ea7\uff09\uff0c7\u7ef4\u5ea6\u6807\u7b7e\u4f53\u7cfb"))
blocks.append(txt("\u3010\u94fe\u5f0f/\u65f6\u5e8f\u68c0\u6d4b\u3011", bold=True))
blocks.append(bul("Guardrail: \u274c \u5355\u6b65\u72ec\u7acb\u5224\u5b9a\uff0c\u65e0\u6cd5\u68c0\u6d4b\u8de8\u6b65\u9aa4\u7ec4\u5408\u653b\u51fb"))
blocks.append(bul("RVGuard: \u2705 \u6ed1\u52a8\u7a97\u53e3 + 6\u4e2a FSM \u76d1\u89c6\u5668\uff0c\u652f\u6301\u591a\u79cd\u65f6\u5e8f\u6a21\u5f0f"))
blocks.append(txt("\u3010\u7ea6\u675f\u4fdd\u771f\u3011", bold=True))
blocks.append(bul("Guardrail: \u274c \u4e0d\u9a8c\u8bc1\u81ea\u7136\u8bed\u8a00\u7ea6\u675f\u662f\u5426\u4fdd\u7559"))
blocks.append(bul("RVGuard: \u2705 \u8bed\u4e49\u5c42\u63d0\u53d6\u7ea6\u675f\uff0c\u7f3a\u5931\u65f6\u81ea\u52a8\u5347\u7ea7 ask"))
blocks.append(txt("\u3010\u57fa\u7ebf\u626b\u63cf\u4e0e\u5ba1\u8ba1\u3011", bold=True))
blocks.append(bul("Guardrail: \u274c \u4e0d\u63d0\u4f9b"))
blocks.append(bul("RVGuard: \u2705 SQLite + JSONL \u53cc\u5199 + \u54c8\u5e0c\u94fe\u4fdd\u62a4 + \u5bfc\u51fa"))
blocks.append(txt("\u3010\u7528\u6237\u5ba1\u6279\u5de5\u4f5c\u53f0\u3011", bold=True))
blocks.append(bul("Guardrail: \u274c \u65e0\u524d\u7aef\u754c\u9762"))
blocks.append(bul("RVGuard: \u2705 \u672c\u5730 Web \u5de5\u4f5c\u53f0\uff0c\u652f\u6301\u52a8\u4f5c\u5ba1\u6279\u3001Trace Timeline"))
blocks.append(txt("\u3010\u975e\u4fb5\u5165\u6027\u3011", bold=True))
blocks.append(bul("Guardrail: \u2705 \u4e0d\u4fee\u6539\u4e0b\u6e38\u4ee3\u7801"))
blocks.append(bul("RVGuard: \u2705 \u4e0d\u4fee\u6539 OpenClaw \u6e90\u7801\uff0c\u901a\u8fc7 Hook \u63a5\u5165"))

# 四、钓鱼邮件场景对比
blocks.append(h3("\u56db\u3001\u5178\u578b\u653b\u51fb\u573a\u666f\u5bf9\u6bd4\u2014\u2014\u9493\u9c7c\u90ae\u4ef6"))
blocks.append(txt("\u5728\u9690\u853d\u6307\u4ee4\u6ce8\u5165\u7684\u9493\u9c7c\u90ae\u4ef6\u573a\u666f\u4e2d\uff1a"))
blocks.append(bul("Guardrail\uff1a\u6bcf\u6b65\u72ec\u7acb\u5224\u5b9a ALLOW/ASK\uff0c\u7528\u6237\u786e\u8ba4\u540e\u6570\u636e\u4ecd\u6cc4\u9732"))
blocks.append(bul("RVGuard\uff1a\u8bed\u4e49\u5c42\u6807\u8bb0\u4e0d\u53ef\u4fe1\u6765\u6e90 + \u68c0\u6d4b\u654f\u611f\u6570\u636e \u2192 RV \u68c0\u6d4b\u65f6\u5e8f\u6a21\u5f0f \u2192 \u81ea\u52a8 BLOCK"))
blocks.append(empty())
blocks.append(txt("\u7ed3\u8bba\uff1aRVGuard \u7684\u65f6\u5e8f\u68c0\u6d4b\u5728\u94fe\u5f0f\u653b\u51fb\u573a\u666f\u4e0b\u5177\u6709\u672c\u8d28\u6027\u5b89\u5168\u4f18\u52bf\u3002"))

# === SECTION: Future Direction ===
blocks.append(div())

blocks.append(h2("\u672a\u6765\u53d1\u5c55\u65b9\u5411"))
blocks.append(empty())

blocks.append(h3("\u8fd1\u671f\uff081-2\u4e2a\u6708\uff09"))
blocks.append(bul("P0 \u573a\u666f\u5168\u91cf\u8986\u76d6\uff1a\u6d88\u606f\u7fa4\u53d1\u3001\u6570\u636e\u5e93\u5bfc\u51fa\u3001\u6587\u4ef6\u6279\u91cf\u64cd\u4f5c\u7684\u89c4\u5219\u5b8c\u5584\u4e0e\u6d4b\u8bd5"))
blocks.append(bul("\u5ba1\u8ba1\u5b58\u50a8\u91cd\u6784\uff1a\u52a8\u4f5c\u5b58\u50a8\u8fc1\u79fb\u5230 SQLite \u8868\uff0c\u7edf\u4e00\u54c8\u5e0c\u94fe\u4fdd\u62a4"))
blocks.append(bul("\u524d\u7aef\u9875\u9762\u8865\u9f50\uff1a\u5b89\u5168\u89c4\u5219\u7ba1\u7406\u9875\u9762\u3001\u5206\u9875/\u65e0\u9650\u6eda\u52a8"))
blocks.append(bul("P1 \u573a\u666f\u5f00\u53d1\uff1a\u6587\u6863\u5916\u53d1\u3001\u4ee3\u63d0\u4ea4\u5ba1\u6279\u3001\u4ee3\u7801\u63a8\u9001\u7b49 6 \u4e2a\u573a\u666f\u76d1\u89c6\u5668"))
blocks.append(bul("\u4f9d\u8d56\u58f0\u660e\u5b8c\u5584\uff1apyproject.toml \u4e2d\u5b8c\u6574\u58f0\u660e Python \u4f9d\u8d56"))

blocks.append(h3("\u4e2d\u671f\uff083-6\u4e2a\u6708\uff09"))
blocks.append(bul("\u7528\u6237\u81ea\u5b9a\u4e49\u89c4\u5219\uff1a\u81ea\u7136\u8bed\u8a00\u89c4\u5219 \u2192 LLM \u63d0\u53d6 \u2192 \u7528\u6237\u786e\u8ba4 \u2192 policies/"))
blocks.append(bul("Back-Translation \u9a8c\u8bc1\uff1aTrace \u53cd\u5411\u91cd\u5199\u4e0e\u539f\u59cb\u8f93\u5165\u5bf9\u6bd4"))
blocks.append(bul("DSL \u8bed\u6cd5\u8bbe\u8ba1\uff1a\u4ece JSON \u89c4\u5219\u6a21\u677f\u8fc7\u6e21\u5230\u8f7b\u91cf DSL"))
blocks.append(bul("\u79bb\u7ebf\u589e\u5f3a RV\uff1a\u63a5\u5165 Spot \u505a LTL \u516c\u5f0f\u6821\u9a8c"))
blocks.append(bul("\u591a Agent \u534f\u4f5c\uff1a\u8de8 Agent Trace \u8054\u5408\u65f6\u5e8f\u9a8c\u8bc1"))

blocks.append(h3("\u8fdc\u671f\uff086-12\u4e2a\u6708\uff09"))
blocks.append(bul("\u81ea\u9002\u5e94\u89c4\u5219\u5b66\u4e60\uff1aRV \u547d\u4e2d\u8fdd\u89c4\u65f6\u81ea\u52a8\u62bd\u53d6\u5171\u6027\u6a21\u5f0f"))
blocks.append(bul("\u9f99\u867e\u76d2\u5b50\u539f\u751f\u96c6\u6210\uff1a\u4f5c\u4e3a OpenClaw \u786c\u4ef6\u9884\u88c5\u5b89\u5168\u7ec4\u4ef6"))
blocks.append(bul("\u793e\u533a\u89c4\u5219\u5e02\u573a\uff1a\u7528\u6237\u5206\u4eab/\u4e0b\u8f7d\u529e\u516c\u573a\u666f\u5b89\u5168\u89c4\u5219\u5305"))
blocks.append(bul("\u591a\u5e73\u53f0\u652f\u6301\uff1a\u4ece OpenClaw \u6269\u5c55\u5230 LangChain\u3001AutoGPT \u7b49"))
blocks.append(bul("\u5f62\u5f0f\u5316\u9a8c\u8bc1\u62a5\u544a\uff1a\u6bcf\u6b21\u6267\u884c\u540e\u751f\u6210 Trace \u7ea7\u522b\u8bc1\u660e"))

blocks.append(div())
blocks.append(txt("RVGuard \u7684\u76ee\u6807\u4e0d\u662f\u66ff\u6362 Guardrail\uff0c\u800c\u662f\u5728\u5176\u901a\u7528\u7b56\u7565\u5c42\u4e4b\u4e0a\uff0c\u6784\u5efa\u4e00\u5c42\u9762\u5411\u7279\u5b9a\u5e73\u53f0\u7684\u6df1\u5ea6\u5b89\u5168\u6cbb\u7406\u5c42\u2014\u2014\u4ece\u7b56\u7565\u5230\u6267\u884c\u3001\u5355\u6b65\u5230\u65f6\u5e8f\u3001\u68c0\u6d4b\u5230\u5ba1\u8ba1\u7684\u5b8c\u6574\u95ed\u73af\u3002"))

# ===== Send batches =====
BATCH_SIZE = 15
total_sent = 0
for i in range(0, len(blocks), BATCH_SIZE):
    batch = blocks[i:i+BATCH_SIZE]
    body = {"children": batch, "index": -1}
    r = requests.post(
        f"https://open.feishu.cn/open-apis/docx/v1/documents/{doc_token}/blocks/{doc_token}/children",
        headers=headers, json=body, timeout=15
    )
    result = r.json()
    if result.get("code") != 0:
        print(f"Batch {i//BATCH_SIZE} FAILED: {result}")
    else:
        total_sent += len(batch)
        print(f"Batch {i//BATCH_SIZE} OK: {len(batch)} blocks (total: {total_sent})")
    time.sleep(0.3)

print(f"\n{'='*50}")
print(f"Done! {total_sent} blocks written to document.")
print(f"URL: https://hcnpg2mrjajh.feishu.cn/wiki/L1fewiHW4i0qcHk1vwbcCJdJnPb")
