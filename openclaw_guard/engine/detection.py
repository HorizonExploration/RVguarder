"""
detection.py 职责：单步、无上下文的快速风险判定。

- 关键词/路径匹配的硬阻断规则（47 条 semantic predicate 规则）
- 不需要跨事件上下文的简单 office policy
- 作为第一道防线，延迟 < 1ms

rv_monitors.py 职责：跨步、有状态、有时序的链式风险判定。
- 需要追踪 Agent 行为序列的攻击模式（如"外部来源→敏感数据→外发"链）
- 依赖 transitions FSM 状态记忆 + WindowManager 统计增强
- 作为第二道防线，延迟 < 5ms
- SEM-OFFICE-001/002（mail_send/report_send 链式外发）已迁移至 MailMonitor/ReportMonitor

分工约定：
- 单步硬阻断（如 rm -rf、写入 SSH 密钥） → detection.py
- 链式攻击（如"搜索→删除"、"外部源→敏感→外发"） → rv_monitors.py
- RV 判定高于 detection 时可覆盖其决策（_apply_rv_if_available）
"""
from __future__ import annotations

from typing import Iterable

from openclaw_guard.engine.semantic_enhancer import SemanticEnhancer
from openclaw_guard.models import BehaviorEvent, DetectionDecision, DetectionRule
from openclaw_guard.utils import utc_now_iso


def builtin_rules() -> list[DetectionRule]:
    rules: list[DetectionRule] = []
    def add(rule_id: str, title: str, description: str, action_types: list[str], severity: str, risk: str, decision: str, *, match_labels: list[str] | None = None) -> None:
        rules.append(
            DetectionRule(
                rule_id=rule_id,
                title=title,
                description=description,
                action_types=action_types,
                severity=severity,
                risk_level=risk,
                decision=decision,
                match_labels=match_labels or [],
            )
        )

    # 47 rules grouped by type.
    add("CMD-001", "阻断 rm -rf", "递归强删默认阻断。", ["command_exec"], "critical", "blocked", "block", match_labels=["command_rm_rf"])
    add("CMD-002", "阻断 curl 管道执行", "curl|sh 供应链风险。", ["command_exec"], "critical", "blocked", "block", match_labels=["command_pipe_curl_sh"])
    add("CMD-003", "阻断 wget 管道执行", "wget|bash 供应链风险。", ["command_exec"], "critical", "blocked", "block", match_labels=["command_pipe_wget_bash"])
    add("CMD-004", "升级 sudo", "提权命令需要二次确认。", ["command_exec"], "high", "dangerous", "escalate", match_labels=["command_sudo"])
    add("CMD-005", "升级 ssh", "远程连接命令需要二次确认。", ["command_exec"], "high", "dangerous", "escalate", match_labels=["command_ssh"])
    add("CMD-006", "升级 scp", "远程复制命令需要二次确认。", ["command_exec"], "high", "dangerous", "escalate", match_labels=["command_scp"])
    add("CMD-007", "确认 chmod", "权限变更命令需要审批。", ["command_exec"], "high", "dangerous", "ask", match_labels=["command_chmod"])
    add("CMD-008", "确认 chown", "属主变更命令需要审批。", ["command_exec"], "high", "dangerous", "ask", match_labels=["command_chown"])
    add("CMD-009", "确认 mv", "批量移动命令可能影响证据链。", ["command_exec"], "medium", "caution", "ask", match_labels=["command_mv"])
    add("CMD-010", "确认 rm", "普通删除命令需要审批。", ["command_exec"], "high", "dangerous", "ask", match_labels=["command_rm"])
    add("FILE-001", "阻断系统目录删除", "系统目录删除默认阻断。", ["file_delete"], "critical", "blocked", "block", match_labels=["path_system_root"])
    add("FILE-002", "阻断敏感凭据目录删除", "删除 SSH/云凭据目录会破坏凭据。", ["file_delete"], "critical", "blocked", "block", match_labels=["path_sensitive_creds"])
    add("FILE-003", "确认工作区外删除", "工作区外删除需要审批。", ["file_delete"], "high", "dangerous", "ask", match_labels=["outside_workspace"])
    add("FILE-004", "确认日志删除", "删除日志会影响取证。", ["file_delete"], "high", "dangerous", "ask", match_labels=["path_log"])
    add("FILE-005", "确认证据目录删除", "证据目录删除需要审批。", ["file_delete"], "critical", "dangerous", "escalate", match_labels=["path_high_value"])
    add("FILE-006", "阻断配置覆盖", "覆盖 openclaw.json 默认阻断。", ["config_modify"], "critical", "blocked", "block", match_labels=["path_openclaw_config"])
    add("FILE-007", "确认工作区外写入", "写入工作区外文件需要审批。", ["file_write"], "high", "dangerous", "ask", match_labels=["outside_workspace"])
    add("FILE-008", "确认脚本写入", "写入脚本文件需要审批。", ["file_write"], "high", "dangerous", "ask", match_labels=["path_script"])
    add("FILE-009", "阻断敏感凭据写入", "写入 SSH/API 凭据默认阻断。", ["file_write"], "critical", "blocked", "block", match_labels=["path_sensitive_creds"])
    add("FILE-010", "确认批量写入", "多目标写入需要审批。", ["file_write"], "medium", "caution", "ask", match_labels=["multi_target"])
    add("NET-001", "确认外部 HTTP 访问", "外部网络访问需要审批。", ["network_egress"], "high", "caution", "ask", match_labels=["network_http"])
    add("NET-002", "阻断未知公网 IP", "未知公网目标默认阻断。", ["network_egress"], "critical", "blocked", "block", match_labels=["network_public_ip"])
    add("NET-003", "升级 webhook", "Webhook 发送需要二次确认。", ["network_egress"], "high", "dangerous", "escalate", match_labels=["network_webhook"])
    add("NET-004", "确认上传", "外传关键词触发审批。", ["network_egress"], "high", "dangerous", "ask", match_labels=["network_upload"])
    add("NET-005", "阻断敏感外传", "携带凭据外发默认阻断。", ["network_egress"], "critical", "blocked", "block", match_labels=["network_secret_payload"])
    add("NET-006", "确认代理切换", "修改代理出口需要审批。", ["network_egress"], "medium", "caution", "ask", match_labels=["network_proxy"])
    add("API-001", "确认危险 API", "危险 API 调用需要审批。", ["channel_send"], "high", "dangerous", "ask", match_labels=["channel_external_send"])
    add("API-002", "阻断敏感 API", "敏感 API 越权默认阻断。", ["channel_send"], "critical", "blocked", "block", match_labels=["channel_admin"])
    add("API-003", "确认通道发送", "跨渠道发送需要审批。", ["channel_send"], "high", "caution", "ask", match_labels=["channel_present"])
    add("API-004", "升级群发", "批量发送需要二次确认。", ["channel_send"], "high", "dangerous", "escalate", match_labels=["bulk_send"])
    add("SKL-001", "确认 shell skill", "Shell 型 skill 需要审批。", ["skill_run"], "high", "dangerous", "ask", match_labels=["skill_shell"])
    add("SKL-002", "确认 network skill", "具备外联能力的 skill 需要审批。", ["skill_run"], "high", "dangerous", "ask", match_labels=["skill_network"])
    add("SKL-003", "确认 delete skill", "具备删除能力的 skill 需要审批。", ["skill_run"], "high", "dangerous", "ask", match_labels=["skill_delete"])
    add("SKL-004", "确认 write skill", "具备写入能力的 skill 需要审批。", ["skill_run"], "high", "dangerous", "ask", match_labels=["skill_write"])
    add("SKL-005", "阻断持久化 skill", "自启动/守护能力默认阻断。", ["skill_run"], "critical", "blocked", "block", match_labels=["skill_persistence"])
    add("SKL-006", "升级系统管理 skill", "系统管理类 skill 需二次确认。", ["skill_run"], "high", "dangerous", "escalate", match_labels=["skill_system_admin"])
    add("CFG-001", "确认配置修改", "修改 OpenClaw 关键配置需要审批。", ["config_modify"], "high", "dangerous", "ask", match_labels=["config_provider_change"])
    add("CFG-002", "阻断鉴权关闭", "关闭鉴权默认阻断。", ["config_modify"], "critical", "blocked", "block", match_labels=["config_auth_disable"])
    add("CFG-003", "确认审批绕过", "绕过审批配置需要审批。", ["config_modify"], "high", "dangerous", "ask", match_labels=["config_bypass"])
    add("CFG-004", "确认沙箱关闭", "关闭沙箱需要审批。", ["config_modify"], "high", "dangerous", "ask", match_labels=["config_sandbox_disable"])
    add("CFG-005", "阻断日志关闭", "关闭审计日志默认阻断。", ["config_modify"], "critical", "blocked", "block", match_labels=["config_audit_disable"])
    add("GEN-001", "确认未解析删除", "删除动作未解析目标路径时先审批。", ["file_delete"], "high", "dangerous", "ask", match_labels=["unparsed_target"])
    add("GEN-002", "确认未解析写入", "写入动作未解析目标路径时先审批。", ["file_write"], "high", "dangerous", "ask", match_labels=["unparsed_target"])
    add("GEN-003", "确认未解析命令", "高危命令模糊时先审批。", ["command_exec"], "medium", "caution", "ask", match_labels=["command_delete_intent"])
    add("GEN-004", "确认未知外联", "未知外部连接先审批。", ["network_egress"], "high", "caution", "ask", match_labels=["network_unknown_external"])
    add("GEN-005", "升级高价值路径", "命中高价值路径需要二次确认。", ["file_delete", "file_write"], "critical", "dangerous", "escalate", match_labels=["path_high_value"])
    add("GEN-006", "阻断批量敏感操作", "一次命中多个敏感目标默认阻断。", ["file_delete", "file_write"], "critical", "blocked", "block", match_labels=["multi_target"])
    return rules


class DetectionEngine:
    def __init__(self, rules: Iterable[DetectionRule] | None = None) -> None:
        self.rules = list(rules or builtin_rules())
        self.semantic = SemanticEnhancer(api_key="")

    def evaluate(self, event: BehaviorEvent) -> DetectionDecision:
        semantic_payload = self._ensure_semantic_payload(event)
        labels = set(str(item) for item in semantic_payload["semantic"].get("labels", []))
        labels.update(_rv_props(semantic_payload))
        scenario = str(semantic_payload["semantic"].get("scenario") or event.action_type)
        trace: list[dict[str, object]] = [
            {
                "stage": "semantic",
                "scenario": scenario,
                "labels": sorted(labels),
            }
        ]

        office_decision = _office_decision(event, scenario, labels, trace)
        if office_decision is not None:
            return office_decision

        matched_rules = [
            rule
            for rule in self.rules
            if event.action_type in rule.action_types
            and all(label in labels for label in rule.match_labels)
        ]
        if matched_rules:
            matched_rule_ids = [rule.rule_id for rule in matched_rules]
            strongest = min(matched_rules, key=lambda item: ("blocked", "dangerous", "caution", "safe").index(item.risk_level))
            requires_second = strongest.decision == "escalate"
            return DetectionDecision(
                event_id=event.event_id,
                timestamp=utc_now_iso(),
                action_type=event.action_type,
                risk_level=strongest.risk_level,
                action=strongest.decision,
                reason=strongest.description,
                rule_ids=matched_rule_ids,
                trace=trace + [{"stage": "semantic_rules", "matches": matched_rule_ids}] + [{"stage": "decision", "outcome": strongest.decision, "rule_id": strongest.rule_id}],
                requires_second_confirmation=requires_second,
                confirmation_word="EXECUTE" if requires_second else None,
            )

        fallback = _fallback_decision(event, scenario=scenario, labels=labels)
        return DetectionDecision(
            event_id=event.event_id,
            timestamp=utc_now_iso(),
            action_type=event.action_type,
            risk_level=fallback["risk_level"],
            action=fallback["action"],
            reason=fallback["reason"],
            rule_ids=[],
            trace=trace + [{"stage": "default", "outcome": fallback["action"]}],
            requires_second_confirmation=bool(fallback.get("requires_second_confirmation")),
            confirmation_word=fallback.get("confirmation_word"),
        )

    def _ensure_semantic_payload(self, event: BehaviorEvent) -> dict[str, object]:
        semantic = event.metadata.get("semantic")
        rv_trace = event.metadata.get("rv_trace")
        if isinstance(semantic, dict) and isinstance(rv_trace, list):
            return {"semantic": semantic, "rv_trace": rv_trace}
        payload = self.semantic.evaluate(event, {"origin": "detector"})
        event.metadata["semantic"] = payload["semantic"]
        event.metadata["rv_trace"] = payload["rv_trace"]
        return payload


def _fallback_decision(event: BehaviorEvent, *, scenario: str | None = None, labels: set[str] | None = None) -> dict[str, object]:
    active_scenario = scenario or event.action_type
    signals = labels or set()
    if active_scenario == "chat_message":
        return {
            "risk_level": "safe",
            "action": "allow",
            "reason": "未命中高危规则，按低风险对话放行。",
        }
    if "command_readonly" in signals:
        return {
            "risk_level": "safe",
            "action": "allow",
            "reason": "检测为只读命令，按低风险动作放行。",
        }
    if active_scenario in {"mail_send", "report_send"}:
        return {
            "risk_level": "dangerous",
            "action": "ask",
            "reason": "外发类办公场景默认进入人工确认。",
        }
    if event.action_type in {"file_delete", "file_write", "config_modify", "network_egress", "channel_send", "skill_run"}:
        return {
            "risk_level": "dangerous",
            "action": "ask",
            "reason": "未命中明确规则，但该动作属于敏感操作，已转入人工确认。",
        }
    if event.action_type == "command_exec":
        return {
            "risk_level": "caution",
            "action": "ask",
            "reason": "命令执行未命中白名单规则，已转入人工确认。",
        }
    return {
        "risk_level": "safe",
        "action": "allow",
        "reason": "未命中高危规则，按低风险动作放行。",
    }


def _rv_props(payload: dict[str, object]) -> set[str]:
    props: set[str] = set()
    for item in payload.get("rv_trace", []):  # type: ignore[union-attr]
        if not isinstance(item, dict):
            continue
        for value in item.get("props", []):
            props.add(str(value))
    return props


def _office_decision(
    event: BehaviorEvent,
    scenario: str,
    labels: set[str],
    trace: list[dict[str, object]],
) -> DetectionDecision | None:
    # SEM-OFFICE-001 (mail_send + external + secret → block) 已迁移至 MailMonitor FSM
    # SEM-OFFICE-002 (report_send + external + internal_source → block) 已迁移至 ReportMonitor FSM
    # 原因：这两条规则本质上是跨步链式风险——需要确认"敏感数据是否来自外部源"
    #       或"日报是否聚合了内部源数据"。RV FSM 的状态记忆能更精确地建模此链路。
    # 保留规则：SEM-OFFICE-003/004/005 是真正的单步策略，仍在此处理。

    if scenario == "mail_send" and "bulk_send" in labels:
        return DetectionDecision(
            event_id=event.event_id,
            timestamp=utc_now_iso(),
            action_type=event.action_type,
            risk_level="dangerous",
            action="escalate",
            reason="邮件群发属于高风险办公动作，需要二次确认。",
            rule_ids=["SEM-OFFICE-003"],
            trace=trace + [{"stage": "office_policy", "policy_id": "SEM-OFFICE-003", "outcome": "escalate"}],
            requires_second_confirmation=True,
            confirmation_word="EXECUTE",
        )
    if scenario == "mail_send" and "ai_generated_content" in labels and "requires_human_review" not in labels:
        return DetectionDecision(
            event_id=event.event_id,
            timestamp=utc_now_iso(),
            action_type=event.action_type,
            risk_level="caution",
            action="ask",
            reason="AI 自动生成邮件内容尚未确认，需人工复核后发送。",
            rule_ids=["SEM-OFFICE-004"],
            trace=trace + [{"stage": "office_policy", "policy_id": "SEM-OFFICE-004", "outcome": "ask"}],
            requires_second_confirmation=False,
            confirmation_word=None,
        )
    if scenario == "report_generate" and "missing_scope_constraint" in labels:
        return DetectionDecision(
            event_id=event.event_id,
            timestamp=utc_now_iso(),
            action_type=event.action_type,
            risk_level="caution",
            action="ask",
            reason="日报生成缺少明确时间或范围约束，需要人工确认。",
            rule_ids=["SEM-OFFICE-005"],
            trace=trace + [{"stage": "office_policy", "policy_id": "SEM-OFFICE-005", "outcome": "ask"}],
            requires_second_confirmation=False,
            confirmation_word=None,
        )
    return None

