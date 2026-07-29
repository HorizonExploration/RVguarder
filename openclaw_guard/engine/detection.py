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
    def add(rule_id: str, title: str, description: str, action_types: list[str], severity: str, risk: str, decision: str, *, keywords: list[str] | None = None, paths: list[str] | None = None, commands: list[str] | None = None, networks: list[str] | None = None, tags: list[str] | None = None) -> None:
        rules.append(
            DetectionRule(
                rule_id=rule_id,
                title=title,
                description=description,
                action_types=action_types,
                severity=severity,
                risk_level=risk,
                decision=decision,
                keywords=keywords or [],
                path_prefixes=paths or [],
                command_prefixes=commands or [],
                network_patterns=networks or [],
                tags=tags or [],
            )
        )

    # 47 rules grouped by type.
    add("CMD-001", "阻断 rm -rf", "递归强删默认阻断。", ["command_exec"], "critical", "blocked", "block", commands=["rm -rf"])
    add("CMD-002", "阻断 curl 管道执行", "curl|sh 供应链风险。", ["command_exec"], "critical", "blocked", "block", keywords=["curl", "| sh"])
    add("CMD-003", "阻断 wget 管道执行", "wget|bash 供应链风险。", ["command_exec"], "critical", "blocked", "block", keywords=["wget", "| bash"])
    add("CMD-004", "升级 sudo", "提权命令需要二次确认。", ["command_exec"], "high", "dangerous", "escalate", commands=["sudo "])
    add("CMD-005", "升级 ssh", "远程连接命令需要二次确认。", ["command_exec"], "high", "dangerous", "escalate", commands=["ssh "])
    add("CMD-006", "升级 scp", "远程复制命令需要二次确认。", ["command_exec"], "high", "dangerous", "escalate", commands=["scp "])
    add("CMD-007", "确认 chmod", "权限变更命令需要审批。", ["command_exec"], "high", "dangerous", "ask", commands=["chmod "])
    add("CMD-008", "确认 chown", "属主变更命令需要审批。", ["command_exec"], "high", "dangerous", "ask", commands=["chown "])
    add("CMD-009", "确认 mv", "批量移动命令可能影响证据链。", ["command_exec"], "medium", "caution", "ask", commands=["mv "])
    add("CMD-010", "确认 rm", "普通删除命令需要审批。", ["command_exec"], "high", "dangerous", "ask", commands=["rm "])
    add("FILE-001", "阻断系统目录删除", "系统目录删除默认阻断。", ["file_delete"], "critical", "blocked", "block", paths=["/bin", "/etc", "/usr", "/System"])
    add("FILE-002", "阻断敏感凭据目录删除", "删除 SSH/云凭据目录会破坏凭据。", ["file_delete"], "critical", "blocked", "block", keywords=["/.ssh", "/.aws", "/.gnupg"])
    add("FILE-003", "确认工作区外删除", "工作区外删除需要审批。", ["file_delete"], "high", "dangerous", "ask", tags=["outside-workspace"])
    add("FILE-004", "确认日志删除", "删除日志会影响取证。", ["file_delete"], "high", "dangerous", "ask", paths=["/var/log", "/tmp/openclaw"])
    add("FILE-005", "确认证据目录删除", "证据目录删除需要审批。", ["file_delete"], "critical", "dangerous", "escalate", keywords=["evidence", "forensics"])
    add("FILE-006", "阻断配置覆盖", "覆盖 openclaw.json 默认阻断。", ["config_modify"], "critical", "blocked", "block", keywords=["openclaw.json"])
    add("FILE-007", "确认工作区外写入", "写入工作区外文件需要审批。", ["file_write"], "high", "dangerous", "ask", tags=["outside-workspace"])
    add("FILE-008", "确认脚本写入", "写入脚本文件需要审批。", ["file_write"], "high", "dangerous", "ask", keywords=[".sh", ".ps1", ".bat"])
    add("FILE-009", "阻断敏感凭据写入", "写入 SSH/API 凭据默认阻断。", ["file_write"], "critical", "blocked", "block", keywords=["id_rsa", "api_key", "secret"])
    add("FILE-010", "确认批量写入", "多目标写入需要审批。", ["file_write"], "medium", "caution", "ask", tags=["multi-target"])
    add("NET-001", "确认外部 HTTP 访问", "外部网络访问需要审批。", ["network_egress"], "high", "caution", "ask", networks=["http://", "https://"])
    add("NET-002", "阻断未知公网 IP", "未知公网目标默认阻断。", ["network_egress"], "critical", "blocked", "block", networks=["http://1.", "http://8.", "https://1.", "https://8."])
    add("NET-003", "升级 webhook", "Webhook 发送需要二次确认。", ["network_egress"], "high", "dangerous", "escalate", keywords=["webhook"])
    add("NET-004", "确认上传", "外传关键词触发审批。", ["network_egress"], "high", "dangerous", "ask", keywords=["upload", "send file", "post data"])
    add("NET-005", "阻断敏感外传", "携带凭据外发默认阻断。", ["network_egress"], "critical", "blocked", "block", keywords=["token", "secret", "password"])
    add("NET-006", "确认代理切换", "修改代理出口需要审批。", ["network_egress"], "medium", "caution", "ask", keywords=["proxy"])
    add("API-001", "确认危险 API", "危险 API 调用需要审批。", ["channel_send"], "high", "dangerous", "ask", keywords=["external-send"])
    add("API-002", "阻断敏感 API", "敏感 API 越权默认阻断。", ["channel_send"], "critical", "blocked", "block", keywords=["admin"])
    add("API-003", "确认通道发送", "跨渠道发送需要审批。", ["channel_send"], "high", "caution", "ask", tags=["channel"])
    add("API-004", "升级群发", "批量发送需要二次确认。", ["channel_send"], "high", "dangerous", "escalate", keywords=["broadcast"])
    add("SKL-001", "确认 shell skill", "Shell 型 skill 需要审批。", ["skill_run"], "high", "dangerous", "ask", keywords=["shell", "exec"])
    add("SKL-002", "确认 network skill", "具备外联能力的 skill 需要审批。", ["skill_run"], "high", "dangerous", "ask", keywords=["webhook", "requests", "axios"])
    add("SKL-003", "确认 delete skill", "具备删除能力的 skill 需要审批。", ["skill_run"], "high", "dangerous", "ask", keywords=["delete", "remove file"])
    add("SKL-004", "确认 write skill", "具备写入能力的 skill 需要审批。", ["skill_run"], "high", "dangerous", "ask", keywords=["write file", "overwrite"])
    add("SKL-005", "阻断持久化 skill", "自启动/守护能力默认阻断。", ["skill_run"], "critical", "blocked", "block", keywords=["autorun", "daemon", "startup"])
    add("SKL-006", "升级系统管理 skill", "系统管理类 skill 需二次确认。", ["skill_run"], "high", "dangerous", "escalate", keywords=["sudo", "ssh"])
    add("CFG-001", "确认配置修改", "修改 OpenClaw 关键配置需要审批。", ["config_modify"], "high", "dangerous", "ask", keywords=["baseUrl", "endpoint", "provider"])
    add("CFG-002", "阻断鉴权关闭", "关闭鉴权默认阻断。", ["config_modify"], "critical", "blocked", "block", keywords=["auth", "disabled"])
    add("CFG-003", "确认审批绕过", "绕过审批配置需要审批。", ["config_modify"], "high", "dangerous", "ask", keywords=["bypass", "allow_all"])
    add("CFG-004", "确认沙箱关闭", "关闭沙箱需要审批。", ["config_modify"], "high", "dangerous", "ask", keywords=["sandbox", "disabled"])
    add("CFG-005", "阻断日志关闭", "关闭审计日志默认阻断。", ["config_modify"], "critical", "blocked", "block", keywords=["audit", "off"])
    add("GEN-001", "确认未解析删除", "删除动作未解析目标路径时先审批。", ["file_delete"], "high", "dangerous", "ask")
    add("GEN-002", "确认未解析写入", "写入动作未解析目标路径时先审批。", ["file_write"], "high", "dangerous", "ask")
    add("GEN-003", "确认未解析命令", "高危命令模糊时先审批。", ["command_exec"], "medium", "caution", "ask", keywords=["delete", "remove"])
    add("GEN-004", "确认未知外联", "未知外部连接先审批。", ["network_egress"], "high", "caution", "ask")
    add("GEN-005", "升级高价值路径", "命中高价值路径需要二次确认。", ["file_delete", "file_write"], "critical", "dangerous", "escalate", keywords=["/cases/", "/evidence/"])
    add("GEN-006", "阻断批量敏感操作", "一次命中多个敏感目标默认阻断。", ["file_delete", "file_write"], "critical", "blocked", "block", tags=["multi-target"])
    return rules


class DetectionEngine:
    def __init__(self, rules: Iterable[DetectionRule] | None = None) -> None:
        self.rules = list(rules or builtin_rules())
        self.rule_index = {rule.rule_id: rule for rule in self.rules}
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

        matched_rule_ids = [rule_id for rule_id, predicate in _semantic_predicates() if predicate(event, labels, scenario)]
        if matched_rule_ids:
            matched_rules = [self.rule_index[rule_id] for rule_id in matched_rule_ids if rule_id in self.rule_index]
            strongest = sorted(matched_rules, key=lambda item: ("blocked", "dangerous", "caution", "safe").index(item.risk_level))[0]
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


def _is_low_risk_command(command: str | None) -> bool:
    if not command:
        return False
    normalized = command.strip().lower()
    return normalized.startswith(("ls", "pwd", "cat ", "grep ", "find ", "echo "))


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


def _semantic_predicates() -> list[tuple[str, callable]]:
    return [
        ("CMD-001", lambda event, labels, scenario: "command_rm_rf" in labels),
        ("CMD-002", lambda event, labels, scenario: "command_pipe_curl_sh" in labels),
        ("CMD-003", lambda event, labels, scenario: "command_pipe_wget_bash" in labels),
        ("CMD-004", lambda event, labels, scenario: "command_sudo" in labels),
        ("CMD-005", lambda event, labels, scenario: "command_ssh" in labels),
        ("CMD-006", lambda event, labels, scenario: "command_scp" in labels),
        ("CMD-007", lambda event, labels, scenario: "command_chmod" in labels),
        ("CMD-008", lambda event, labels, scenario: "command_chown" in labels),
        ("CMD-009", lambda event, labels, scenario: "command_mv" in labels),
        ("CMD-010", lambda event, labels, scenario: "command_rm" in labels),
        ("FILE-001", lambda event, labels, scenario: event.action_type == "file_delete" and "path_system_root" in labels),
        ("FILE-002", lambda event, labels, scenario: event.action_type == "file_delete" and "path_sensitive_creds" in labels),
        ("FILE-003", lambda event, labels, scenario: event.action_type == "file_delete" and "outside_workspace" in labels),
        ("FILE-004", lambda event, labels, scenario: event.action_type == "file_delete" and "path_log" in labels),
        ("FILE-005", lambda event, labels, scenario: event.action_type == "file_delete" and "path_high_value" in labels),
        ("FILE-006", lambda event, labels, scenario: event.action_type == "config_modify" and "path_openclaw_config" in labels),
        ("FILE-007", lambda event, labels, scenario: event.action_type == "file_write" and "outside_workspace" in labels),
        ("FILE-008", lambda event, labels, scenario: event.action_type == "file_write" and "path_script" in labels),
        ("FILE-009", lambda event, labels, scenario: event.action_type == "file_write" and "path_sensitive_creds" in labels),
        ("FILE-010", lambda event, labels, scenario: event.action_type == "file_write" and "multi_target" in labels),
        ("NET-001", lambda event, labels, scenario: event.action_type == "network_egress" and "network_http" in labels),
        ("NET-002", lambda event, labels, scenario: event.action_type == "network_egress" and "network_public_ip" in labels),
        ("NET-003", lambda event, labels, scenario: event.action_type == "network_egress" and "network_webhook" in labels),
        ("NET-004", lambda event, labels, scenario: event.action_type == "network_egress" and "network_upload" in labels),
        ("NET-005", lambda event, labels, scenario: event.action_type == "network_egress" and "network_secret_payload" in labels),
        ("NET-006", lambda event, labels, scenario: event.action_type == "network_egress" and "network_proxy" in labels),
        ("API-001", lambda event, labels, scenario: event.action_type == "channel_send" and "channel_external_send" in labels),
        ("API-002", lambda event, labels, scenario: event.action_type == "channel_send" and "channel_admin" in labels),
        ("API-003", lambda event, labels, scenario: event.action_type == "channel_send" and "channel_present" in labels),
        ("API-004", lambda event, labels, scenario: event.action_type == "channel_send" and "bulk_send" in labels),
        ("SKL-001", lambda event, labels, scenario: event.action_type == "skill_run" and "skill_shell" in labels),
        ("SKL-002", lambda event, labels, scenario: event.action_type == "skill_run" and "skill_network" in labels),
        ("SKL-003", lambda event, labels, scenario: event.action_type == "skill_run" and "skill_delete" in labels),
        ("SKL-004", lambda event, labels, scenario: event.action_type == "skill_run" and "skill_write" in labels),
        ("SKL-005", lambda event, labels, scenario: event.action_type == "skill_run" and "skill_persistence" in labels),
        ("SKL-006", lambda event, labels, scenario: event.action_type == "skill_run" and "skill_system_admin" in labels),
        ("CFG-001", lambda event, labels, scenario: event.action_type == "config_modify" and "config_provider_change" in labels),
        ("CFG-002", lambda event, labels, scenario: event.action_type == "config_modify" and "config_auth_disable" in labels),
        ("CFG-003", lambda event, labels, scenario: event.action_type == "config_modify" and "config_bypass" in labels),
        ("CFG-004", lambda event, labels, scenario: event.action_type == "config_modify" and "config_sandbox_disable" in labels),
        ("CFG-005", lambda event, labels, scenario: event.action_type == "config_modify" and "config_audit_disable" in labels),
        ("GEN-001", lambda event, labels, scenario: event.action_type == "file_delete" and "unparsed_target" in labels),
        ("GEN-002", lambda event, labels, scenario: event.action_type == "file_write" and "unparsed_target" in labels),
        ("GEN-003", lambda event, labels, scenario: event.action_type == "command_exec" and "command_delete_intent" in labels),
        ("GEN-004", lambda event, labels, scenario: event.action_type == "network_egress" and "network_unknown_external" in labels),
        ("GEN-005", lambda event, labels, scenario: event.action_type in {"file_delete", "file_write"} and "path_high_value" in labels),
        ("GEN-006", lambda event, labels, scenario: event.action_type in {"file_delete", "file_write"} and "multi_target" in labels),
    ]
