from __future__ import annotations

from dataclasses import replace
from typing import Iterable

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

    def evaluate(self, event: BehaviorEvent) -> DetectionDecision:
        matched: list[DetectionRule] = []
        trace: list[dict[str, object]] = []
        haystack = " ".join(
            [
                event.command or "",
                " ".join(event.target_paths),
                " ".join(event.network_targets),
                event.api_name or "",
                event.skill_name or "",
                event.channel_name or "",
                str(event.raw_payload),
            ]
        ).lower()
        for rule in self.rules:
            if event.action_type not in rule.action_types:
                continue
            hit = False
            if rule.keywords and any(keyword.lower() in haystack for keyword in rule.keywords):
                hit = True
            if rule.command_prefixes and event.command and any(event.command.lower().startswith(prefix.lower()) for prefix in rule.command_prefixes):
                hit = True
            if rule.path_prefixes and any(path.startswith(prefix.replace("~", str(__import__("pathlib").Path.home()))) for path in event.target_paths for prefix in rule.path_prefixes):
                hit = True
            if rule.network_patterns and any(pattern.lower() in haystack for pattern in rule.network_patterns):
                hit = True
            if "outside-workspace" in rule.tags and event.metadata.get("outside_workspace"):
                hit = True
            if "multi-target" in rule.tags and len(event.target_paths) > 1:
                hit = True
            if "channel" in rule.tags and bool(event.channel_name):
                hit = True
            trace.append({"rule_id": rule.rule_id, "outcome": "match" if hit else "miss"})
            if hit:
                matched.append(rule)
        if not matched:
            fallback = _fallback_decision(event)
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
        strongest = sorted(matched, key=lambda item: ("blocked", "dangerous", "caution", "safe").index(item.risk_level))[0]
        requires_second = strongest.decision == "escalate"
        return DetectionDecision(
            event_id=event.event_id,
            timestamp=utc_now_iso(),
            action_type=event.action_type,
            risk_level=strongest.risk_level,
            action=strongest.decision,
            reason=strongest.description,
            rule_ids=[item.rule_id for item in matched],
            trace=trace + [{"stage": "decision", "outcome": strongest.decision, "rule_id": strongest.rule_id}],
            requires_second_confirmation=requires_second,
            confirmation_word="EXECUTE" if requires_second else None,
        )


def _fallback_decision(event: BehaviorEvent) -> dict[str, object]:
    if event.action_type == "chat_message":
        return {
            "risk_level": "safe",
            "action": "allow",
            "reason": "未命中高危规则，按低风险对话放行。",
        }
    if event.action_type == "command_exec" and _is_low_risk_command(event.command):
        return {
            "risk_level": "safe",
            "action": "allow",
            "reason": "检测为只读命令，按低风险动作放行。",
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
