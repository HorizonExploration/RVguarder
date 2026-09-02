"""Frozen compatibility metadata for the pre-PMKB single-step rules.

The records are retained only for offline LEGACY replay and migration audits.
They are not an executable decision engine; runtime authorization is owned by
the PMKB evaluator.
"""

from __future__ import annotations

from openclaw_guard.models import DetectionRule


def legacy_rules() -> list[DetectionRule]:
    """Return the 47 historical rules used by the LEGACY replay gate."""
    rules: list[DetectionRule] = []

    def add(rule_id: str, title: str, description: str, action_types: list[str], severity: str, risk: str, decision: str, *, match_labels: list[str] | None = None) -> None:
        rules.append(DetectionRule(rule_id=rule_id, title=title, description=description,
                                   action_types=action_types, severity=severity,
                                   risk_level=risk, decision=decision,
                                   match_labels=match_labels or []))

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
