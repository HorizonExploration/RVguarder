"""
nl2spec_generator.py —— 阶段 E：自然语言 → 结构化 IR 生成器。

QA 分解翻译流水线：
1. 事件步骤识别 → event + all_of/any_of tags
2. 实体约束提取 → entity_all_of/entity_any_of
3. 判定映射 → verdict (block/escalate/ask)

支持 LLM 模式和内置规则模板引擎两种模式。
内置模板覆盖 10 种常见办公安全场景，用于离线和测试。
"""

from __future__ import annotations

from typing import Any

from openclaw_guard.rv.rv_dsl import (
    ChainRule,
    MonitorSpec,
    Ruleset,
)


# 内置模板：nl 关键词 → 结构化 IR
_BUILTIN_TEMPLATES: list[dict[str, Any]] = [
    {
        "keywords": ["rm -rf", "递归删除", "强制删除", "删除系统"],
        "monitor": "NL2SpecFileGuard",
        "initial": "idle",
        "rules": [
            {"id": "nl_rmrf", "from": "idle", "to": "blocked", "verdict": "block",
             "when": {"event": "command_exec", "all_of": ["command_rm_rf"]}},
        ],
    },
    {
        "keywords": ["curl|sh", "curl管道", "curl pipe"],
        "monitor": "NL2SpecCurlGuard",
        "initial": "idle",
        "rules": [
            {"id": "nl_curl", "from": "idle", "to": "blocked", "verdict": "block",
             "when": {"event": "command_exec", "all_of": ["command_pipe_curl_sh"]}},
        ],
    },
    {
        "keywords": ["外部发邮件", "外发邮件", "外部邮件", "external mail", "send external"],
        "monitor": "NL2SpecMailGuard",
        "initial": "idle",
        "rules": [
            {"id": "nl_extmail_idle_ask", "from": "idle", "to": "idle", "verdict": "ask",
             "when": {"event": "mail_send", "entity_any_of": [
                 {"kind": "recipients", "match_type": "domain_not_in", "values": ["internal.com"]},
             ]}},
            {"id": "nl_extmail_secret_block", "from": "idle", "to": "blocked", "verdict": "block",
             "when": {"event": "mail_send", "all_of": ["contains_secret"], "entity_any_of": [
                 {"kind": "recipients", "match_type": "domain_not_in", "values": ["internal.com"]},
             ]}},
        ],
    },
    {
        "keywords": ["删除凭据", "delete credentials", "删除密钥"],
        "monitor": "NL2SpecCredGuard",
        "initial": "idle",
        "rules": [
            {"id": "nl_cred", "from": "idle", "to": "blocked", "verdict": "block",
             "when": {"event": "file_delete", "all_of": ["path_sensitive_creds"]}},
        ],
    },
    {
        "keywords": ["sudo", "提权", "root", "管理员权限"],
        "monitor": "NL2SpecSudoGuard",
        "initial": "idle",
        "rules": [
            {"id": "nl_sudo", "from": "idle", "to": "idle", "verdict": "escalate",
             "when": {"event": "command_exec", "all_of": ["command_sudo"]}},
        ],
    },
    {
        "keywords": ["导出数据", "export data", "批量导出"],
        "monitor": "NL2SpecExportGuard",
        "initial": "idle",
        "rules": [
            {"id": "nl_export", "from": "idle", "to": "blocked", "verdict": "block",
             "when": {"any_of": ["batch_export", "large_export"]}},
        ],
    },
    {
        "keywords": ["群发", "broadcast", "群消息"],
        "monitor": "NL2SpecBroadcastGuard",
        "initial": "idle",
        "rules": [
            {"id": "nl_bcast_ask", "from": "idle", "to": "idle", "verdict": "ask",
             "when": {"all_of": ["channel_send", "bulk_send"]}},
            {"id": "nl_bcast_block", "from": "idle", "to": "blocked", "verdict": "block",
             "when": {"all_of": ["channel_send", "bulk_send", "external_recipient"]}},
        ],
    },
    {
        "keywords": ["禁用审计", "disable audit", "关闭审计"],
        "monitor": "NL2SpecAuditGuard",
        "initial": "idle",
        "rules": [
            {"id": "nl_audit", "from": "idle", "to": "blocked", "verdict": "block",
             "when": {"all_of": ["config_audit_disable"]}},
        ],
    },
    {
        "keywords": ["敏感查询", "query sensitive", "查询用户表"],
        "monitor": "NL2SpecQueryGuard",
        "initial": "idle",
        "rules": [
            {"id": "nl_query_ask", "from": "idle", "to": "query_sensitive", "verdict": "ask",
             "when": {"all_of": ["database_query"], "any_of": ["user_table", "user", "payment"]}},
        ],
    },
    {
        "keywords": ["持久化", "persistence", "自启动", "守护进程"],
        "monitor": "NL2SpecPersistGuard",
        "initial": "idle",
        "rules": [
            {"id": "nl_persist", "from": "idle", "to": "blocked", "verdict": "block",
             "when": {"event": "skill_run", "all_of": ["skill_persistence"]}},
        ],
    },
]


def _match_keywords(nl: str, template: dict[str, Any]) -> bool:
    """检查 nl 字符串是否匹配模板关键词。"""
    nl_lower = nl.lower()
    for kw in template["keywords"]:
        # 支持 | 分隔的多词匹配
        for part in kw.split("|"):
            if part.strip() in nl_lower:
                return True
    return False


def generate_ruleset(
    nl_policy: str,
    *,
    monitor_name: str | None = None,
    use_llm: bool = False,
    llm_config: dict[str, Any] | None = None,
) -> Ruleset | None:
    """从自然语言策略生成结构化 Ruleset。

    Args:
        nl_policy: 自然语言安全策略描述
        monitor_name: 监视器名称（默认自动生成）
        use_llm: 是否使用 LLM（暂未实现，默认使用内置模板）
        llm_config: LLM 配置

    Returns:
        Ruleset 或 None（无法匹配时）
    """
    if not use_llm or llm_config is None:
        return _generate_from_templates(nl_policy, monitor_name)

    # LLM 模式预留（Phase E 后续迭代中实现）
    return None


def _generate_from_templates(
    nl_policy: str,
    monitor_name: str | None = None,
) -> Ruleset | None:
    """从内置模板匹配生成 Ruleset。"""
    monitors: list[MonitorSpec] = []

    for template in _BUILTIN_TEMPLATES:
        if _match_keywords(nl_policy, template):
            spec = MonitorSpec(
                name=template["monitor"],
                initial=template["initial"],
                rules=[
                    ChainRule(**r, origin="nl2spec", source_nl=nl_policy)
                    if isinstance(r, dict)
                    else ChainRule.model_validate(r)
                    for r in template["rules"]
                ],
            )
            monitors.append(spec)

    if not monitors:
        return None

    return Ruleset(
        monitors=monitors,
        source_nl=nl_policy,
    )
