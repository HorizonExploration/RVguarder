from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import urllib.request
import urllib.error
from pathlib import Path
from typing import Any

from openclaw_guard.models import BehaviorEvent

logger = logging.getLogger(__name__)

_RE_EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,})\b", re.IGNORECASE)
_RE_PUBLIC_IP = re.compile(r"https?://(\d{1,3}(?:\.\d{1,3}){3})", re.IGNORECASE)
_INTERNAL_DOMAINS = {"openclaw.ai", "openclaw.local", "internal.local", "company.local"}
_SYSTEM_PREFIXES = ("/bin", "/etc", "/usr", "/system")
_LOG_PREFIXES = ("/var/log", "/tmp/openclaw")
_SENSITIVE_PATH_MARKERS = ("/.ssh", "/.aws", "/.gnupg", "id_rsa", "api_key", "/secrets/", "/credentials/")
_HIGH_VALUE_PATH_MARKERS = ("/cases/", "/evidence/", "evidence", "forensics")
_SCRIPT_SUFFIXES = {".sh", ".ps1", ".bat"}
_READONLY_COMMANDS = ("ls", "pwd", "cat ", "grep ", "find ", "echo ")

_DEFAULT_LLM_BASE_URL = "https://api.deepseek.com/v1"
_DEFAULT_LLM_MODEL = "deepseek-v4-flash"
_DEFAULT_TIMEOUT_SEC = 10
_CONFIG_FILE_NAME = "guard-config.json"


class SemanticEnhancer:
    """独立语义层。

    输出形式按照"直接服务决策与 RV"设计：
    - `semantic` 负责提供结构化语义结果
    - `rv_trace` 负责提供 RV 可消费的直接输入

    调用方式：
    - 若配置了 API key，优先调用 LLM API 做真实语义理解
    - API 调用失败/超时/返回非 JSON 时，自动降级到本地规则化实现
    """

    def __init__(
        self,
        api_key: str | None = None,
        model: str = _DEFAULT_LLM_MODEL,
        base_url: str = _DEFAULT_LLM_BASE_URL,
        config_path: str | Path | None = None,
    ) -> None:
        self.model = model
        self.base_url = base_url.rstrip("/")

        # API key 优先级：构造函数参数 > 环境变量 > 配置文件
        # api_key 显式传入空字符串时，表示不启用 LLM，跳过后续加载
        if api_key is not None:
            resolved_key = api_key.strip()
        else:
            resolved_key = os.environ.get("DEEPSEEK_API_KEY", "").strip()
            if not resolved_key:
                resolved_key = self._load_key_from_config(config_path)

        self.api_key = resolved_key
        self._llm_enabled = bool(self.api_key)

    @staticmethod
    def _load_key_from_config(config_path: str | Path | None) -> str:
        """从配置文件加载 API key。

        查找顺序：
        1. 显式传入的 config_path
        2. config_path 未传入时：cwd/runtime/guard-config.json
        3. config_path 未传入时：cwd/guard-config.json
        """
        if config_path:
            path = Path(config_path)
            if path.is_file():
                try:
                    data = json.loads(path.read_text(encoding="utf-8"))
                    key = (data.get("llm_api_key") or "").strip()
                    if key:
                        logger.info("Loaded LLM API key from %s", path)
                        return key
                except (json.JSONDecodeError, OSError) as exc:
                    logger.warning("Failed to read config %s: %s", path, exc)
            return ""
        cwd = Path.cwd()
        for candidate in [cwd / "runtime" / _CONFIG_FILE_NAME, cwd / _CONFIG_FILE_NAME]:
            if candidate.is_file():
                try:
                    data = json.loads(candidate.read_text(encoding="utf-8"))
                    key = (data.get("llm_api_key") or "").strip()
                    if key:
                        logger.info("Loaded LLM API key from %s", candidate)
                        return key
                except (json.JSONDecodeError, OSError) as exc:
                    logger.warning("Failed to read config %s: %s", candidate, exc)
        return ""

    def evaluate(self, event: BehaviorEvent, context: dict[str, Any] | None = None) -> dict[str, Any]:
        ctx = context or {}
        source_message = str(ctx.get("source_message") or event.raw_payload.get("raw_user_intent") or "").strip()
        tool_name = str(event.metadata.get("tool_name") or "")
        origin = str(ctx.get("origin") or event.source or "unknown")
        haystack = _build_haystack(event, source_message, tool_name)

        result: dict[str, Any] | None = None

        # 1. 若配置了 LLM，优先调用 LLM API
        if self._llm_enabled and source_message:
            try:
                result = self._call_llm(event, source_message, tool_name, haystack, origin)
            except Exception as exc:
                logger.warning("LLM semantic analysis failed, falling back to local rules: %s", exc)

        # 2. 降级到本地规则化实现
        if result is None:
            result = self._local_evaluate(event, source_message, tool_name, haystack, origin)

        # 3. Hard validation: 根据工具名称硬性纠正语义标签，防止 LLM 幻觉误分类
        hard_tool_name = (
            getattr(event, 'metadata', {}).get('tool_name')
            or (event.raw_payload.get('toolName') if hasattr(event, 'raw_payload') and isinstance(getattr(event, 'raw_payload', None), dict) else '')
            or ''
        )
        if hard_tool_name:
            result["semantic"] = self._validate_tool_name(hard_tool_name, result["semantic"])

        return result

    def _call_llm(
        self,
        event: BehaviorEvent,
        source_message: str,
        tool_name: str,
        haystack: str,
        origin: str,
    ) -> dict[str, Any] | None:
        prompt = self._build_prompt(event, source_message, tool_name, haystack)
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": "你是一个安全语义分析引擎。你的职责是分析用户的输入意图和上下文，输出严格的结构化 JSON。不要输出任何额外文字，只输出 JSON。"},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.1,
            "max_tokens": 1024,
            "response_format": {"type": "json_object"},
        }
        req_data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=req_data,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
            method="POST",
        )
        try:
            resp = urllib.request.urlopen(req, timeout=_DEFAULT_TIMEOUT_SEC)
        except urllib.error.HTTPError as exc:
            logger.warning("LLM HTTP %s: %s", exc.code, exc.read().decode("utf-8", errors="replace"))
            return None
        except urllib.error.URLError as exc:
            logger.warning("LLM URL error: %s", exc.reason)
            return None

        body = resp.read().decode("utf-8")
        try:
            data = json.loads(body)
        except json.JSONDecodeError as exc:
            logger.warning("LLM response not JSON: %s", exc)
            return None

        choices = data.get("choices", [])
        if not choices:
            logger.warning("LLM response empty choices")
            return None

        content = choices[0].get("message", {}).get("content", "").strip()
        if not content:
            logger.warning("LLM response empty content")
            return None

        try:
            parsed = json.loads(content)
        except json.JSONDecodeError:
            logger.warning("LLM content is not valid JSON: %.200s", content)
            return None

        # 校验必要字段
        semantic = parsed.get("semantic")
        rv_trace = parsed.get("rv_trace")
        if not isinstance(semantic, dict) or not isinstance(rv_trace, list):
            logger.warning("LLM output missing required fields: semantic=%s, rv_trace=%s", type(semantic).__name__, type(rv_trace).__name__)
            return None

        # 补全缺失字段
        semantic.setdefault("version", "v2")
        semantic.setdefault("engine", f"llm-{self.model}")
        semantic.setdefault("origin", origin)
        semantic.setdefault("scenario", event.action_type)
        semantic.setdefault("intent", {"category": event.action_type, "goal": ""})
        semantic.setdefault("entities", {"paths": [], "urls": [], "recipients": [], "tool_name": None})
        semantic.setdefault("constraints", {})
        semantic.setdefault("confidence", 0.5)
        semantic.setdefault("labels", [event.action_type])

        # 确保 rv_trace 每条都有 step_id/event/props
        for item in rv_trace:
            if not isinstance(item, dict):
                continue
            item.setdefault("step_id", "s1")
            item.setdefault("event", semantic.get("scenario", event.action_type))
            item.setdefault("props", [])

        return {"semantic": semantic, "rv_trace": rv_trace}

    def _build_prompt(self, event: BehaviorEvent, source_message: str, tool_name: str, haystack: str) -> str:
        return f"""分析以下安全事件，输出严格的结构化 JSON。

## 事件信息
- action_type: {event.action_type}
- command: {event.command or "N/A"}
- target_paths: {event.target_paths}
- network_targets: {event.network_targets}
- channel_name: {event.channel_name or "N/A"}
- api_name: {event.api_name or "N/A"}
- skill_name: {event.skill_name or "N/A"}
- tool_name: {tool_name or "N/A"}
- outside_workspace: {event.metadata.get("outside_workspace", False)}
- source_message: {source_message or "N/A"}

## 要求输出的 JSON 结构
{{
  "semantic": {{
    "version": "v2",
    "engine": "llm-deepseek-chat",
    "origin": "chat|hook|reply",
    "scenario": "请判断最匹配的场景：mail_send / mail_read / report_generate / report_send / attachment_download / file_delete / file_write / config_modify / network_egress / channel_send / skill_run / command_exec / chat_message",
    "intent": {{
      "category": "场景分类",
      "goal": "用中文简明扼要地概括用户本次动作的目标，如：发送汇报邮件、删除系统日志、访问外部API等"
    }},
    "entities": {{
      "paths": ["目标路径列表"],
      "urls": ["目标URL列表"],
      "recipients": ["收件人邮箱列表"],
      "tool_name": "工具名或null"
    }},
    "constraints": {{
      "exclude": ["排除条件列表，如attachments/logs/internal_bug_details"],
      "time_range": "时间范围: today/yesterday/this_week/null",
      "has_exclude": true/false,
      "has_time_constraint": true/false,
      "has_scope_constraint": true/false,
      "requires_human_review": true/false
    }},
    "confidence": 0.0-1.0,
    "labels": [
      "根据事件类型选择标签：动作类型标签(如file_delete/network_egress/command_exec/mail_send等)、命令标签(command_rm_rf/command_sudo/command_readonly等)、路径标签(path_system_root/path_sensitive_creds/path_high_value/path_log等)、网络标签(network_http/network_public_ip/network_secret_payload等)、配置标签(config_auth_disable/config_audit_disable等)、渠道标签(channel_external_send/bulk_send等)、技能标签(skill_shell/skill_persistence等)、办公标签(external_recipient/contains_secret/contains_attachment/ai_generated_content/internal_source/bulk_send/has_recipient等)、通用标签(outside_workspace/multi_target/unparsed_target等)"
    ]
  }},
  "rv_trace": [
    {{
      "step_id": "s1",
      "event": "scenario值",
      "props": ["来自labels的标签列表"]
    }}
  ]
}}

## 注意事项
1. 只输出 JSON，不要输出任何其他文字
2. scenario 必须从上面列表中选取
3. labels 必须包含 action_type、scenario 和有意义的语义标签
4. confidence 反映你对语义理解的把握程度
5. constraints 中的 exclude 列表列出用户明确要求排除的内容
6. rv_trace 第一条的 event 必须与 scenario 一致
"""

    @staticmethod
    def _validate_tool_name(tool_name: str, semantic: dict) -> dict:
        """根据工具名称硬性纠正语义标签，防止 LLM 幻觉误分类。

        规则矩阵：
        - read → 强制注入 file_read，剔除 file_write
        - write/edit → 强制注入 file_write，剔除 file_read
        - exec/shell → 强制注入 command_exec
        - search → 强制注入 file_search
        - delete/remove → 强制注入 file_delete
        """
        labels = list(semantic.get("labels", []))
        lowered = (tool_name or "").lower()
        scenario = semantic.get("scenario", "")

        # Read operations: never write
        if lowered in ("read", "file_read", "grep", "cat", "head", "tail", "list", "ls"):
            # Remove write-related labels
            labels = [l for l in labels if l not in ("file_write", "config_modify")]
            # Remove write scenario
            if scenario == "file_write":
                semantic["scenario"] = "file_read"
            # Inject read labels
            for tag in ("file_read",):
                if tag not in labels:
                    labels.append(tag)

        # Write operations: never read
        elif lowered in ("write", "edit", "create", "save", "overwrite", "patch"):
            labels = [l for l in labels if l not in ("file_read",)]
            for tag in ("file_write",):
                if tag not in labels:
                    labels.append(tag)

        # Execute operations
        elif lowered in ("exec", "shell", "command", "bash", "run", "execute"):
            labels = [l for l in labels if l not in ("file_read", "file_write", "network_egress")]
            for tag in ("command_exec",):
                if tag not in labels:
                    labels.append(tag)

        # Search operations
        elif "search" in lowered or lowered in ("grep", "find", "locate"):
            for tag in ("file_search",):
                if tag not in labels:
                    labels.append(tag)

        # Delete operations
        elif lowered in ("delete", "remove", "unlink", "rm", "trash"):
            for tag in ("file_delete",):
                if tag not in labels:
                    labels.append(tag)

        semantic["labels"] = labels
        return semantic

    # ---- 本地规则化降级实现 ----

    def _local_evaluate(
        self,
        event: BehaviorEvent,
        source_message: str,
        tool_name: str,
        haystack: str,
        origin: str,
    ) -> dict[str, Any]:
        scenario = _infer_scenario(event, haystack)
        recipients = _extract_recipients(source_message, event)
        constraints = _extract_constraints(source_message, haystack, scenario)
        labels = _base_labels(event, scenario)
        labels.update(_command_labels(event, haystack))
        labels.update(_path_labels(event))
        labels.update(_network_labels(event, haystack))
        labels.update(_config_labels(event, haystack))
        labels.update(_channel_labels(event, haystack, recipients))
        labels.update(_skill_labels(event, haystack))
        labels.update(_office_labels(event, scenario, haystack, recipients, constraints))

        semantic = {
            "version": "v2",
            "engine": "builtin-fallback",
            "origin": origin,
            "scenario": scenario,
            "intent": {
                "category": scenario or event.action_type,
                "goal": _goal_for_scenario(scenario, event),
            },
            "entities": {
                "paths": list(event.target_paths),
                "urls": list(event.network_targets),
                "recipients": recipients,
                "tool_name": tool_name or None,
            },
            "constraints": constraints,
            "confidence": _confidence_for(labels, recipients, constraints),
            "labels": sorted(labels),
        }
        return {
            "semantic": semantic,
            "rv_trace": [
                {
                    "step_id": "s1",
                    "event": scenario or event.action_type,
                    "props": sorted(labels),
                }
            ],
        }


# ========== 本地规则化辅助函数（降级用） ==========


def _build_haystack(event: BehaviorEvent, source_message: str, tool_name: str) -> str:
    return " ".join(
        [
            source_message,
            event.command or "",
            " ".join(event.target_paths),
            " ".join(event.network_targets),
            event.channel_name or "",
            event.api_name or "",
            event.skill_name or "",
            tool_name,
            str(event.raw_payload),
        ]
    ).lower()


def _infer_scenario(event: BehaviorEvent, haystack: str) -> str:
    if _looks_like_mail_send(event, haystack):
        return "mail_send"
    if _looks_like_mail_read(event, haystack):
        return "mail_read"
    if _looks_like_report_send(event, haystack):
        return "report_send"
    if _looks_like_report_generate(event, haystack):
        return "report_generate"
    if _looks_like_attachment_download(event, haystack):
        return "attachment_download"
    return event.action_type


def _base_labels(event: BehaviorEvent, scenario: str) -> set[str]:
    labels = {event.action_type, scenario}
    if event.metadata.get("outside_workspace"):
        labels.add("outside_workspace")
    if len(event.target_paths) > 1:
        labels.add("multi_target")
    if not event.target_paths and event.action_type in {"file_delete", "file_write"}:
        labels.add("unparsed_target")
    if event.action_type == "command_exec" and _is_low_risk_command(event.command):
        labels.add("command_readonly")
    return labels


def _command_labels(event: BehaviorEvent, haystack: str) -> set[str]:
    command = (event.command or "").strip().lower()
    labels: set[str] = set()
    if event.action_type != "command_exec" and not command:
        return labels
    if command.startswith("rm -rf"):
        labels.add("command_rm_rf")
    if "curl" in command and "| sh" in command:
        labels.add("command_pipe_curl_sh")
    if "wget" in command and ("| bash" in command or "| sh" in command):
        labels.add("command_pipe_wget_bash")
    if command.startswith("sudo "):
        labels.add("command_sudo")
    if command.startswith("ssh "):
        labels.add("command_ssh")
    if command.startswith("scp "):
        labels.add("command_scp")
    if command.startswith("chmod "):
        labels.add("command_chmod")
    if command.startswith("chown "):
        labels.add("command_chown")
    if command.startswith("mv "):
        labels.add("command_mv")
    if command.startswith("rm "):
        labels.add("command_rm")
    if any(token in haystack for token in ("delete", "remove", "删除", "移除")) and not labels:
        labels.add("command_delete_intent")
    return labels


def _path_labels(event: BehaviorEvent) -> set[str]:
    labels: set[str] = set()
    for raw in event.target_paths:
        path = raw.lower()
        normalized = path.replace("\\", "/")
        if normalized.startswith(_SYSTEM_PREFIXES):
            labels.add("path_system_root")
        if any(marker in normalized for marker in _SENSITIVE_PATH_MARKERS):
            labels.add("path_sensitive_creds")
        if normalized.startswith(_LOG_PREFIXES):
            labels.add("path_log")
        if any(marker in normalized for marker in _HIGH_VALUE_PATH_MARKERS):
            labels.add("path_high_value")
        if normalized.endswith("openclaw.json"):
            labels.add("path_openclaw_config")
        if Path(normalized).suffix.lower() in _SCRIPT_SUFFIXES:
            labels.add("path_script")
    return labels


def _network_labels(event: BehaviorEvent, haystack: str) -> set[str]:
    labels: set[str] = set()
    targets = list(event.network_targets)
    if any(target.lower().startswith(("http://", "https://")) for target in targets):
        labels.add("network_http")
    if any("webhook" in target.lower() for target in targets) or "webhook" in haystack:
        labels.add("network_webhook")
    if any(token in haystack for token in ("upload", "send file", "post data", "上传", "外发")):
        labels.add("network_upload")
    if any(token in haystack for token in ("proxy", "代理")):
        labels.add("network_proxy")
    if any(token in haystack for token in ("token", "secret", "password", "api key")):
        labels.add("network_secret_payload")
    if _contains_public_ip(targets):
        labels.add("network_public_ip")
    if event.action_type == "network_egress" and not targets:
        labels.add("network_unknown_external")
    return labels


def _config_labels(event: BehaviorEvent, haystack: str) -> set[str]:
    if event.action_type != "config_modify":
        return set()
    labels: set[str] = set()
    if any(token in haystack for token in ("baseurl", "endpoint", "provider", "模型配置", "网关配置")):
        labels.add("config_provider_change")
    if any(token in haystack for token in ("auth", "disabled", "鉴权关闭")):
        labels.add("config_auth_disable")
    if any(token in haystack for token in ("bypass", "allow_all", "审批绕过")):
        labels.add("config_bypass")
    if any(token in haystack for token in ("sandbox", "沙箱")):
        labels.add("config_sandbox_disable")
    if any(token in haystack for token in ("audit", "日志关闭", "审计关闭", "audit off")):
        labels.add("config_audit_disable")
    return labels


def _channel_labels(event: BehaviorEvent, haystack: str, recipients: list[str]) -> set[str]:
    if event.action_type != "channel_send":
        return set()
    labels: set[str] = {"channel_present"}
    if any(token in haystack for token in ("external-send", "外部发送", "对外发送")):
        labels.add("channel_external_send")
    if any(token in haystack for token in ("admin", "管理员")):
        labels.add("channel_admin")
    if len(recipients) > 1 or any(token in haystack for token in ("broadcast", "群发")):
        labels.add("bulk_send")
    return labels


def _skill_labels(event: BehaviorEvent, haystack: str) -> set[str]:
    if event.action_type != "skill_run":
        return set()
    labels: set[str] = set()
    if any(token in haystack for token in ("shell", "exec")):
        labels.add("skill_shell")
    if any(token in haystack for token in ("webhook", "requests", "axios")):
        labels.add("skill_network")
    if any(token in haystack for token in ("delete", "remove file", "删除")):
        labels.add("skill_delete")
    if any(token in haystack for token in ("write file", "overwrite", "写入")):
        labels.add("skill_write")
    if any(token in haystack for token in ("autorun", "daemon", "startup", "守护")):
        labels.add("skill_persistence")
    if any(token in haystack for token in ("sudo", "ssh")):
        labels.add("skill_system_admin")
    return labels


def _office_labels(
    event: BehaviorEvent,
    scenario: str,
    haystack: str,
    recipients: list[str],
    constraints: dict[str, Any],
) -> set[str]:
    labels: set[str] = set()
    if recipients:
        labels.add("has_recipient")
    if any(_is_external_recipient(item) for item in recipients):
        labels.add("external_recipient")
    if len(recipients) > 1 or any(token in haystack for token in ("群发", "broadcast", "cc ", "bcc ")):
        labels.add("bulk_send")
    if any(token in haystack for token in ("附件", "attachment")):
        labels.add("contains_attachment")
    if any(token in haystack for token in ("token", "secret", "password", "api key", "合同", "身份证", "客户资料", "internal bug", "内部缺陷", "未公开")):
        labels.add("contains_secret")
    if any(token in haystack for token in ("ai generated", "自动生成", "ai 起草", "llm")):
        labels.add("ai_generated_content")
    if constraints.get("requires_human_review"):
        labels.add("requires_human_review")
    if constraints.get("exclude"):
        labels.add("has_exclude_constraints")
    if constraints.get("time_range"):
        labels.add(f"time_{constraints['time_range']}")
    if scenario in {"report_generate", "report_send"} and any(token in haystack for token in ("ticket", "bug", "issue", "内部")):
        labels.add("internal_source")
    if scenario == "report_generate" and not constraints.get("time_range"):
        labels.add("missing_scope_constraint")

    # 新增：来源可信度与操作阶段标签（支持 RV FSM 链式检测）
    # 来源标签
    if any(token in haystack for token in ("外部", "external", "outside", "附件打开")):
        labels.add("external_source")
    if any(token in haystack for token in ("内部", "internal", "公司内部", "组织内")):
        labels.add("source_internal")
    if any(token in haystack for token in ("附件", "attachment")) and \
       any(token in haystack for token in ("打开", "读取", "查看", "open", "read")):
        labels.add("attachment_open")
    # 操作阶段标签
    if any(token in haystack for token in ("合并", "拼接", "merge", "combine", "concat")):
        labels.add("file_merge")
    if any(token in haystack for token in ("打包", "压缩", "compress", "zip", "tar", "package")):
        labels.add("file_compress")
    if any(token in haystack for token in ("通讯录", "contacts", "crm", "客户库")):
        labels.add("contacts_db")
    if any(token in haystack for token in ("上传", "upload", "发送文件", "外传")):
        labels.add("file_upload")
    if any(token in haystack for token in ("跨组织", "cross", "合作单位", "外部群")):
        labels.add("cross_org")
    return labels


def _extract_recipients(source_message: str, event: BehaviorEvent) -> list[str]:
    recipients: list[str] = []
    candidate_text = " ".join([source_message, " ".join(event.network_targets), str(event.raw_payload)])
    for match in _RE_EMAIL.finditer(candidate_text):
        address = match.group(0)
        if address not in recipients:
            recipients.append(address)
    return recipients[:8]


def _extract_constraints(source_message: str, haystack: str, scenario: str) -> dict[str, Any]:
    constraints: dict[str, Any] = {
        "exclude": [],
        "time_range": None,
        "requires_human_review": False,
    }
    if any(token in source_message for token in ("不要", "别", "禁止")):
        if "附件" in source_message or "attachment" in haystack:
            constraints["exclude"].append("attachments")
        if "日志" in source_message or "log" in haystack:
            constraints["exclude"].append("logs")
        if "bug" in haystack or "缺陷" in source_message:
            constraints["exclude"].append("internal_bug_details")
    if "今天" in source_message or "today" in haystack:
        constraints["time_range"] = "today"
    elif "昨日" in source_message or "昨天" in source_message or "yesterday" in haystack:
        constraints["time_range"] = "yesterday"
    elif "本周" in source_message or "this week" in haystack:
        constraints["time_range"] = "this_week"
    if any(token in haystack for token in ("确认后", "人工确认", "review", "approve")):
        constraints["requires_human_review"] = True
    if scenario == "mail_send" and "草稿" in source_message:
        constraints["requires_human_review"] = True
    return constraints


def _goal_for_scenario(scenario: str, event: BehaviorEvent) -> str:
    mapping = {
        "mail_send": "发送邮件",
        "mail_read": "读取邮件",
        "report_generate": "生成汇报",
        "report_send": "发送汇报",
        "attachment_download": "下载附件",
        "file_delete": "删除文件",
        "file_write": "写入文件",
        "config_modify": "修改配置",
        "network_egress": "网络访问",
        "channel_send": "通道发送",
        "skill_run": "运行技能",
        "command_exec": "执行命令",
    }
    return mapping.get(scenario, event.action_type.replace("_", " "))


def _confidence_for(labels: set[str], recipients: list[str], constraints: dict[str, Any]) -> float:
    confidence = 0.6
    if recipients:
        confidence += 0.1
    if constraints.get("exclude") or constraints.get("time_range"):
        confidence += 0.1
    if len(labels) >= 4:
        confidence += 0.1
    return min(confidence, 0.95)


def _looks_like_mail_send(event: BehaviorEvent, haystack: str) -> bool:
    mail_tokens = ("邮件", "邮箱", "email", "mail", "smtp", "gmail", "outlook")
    send_tokens = ("发送", "发给", "发邮件", "回复", "reply", "send", "forward", "转发")
    return any(token in haystack for token in mail_tokens) and (
        any(token in haystack for token in send_tokens) or event.action_type in {"network_egress", "channel_send"}
    )


def _looks_like_mail_read(event: BehaviorEvent, haystack: str) -> bool:
    mail_tokens = ("邮件", "邮箱", "email", "mail", "inbox", "收件箱")
    read_tokens = ("读取", "查看", "总结", "summarize", "read", "list", "fetch")
    return any(token in haystack for token in mail_tokens) and any(token in haystack for token in read_tokens)


def _looks_like_report_generate(event: BehaviorEvent, haystack: str) -> bool:
    report_tokens = ("日报", "周报", "晨报", "总结", "summary", "report")
    generate_tokens = ("生成", "整理", "汇总", "撰写", "generate", "summarize", "draft")
    return any(token in haystack for token in report_tokens) and any(token in haystack for token in generate_tokens)


def _looks_like_report_send(event: BehaviorEvent, haystack: str) -> bool:
    report_tokens = ("日报", "周报", "晨报", "总结", "summary", "report")
    send_tokens = ("发送", "发给", "reply", "send", "forward", "转发", "外发")
    return any(token in haystack for token in report_tokens) and any(token in haystack for token in send_tokens)


def _looks_like_attachment_download(event: BehaviorEvent, haystack: str) -> bool:
    attachment_tokens = ("附件", "attachment", "download", "下载")
    return any(token in haystack for token in attachment_tokens) and event.action_type in {
        "network_egress",
        "file_write",
        "command_exec",
    }


def _contains_public_ip(targets: list[str]) -> bool:
    for target in targets:
        match = _RE_PUBLIC_IP.search(target)
        if not match:
            continue
        try:
            ip = ipaddress.ip_address(match.group(1))
        except ValueError:
            continue
        if not ip.is_private and not ip.is_loopback:
            return True
    return False


def _is_low_risk_command(command: str | None) -> bool:
    if not command:
        return False
    normalized = command.strip().lower()
    return normalized.startswith(_READONLY_COMMANDS)


def _is_external_recipient(address: str) -> bool:
    domain = address.rsplit("@", 1)[-1].lower()
    return domain not in _INTERNAL_DOMAINS
