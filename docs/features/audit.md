# 审计与取证

## 存储架构

审计存储基于 `DBStoreInterface` 抽象接口，由 `get_db_store()` 工厂按连接串 / `DBConfig` 与 `DB_STORE_MODE`（或 `OPENCLAW_GUARD_DB_STORE_MODE`）环境变量选择后端，实例会被缓存复用：

| 模式 | 后端 | 说明 |
|------|------|------|
| `native`（默认） | SQLiteStore | 本地 SQLite 主审计库 |
| `postgresql` | PostgreSQLStore | PostgreSQL 数据库（`database_url` 或 `DBConfig`） |
| `sqlalchemy` | SQLAlchemyStore | 通过 SQLAlchemy 连接任意数据库 URL |

此外保留 JSONL 追加写入备份（`audit.jsonl`）。

## 防篡改机制

- 每条记录有 `previous_hash`
- 每条记录有 `record_hash`
- 可通过哈希链做完整性验证（`verify_chain`）

## 导出格式

- JSON（`audit-export.json`）
- CSV（`audit-export.csv`）

## 使用命令

```bash
openclaw-guard export-audit --output /path/to/audit.json
```

> `--output` 为必选参数，导出结果（含 JSON / CSV 文件路径）以 JSON 写入该文件。

## 当前审计记录类型

- `detection_decision`
- `hook_before_tool_call`
- `hook_after_tool_call`
- `chat_send`
- `chat_send_started`
- `chat_send_failed`
- `chat_wait_failed`
- `chat_reset`
- `chat_model_switch`
- `action_allowed`
- `action_execution_failed`
- `action_blocked_guard_inactive`
- `action_approved`
- `action_rejected`
- `actions_cleared`
- `skill_upsert`
- `skill_delete`
- `channel_upsert`
- `channel_delete`

## 当前已完成的稳定性优化

- 查询按 SQLite `rowid` 稳定排序
- 哈希链校验顺序与写入顺序一致
- 补充了同秒时间戳回归测试
