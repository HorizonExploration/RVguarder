# 审计与取证

## 存储方式

- SQLite：主审计库
- JSONL：追加写入备份

## 防篡改机制

- 每条记录有 `previous_hash`
- 每条记录有 `record_hash`
- 可通过哈希链做完整性验证

## 导出格式

- JSON
- CSV

## 使用命令

```bash
python -m openclaw_guard.main export-audit
```

## 当前审计记录类型

- `baseline_scan`
- `detection_decision`
- `conversation`
- `action_rejected`
- `action_executed`
- `audit_export`

## 当前已完成的稳定性优化

- 查询按 SQLite `rowid` 稳定排序
- 哈希链校验顺序与写入顺序一致
- 补充了同秒时间戳回归测试
