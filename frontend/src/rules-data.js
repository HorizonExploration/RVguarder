/**
 * 内置安全规则数据 —— 从 Rules.jsx 抽取，与后端 detection.py 的 47 条规则对齐。
 *
 * 数据与视图分离：本模块只维护规则数据，Rules 页只负责渲染与搜索。
 * 注意：后端 detection.py 另有等价定义（双轨），由 tests/test_constraints.py 一致性测试兜底。
 */

export const BUILTIN_RULES = (() => {
  const base = [
    { ruleId: 'CMD-001', title: '阻断 rm -rf', desc: '递归强删默认阻断。', at: ['command_exec'], sv: 'critical', dc: 'block', grp: 'command' },
    { ruleId: 'CMD-002', title: '阻断 curl 管道执行', desc: 'curl|sh 供应链风险。', at: ['command_exec'], sv: 'critical', dc: 'block', grp: 'command' },
    { ruleId: 'CMD-003', title: '阻断 wget 管道执行', desc: 'wget|bash 供应链风险。', at: ['command_exec'], sv: 'critical', dc: 'block', grp: 'command' },
    { ruleId: 'CMD-004', title: '升级 sudo', desc: '提权命令需要二次确认。', at: ['command_exec'], sv: 'high', dc: 'escalate', grp: 'command' },
    { ruleId: 'CMD-005', title: '升级 ssh', desc: '远程连接命令需要二次确认。', at: ['command_exec'], sv: 'high', dc: 'escalate', grp: 'command' },
    { ruleId: 'CMD-006', title: '升级 scp', desc: '远程复制命令需要二次确认。', at: ['command_exec'], sv: 'high', dc: 'escalate', grp: 'command' },
    { ruleId: 'CMD-007', title: '确认 chmod', desc: '权限变更命令需要审批。', at: ['command_exec'], sv: 'high', dc: 'ask', grp: 'command' },
    { ruleId: 'CMD-008', title: '确认 chown', desc: '属主变更命令需要审批。', at: ['command_exec'], sv: 'high', dc: 'ask', grp: 'command' },
    { ruleId: 'CMD-009', title: '确认 mv', desc: '批量移动命令可能影响证据链。', at: ['command_exec'], sv: 'medium', dc: 'ask', grp: 'command' },
    { ruleId: 'CMD-010', title: '确认 rm', desc: '普通删除命令需要审批。', at: ['command_exec'], sv: 'high', dc: 'ask', grp: 'command' },
    { ruleId: 'FILE-001', title: '阻断系统目录删除', desc: '系统目录删除默认阻断。', at: ['file_delete'], sv: 'critical', dc: 'block', grp: 'file' },
    { ruleId: 'FILE-002', title: '阻断敏感凭据目录删除', desc: '删除 SSH/云凭据目录会破坏凭据。', at: ['file_delete'], sv: 'critical', dc: 'block', grp: 'file' },
    { ruleId: 'FILE-003', title: '确认工作区外删除', desc: '工作区外删除需要审批。', at: ['file_delete'], sv: 'high', dc: 'ask', grp: 'file' },
    { ruleId: 'FILE-004', title: '确认日志删除', desc: '删除日志会影响取证。', at: ['file_delete'], sv: 'high', dc: 'ask', grp: 'file' },
    { ruleId: 'FILE-005', title: '确认证据目录删除', desc: '证据目录删除需要审批。', at: ['file_delete'], sv: 'critical', dc: 'escalate', grp: 'file' },
    { ruleId: 'FILE-006', title: '阻断配置覆盖', desc: '覆盖 openclaw.json 默认阻断。', at: ['config_modify'], sv: 'critical', dc: 'block', grp: 'file' },
    { ruleId: 'FILE-007', title: '确认工作区外写入', desc: '写入工作区外文件需要审批。', at: ['file_write'], sv: 'high', dc: 'ask', grp: 'file' },
    { ruleId: 'FILE-008', title: '确认脚本写入', desc: '写入脚本文件需要审批。', at: ['file_write'], sv: 'high', dc: 'ask', grp: 'file' },
    { ruleId: 'FILE-009', title: '阻断敏感凭据写入', desc: '写入 SSH/API 凭据默认阻断。', at: ['file_write'], sv: 'critical', dc: 'block', grp: 'file' },
    { ruleId: 'FILE-010', title: '确认批量写入', desc: '多目标写入需要审批。', at: ['file_write'], sv: 'medium', dc: 'ask', grp: 'file' },
    { ruleId: 'NET-001', title: '确认外部 HTTP 访问', desc: '外部网络访问需要审批。', at: ['network_egress'], sv: 'high', dc: 'ask', grp: 'network' },
    { ruleId: 'NET-002', title: '阻断未知公网 IP', desc: '未知公网目标默认阻断。', at: ['network_egress'], sv: 'critical', dc: 'block', grp: 'network' },
    { ruleId: 'NET-003', title: '升级 webhook', desc: 'Webhook 发送需要二次确认。', at: ['network_egress'], sv: 'high', dc: 'escalate', grp: 'network' },
    { ruleId: 'NET-004', title: '确认上传', desc: '外传关键词触发审批。', at: ['network_egress'], sv: 'high', dc: 'ask', grp: 'network' },
    { ruleId: 'NET-005', title: '阻断敏感外传', desc: '携带凭据外发默认阻断。', at: ['network_egress'], sv: 'critical', dc: 'block', grp: 'network' },
    { ruleId: 'NET-006', title: '确认代理切换', desc: '修改代理出口需要审批。', at: ['network_egress'], sv: 'medium', dc: 'ask', grp: 'network' },
    { ruleId: 'API-001', title: '确认危险 API', desc: '危险 API 调用需要审批。', at: ['channel_send'], sv: 'high', dc: 'ask', grp: 'api' },
    { ruleId: 'API-002', title: '阻断敏感 API', desc: '敏感 API 越权默认阻断。', at: ['channel_send'], sv: 'critical', dc: 'block', grp: 'api' },
    { ruleId: 'API-003', title: '确认通道发送', desc: '跨渠道发送需要审批。', at: ['channel_send'], sv: 'high', dc: 'ask', grp: 'api' },
    { ruleId: 'API-004', title: '升级群发', desc: '批量发送需要二次确认。', at: ['channel_send'], sv: 'high', dc: 'escalate', grp: 'api' },
    { ruleId: 'SKL-001', title: '确认 shell skill', desc: 'Shell 型 skill 需要审批。', at: ['skill_run'], sv: 'high', dc: 'ask', grp: 'skill' },
    { ruleId: 'SKL-002', title: '确认 network skill', desc: '具备外联能力的 skill 需要审批。', at: ['skill_run'], sv: 'high', dc: 'ask', grp: 'skill' },
    { ruleId: 'SKL-003', title: '确认 delete skill', desc: '具备删除能力的 skill 需要审批。', at: ['skill_run'], sv: 'high', dc: 'ask', grp: 'skill' },
    { ruleId: 'SKL-004', title: '确认 write skill', desc: '具备写入能力的 skill 需要审批。', at: ['skill_run'], sv: 'high', dc: 'ask', grp: 'skill' },
    { ruleId: 'SKL-005', title: '阻断持久化 skill', desc: '自启动/守护能力默认阻断。', at: ['skill_run'], sv: 'critical', dc: 'block', grp: 'skill' },
    { ruleId: 'SKL-006', title: '升级系统管理 skill', desc: '系统管理类 skill 需二次确认。', at: ['skill_run'], sv: 'high', dc: 'escalate', grp: 'skill' },
    { ruleId: 'CFG-001', title: '确认配置修改', desc: '修改 OpenClaw 关键配置需要审批。', at: ['config_modify'], sv: 'high', dc: 'ask', grp: 'config' },
    { ruleId: 'CFG-002', title: '阻断鉴权关闭', desc: '关闭鉴权默认阻断。', at: ['config_modify'], sv: 'critical', dc: 'block', grp: 'config' },
    { ruleId: 'CFG-003', title: '确认审批绕过', desc: '绕过审批配置需要审批。', at: ['config_modify'], sv: 'high', dc: 'ask', grp: 'config' },
    { ruleId: 'CFG-004', title: '确认沙箱关闭', desc: '关闭沙箱需要审批。', at: ['config_modify'], sv: 'high', dc: 'ask', grp: 'config' },
    { ruleId: 'CFG-005', title: '阻断日志关闭', desc: '关闭审计日志默认阻断。', at: ['config_modify'], sv: 'critical', dc: 'block', grp: 'config' },
    { ruleId: 'GEN-001', title: '确认未解析删除', desc: '删除动作未解析目标路径时先审批。', at: ['file_delete'], sv: 'high', dc: 'ask', grp: 'general' },
    { ruleId: 'GEN-002', title: '确认未解析写入', desc: '写入动作未解析目标路径时先审批。', at: ['file_write'], sv: 'high', dc: 'ask', grp: 'general' },
    { ruleId: 'GEN-003', title: '确认未解析命令', desc: '高危命令模糊时先审批。', at: ['command_exec'], sv: 'medium', dc: 'ask', grp: 'general' },
    { ruleId: 'GEN-004', title: '确认未知外联', desc: '未知外部连接先审批。', at: ['network_egress'], sv: 'high', dc: 'ask', grp: 'general' },
    { ruleId: 'GEN-005', title: '升级高价值路径', desc: '命中高价值路径需要二次确认。', at: ['file_delete', 'file_write'], sv: 'critical', dc: 'escalate', grp: 'general' },
    { ruleId: 'GEN-006', title: '阻断批量敏感操作', desc: '一次命中多个敏感目标默认阻断。', at: ['file_delete', 'file_write'], sv: 'critical', dc: 'block', grp: 'general' },
  ];
  const office = [
    { ruleId: 'SEM-OFFICE-001', title: '阻断敏感邮件外发', desc: '邮件外发包含敏感信息时阻断。', at: ['mail_send'], sv: 'critical', dc: 'block', grp: 'office' },
    { ruleId: 'SEM-OFFICE-002', title: '阻断日报内部外发', desc: '日报外发包含内部来源内容时阻断。', at: ['report_send'], sv: 'critical', dc: 'block', grp: 'office' },
    { ruleId: 'SEM-OFFICE-003', title: '升级邮件群发', desc: '邮件群发需要二次确认。', at: ['mail_send'], sv: 'high', dc: 'escalate', grp: 'office' },
    { ruleId: 'SEM-OFFICE-004', title: '确认 AI 草拟邮件', desc: 'AI 自动生成邮件需人工复核后发送。', at: ['mail_send'], sv: 'medium', dc: 'ask', grp: 'office' },
    { ruleId: 'SEM-OFFICE-005', title: '确认日报生成范围', desc: '日报生成缺少明确时间或范围约束。', at: ['report_generate'], sv: 'medium', dc: 'ask', grp: 'office' },
  ];
  return base.concat(office);
})();
