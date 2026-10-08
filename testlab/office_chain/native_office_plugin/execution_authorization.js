// 可选宿主授权消费契约：Agent不能签发permit；实际副作用与撤销按SQLite锁串行。
import { createHmac, timingSafeEqual } from "node:crypto";
import { lstatSync, realpathSync } from "node:fs";
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
  return JSON.stringify(value);
}

export class ExecutionAuthorization {
  constructor({database, key, describeProposal, invalidateSnapshot}) {
    this.database = database; this.key = key; this.describeProposal = describeProposal;
    this.invalidateSnapshot = invalidateSnapshot; this.permits = new Map();
  }

  accept(envelope, event, ctx) {
    // 只供已登记宿主Hook调用；无工具/HTTP签发入口。失败令该快照不可消费。
    try {
      if (!envelope || Object.keys(envelope).sort().join() !== "payload,signature") throw new Error("invalid permit envelope");
      const {payload, signature} = envelope;
      let nodes = 128, budget = 16384;
      const inspect = (value, depth) => {
        if (--nodes < 0 || depth > 6) throw new Error("permit complexity");
        if (typeof value === "string") {
          if (value.length > 16384) throw new Error("permit size");
          budget -= Buffer.byteLength(value);
        } else if (value === null || typeof value === "boolean" || (typeof value === "number" && Number.isFinite(value))) budget -= 32;
        else if (value && typeof value === "object" && !Array.isArray(value)) {
          const entries = Object.entries(value);
          if (entries.length > nodes) throw new Error("permit complexity");
          for (const [key, child] of entries) { budget -= key.length; inspect(child, depth + 1); }
        } else throw new Error("permit type");
        if (budget < 0) throw new Error("permit size");
      };
      inspect(payload, 0);
      const encoded = canonical(payload);
      if (Buffer.byteLength(encoded) > 16384 || typeof signature !== "string" || !/^[0-9a-f]{64}$/.test(signature)) throw new Error("invalid permit size");
      const expected = createHmac("sha256", this.key).update(encoded).digest();
      if (!timingSafeEqual(Buffer.from(signature, "hex"), expected)) throw new Error("invalid permit signature");
      const proposal = this.describeProposal(event, ctx)?.payload;
      const now = Date.now();
      if (!proposal || payload.format_version !== 1 || payload.purpose !== "authorized_snapshot_use"
          || Object.keys(payload).sort().join() !== "expires_at_ms,format_version,grant_id,issued_at_ms,proposal,purpose"
          || typeof payload.grant_id !== "string" || !payload.grant_id || payload.grant_id.length > 64
          || canonical(payload.proposal) !== canonical(proposal)
          || !Number.isSafeInteger(payload.issued_at_ms) || !Number.isSafeInteger(payload.expires_at_ms)
          || !(payload.issued_at_ms <= now && now < payload.expires_at_ms)
          || payload.expires_at_ms > proposal.expires_at_ms || payload.expires_at_ms - payload.issued_at_ms > 300000) throw new Error("permit scope mismatch");
      for (const [id, value] of this.permits) if (value.expires_at_ms <= now) this.permits.delete(id);
      if (!this.permits.has(proposal.tool_call_id) && this.permits.size >= 16) throw new Error("permit capacity reached");
      this.permits.set(proposal.tool_call_id, structuredClone(payload));
      return true;
    } catch {
      this.invalidateSnapshot(event, ctx);
      return false;
    }
  }

  run(snapshot, callId, toolName, effect) {
    const permit = this.permits.get(String(callId));
    this.permits.delete(String(callId));
    if (!permit) return effect(); // B0及Guard离线保持原生路径；没有授权例外。
    const now = Date.now(), proposal = permit.proposal;
    if (!snapshot || now >= permit.expires_at_ms || snapshot.snapshotId !== proposal.snapshot_id
        || snapshot.digest !== proposal.arguments_sha256 || toolName !== proposal.tool_name
        || snapshot.sourceSha256 !== proposal.source.sha256 || snapshot.bytes.length !== proposal.source.size_bytes) throw new Error("authorization snapshot expired or changed");
    const info = lstatSync(this.database);
    if (!info.isFile() || info.isSymbolicLink() || (info.mode & 0o077) || info.nlink !== 1
        || (process.getuid && info.uid !== process.getuid()) || realpathSync(this.database) !== this.database) throw new Error("authorization database is not host-private");
    const { DatabaseSync } = require("node:sqlite");
    const db = new DatabaseSync(this.database);
    try {
      db.exec("PRAGMA busy_timeout=0; BEGIN IMMEDIATE");
      const row = db.prepare("SELECT payload,expires,revoked FROM grants WHERE id=?").get(permit.grant_id);
      if (!row || row.revoked !== 0 || row.expires * 1000 <= now || typeof row.payload !== "string" || Buffer.byteLength(row.payload) > 16384) throw new Error("authorization revoked, expired or unavailable");
      const grant = JSON.parse(row.payload), binding = grant.binding, resource = grant.resource;
      const active = db.prepare("SELECT payload FROM grants WHERE revoked=0 AND expires>? LIMIT 1025").all(now / 1000);
      if (active.length > 1024) throw new Error("authorization task budget exceeded");
      const tasks = new Set();
      for (const item of active) {
        if (typeof item.payload !== "string" || Buffer.byteLength(item.payload) > 16384) throw new Error("authorization record budget exceeded");
        const candidate = JSON.parse(item.payload).binding;
        if (["principal_id", "agent_id"].every(key => candidate[key] === proposal[key])
            && ["session_id", "run_id"].every(key => !candidate[key] || candidate[key] === proposal[key])) tasks.add(candidate.task_id);
      }
      if (tasks.size !== 1 || !tasks.has(proposal.task_id)) throw new Error("authorization task became ambiguous");
      if (["task_id", "principal_id", "agent_id"].some(key => binding[key] !== proposal[key])
          || ["session_id", "run_id"].some(key => binding[key] && binding[key] !== proposal[key])
          || grant.operation !== proposal.operation_family || grant.recipient !== proposal.recipient
          || resource.namespace !== proposal.source.namespace || resource.resource_id !== proposal.source.resource_id
          || resource.content_version !== `sha256:${proposal.source.sha256}` || resource.size_bytes !== proposal.source.size_bytes) throw new Error("authorization grant scope mismatch");
      // 检查、实际本地副作用、COMMIT之间没有await；revoke在同一写锁之后生效。
      // SQLite初始化、记录扫描可能跨过有效期，不能复用入口时钟。
      const consumptionTime = Date.now();
      if (consumptionTime >= permit.expires_at_ms || consumptionTime >= proposal.expires_at_ms
          || consumptionTime >= row.expires * 1000) throw new Error("authorization expired before consumption");
      const result = effect();
      if (result && typeof result.then === "function") throw new Error("authorization effect must be synchronous");
      db.exec("COMMIT");
      return result;
    } finally {
      if (db.isTransaction) db.exec("ROLLBACK");
      db.close();
    }
  }

  close() { this.permits.clear(); }
}
