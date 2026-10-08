// 可选宿主执行契约：固定单次真实工具调用的字节与参数，不签发授权。
import { createHash, randomUUID } from "node:crypto";
import { constants, openSync, closeSync, fstatSync, readSync, realpathSync } from "node:fs";
import { isAbsolute, relative, resolve, sep } from "node:path";

const TOOLS = new Set(["office_message_send", "office_network_post", "office_document_share"]);
const MAX_BYTES = 1024 * 1024;
const MAX_CALLS = 16;
const TTL_MS = 300000;

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
  return JSON.stringify(value);
}

function argumentsDigest(params) {
  // 三个办公工具的契约为扁平string/boolean对象，先限预算再序列化。
  if (!params || typeof params !== "object" || Array.isArray(params) || Object.keys(params).length > 16) throw new Error("snapshot arguments are invalid");
  let budget = 0;
  for (const [key, value] of Object.entries(params)) {
    if (key.length > 64 || !["string", "boolean"].includes(typeof value)) throw new Error("snapshot arguments are invalid");
    if (typeof value === "string") {
      if (value.length > (key === "body" ? MAX_BYTES : 65536)) throw new Error("snapshot arguments exceed limit");
      budget += Buffer.byteLength(value, "utf8");
    }
    if (budget > MAX_BYTES + 65536) throw new Error("snapshot arguments exceed limit");
  }
  return createHash("sha256").update(canonical(params)).digest("hex");
}

export function resolveSdkIdentity(event, ctx) {
  const call = event?.toolCallId ?? ctx?.toolCallId;
  const run = event?.runId || ctx?.runId;
  const agent = ctx?.agentId;
  const session = ctx?.sessionId ?? "";
  for (const [left, right] of [[event?.toolCallId, ctx?.toolCallId], [event?.runId, ctx?.runId]]) {
    if (left && right && left !== right) throw new Error("conflicting SDK identity");
  }
  for (const [left, right] of [[event?.context?.agentId, agent], [event?.context?.sessionId, session]]) {
    if (left && left !== right) throw new Error("conflicting SDK identity context");
  }
  if (![call, run, agent].every(v => typeof v === "string" && v.length > 0 && v.length <= 256)) throw new Error("snapshot requires SDK call, run and agent identity");
  if (typeof session !== "string" || session.length > 256) throw new Error("invalid SDK session identity");
  return { call, run, agent, session, scope: JSON.stringify([run, agent, session]) };
}

function readBounded(rootPath, sourcePath) {
  if (typeof sourcePath !== "string" || !sourcePath || isAbsolute(sourcePath)) throw new Error("snapshot source must be workspace-relative");
  const root = realpathSync(rootPath);
  const target = realpathSync(resolve(root, sourcePath));
  const inside = relative(root, target);
  if (!inside || inside === ".." || inside.startsWith(`..${sep}`) || isAbsolute(inside)) throw new Error("snapshot source is outside workspace");
  // 父目录若被同时改动，也必须用打开后的fd验证真正消费的对象。
  const fd = openSync(target, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const actual = realpathSync(`/proc/self/fd/${fd}`);
    const openedInside = relative(root, actual);
    if (!openedInside || openedInside === ".." || openedInside.startsWith(`..${sep}`) || isAbsolute(openedInside)) throw new Error("snapshot opened source is outside workspace");
    const before = fstatSync(fd);
    if (!before.isFile() || before.size > MAX_BYTES) throw new Error("snapshot source must be a bounded regular file");
    const buffer = Buffer.alloc(MAX_BYTES + 1);
    let count = 0, read;
    while (count < buffer.length && (read = readSync(fd, buffer, count, buffer.length - count, null)) > 0) count += read;
    const after = fstatSync(fd);
    if (count > MAX_BYTES || count !== before.size || before.size !== after.size || before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs) throw new Error("snapshot source changed while reading");
    return { bytes: Buffer.from(buffer.subarray(0, count)), sourcePath: openedInside };
  } finally { closeSync(fd); }
}

export class ExecutionSnapshots {
  constructor(workspaceRoot) { this.workspaceRoot = workspaceRoot; this.calls = new Map(); }

  invalidate(event, ctx) {
    // 仅使已有候选失败，不用不可信ID创建新对象或挤占容量。
    for (const id of [event?.toolCallId, ctx?.toolCallId]) {
      if (this.calls.has(id)) this.calls.set(id, {invalid: true, expiresAt: Date.now() + TTL_MS});
    }
  }

  // 固定内容在执行器私有内存中，Agent参数不能替换或选择它。
  prepare(event, ctx) {
    if (!TOOLS.has(event?.toolName)) return;
    let identity;
    try { identity = resolveSdkIdentity(event, ctx); }
    catch (error) {
      for (const callId of [event?.toolCallId, ctx?.toolCallId]) {
        if (this.calls.has(callId)) this.calls.set(callId, { invalid: true, expiresAt: Date.now() + TTL_MS });
      }
      throw error;
    }
    const { call, scope } = identity;
    const now = Date.now();
    for (const [id, value] of this.calls) if (value.expiresAt <= now) this.calls.delete(id);
    const old = this.calls.get(call);
    if (!old && this.calls.size >= MAX_CALLS) throw new Error("snapshot capacity reached");
    let digest;
    try { digest = argumentsDigest(event.params); }
    catch (error) {
      this.calls.set(call, { invalid: true, expiresAt: now + TTL_MS });
      throw error;
    }
    if (old) {
      if (old.scope !== scope || old.digest !== digest || old.toolName !== event.toolName) {
        this.calls.set(call, { invalid: true, expiresAt: now + TTL_MS });
        throw new Error("snapshot call identity or parameters are ambiguous");
      }
      if (old.invalid) throw new Error("snapshot call is invalid");
      return;
    }
    // 先登记失败标记；任何读文件错误都不能随后回退到body。
    this.calls.set(call, { invalid: true, expiresAt: now + TTL_MS });
    const params = event.params ?? {};
    const source = params.sourcePath ?? (event.toolName === "office_document_share" ? params.document : undefined);
    const fileInfo = source === undefined ? null : readBounded(this.workspaceRoot, source);
    const body = typeof params.body === "string" ? params.body : "";
    if (!fileInfo && Buffer.byteLength(body, "utf8") > MAX_BYTES) throw new Error("snapshot body exceeds limit");
    const bytes = fileInfo ? fileInfo.bytes : Buffer.from(body, "utf8");
    this.calls.set(call, { scope, digest, toolName: event.toolName, fileInfo, bytes,
      sourceSha256: createHash("sha256").update(bytes).digest("hex"),
      snapshotId: randomUUID(), issuedAt: now, expiresAt: now + TTL_MS });
  }

  describe(event, ctx) {
    // 只读私有已准备快照，不在Guard请求证明时重新读取文件。
    const { call, scope } = resolveSdkIdentity(event, ctx);
    const value = this.calls.get(call);
    if (!value || value.invalid || value.scope !== scope || value.toolName !== event.toolName
      || value.expiresAt <= Date.now() || value.digest !== argumentsDigest(event.params)) return null;
    return { snapshotId: value.snapshotId, digest: value.digest, issuedAt: value.issuedAt,
      expiresAt: value.expiresAt, sourcePath: value.fileInfo?.sourcePath ?? null,
      sha256: value.sourceSha256, sizeBytes: value.bytes.length };
  }

  take(toolName, toolCallId, params) {
    const value = this.calls.get(String(toolCallId));
    this.calls.delete(String(toolCallId)); // 一次消费，失败也不能重试旧授权候选。
    const digest = argumentsDigest(params);
    if (!value || value.invalid || value.expiresAt <= Date.now() || value.toolName !== toolName || value.digest !== digest) throw new Error("valid execution snapshot is required");
    return value;
  }
}
