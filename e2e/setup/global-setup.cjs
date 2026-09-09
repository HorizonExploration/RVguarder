const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawn } = require("child_process");

const CACHE_DIR = path.resolve(__dirname, "..", ".cache");
const CACHE_FILE = path.join(CACHE_DIR, "server.json");

async function sleep(ms) {
  await new Promise((r) => setTimeout(r, ms));
}

async function waitFor(fn, timeoutMs) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    const ok = await fn();
    if (ok) return;
    await sleep(200);
  }
  throw new Error("wait_for_timeout");
}

function buildE2EConfig() {
  return {
    models: { providers: {} },
    skills: {
      demoSkill: {
        enabled: true,
        description: "E2E demo skill",
        permissions: ["skill_run"]
      }
    }
  };
}

module.exports = async () => {
  fs.mkdirSync(CACHE_DIR, { recursive: true });

  const repoRoot = path.resolve(__dirname, "..", "..");
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "openclaw-guard-e2e-"));
  const projectDir = path.join(tmpRoot, "project");
  fs.mkdirSync(projectDir, { recursive: true });
  const configPath = path.join(projectDir, "openclaw.json");
  fs.writeFileSync(configPath, JSON.stringify(buildE2EConfig(), null, 2), "utf-8");

  const args = [
    "-u",
    "-m",
    "openclaw_guard.main",
    "run",
    "--project-dir",
    projectDir,
    "--config-path",
    configPath,
    "--no-browser",
    "--host",
    "127.0.0.1",
    "--port",
    "0"
  ];

  const child = spawn("python", args, {
    cwd: repoRoot,
    env: { ...process.env },
    stdio: ["ignore", "pipe", "pipe"]
  });

  let url = null;
  let stderr = "";
  let exited = false;

  child.stderr.on("data", (buf) => {
    stderr += buf.toString("utf-8");
  });
  child.on("exit", () => {
    exited = true;
  });

  child.stdout.setEncoding("utf-8");
  child.stdout.on("data", (chunk) => {
    const lines = String(chunk || "")
      .split("\n")
      .map((l) => l.trim())
      .filter(Boolean);
    for (const line of lines) {
      try {
        const parsed = JSON.parse(line);
        if (parsed && parsed.url && typeof parsed.url === "string") {
          url = parsed.url;
        }
      } catch (_) {}
    }
  });

  await waitFor(() => url || exited, 15_000);
  if (!url) {
    try {
      child.kill("SIGTERM");
    } catch (_) {}
    throw new Error(`failed_to_boot_server: ${stderr || "no_stderr"}`);
  }

  const healthUrl = new URL("/api/health", url).toString();
  await waitFor(
    async () => {
      try {
        const resp = await fetch(healthUrl, { method: "GET" });
        return resp.ok;
      } catch (_) {
        return false;
      }
    },
    15_000
  );

  fs.writeFileSync(
    CACHE_FILE,
    JSON.stringify(
      {
        url,
        pid: child.pid,
        tmpRoot,
        projectDir,
        configPath
      },
      null,
      2
    ),
    "utf-8"
  );
};
