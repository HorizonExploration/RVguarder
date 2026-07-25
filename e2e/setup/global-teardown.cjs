const fs = require("fs");
const path = require("path");

const CACHE_DIR = path.resolve(__dirname, "..", ".cache");
const CACHE_FILE = path.join(CACHE_DIR, "server.json");

async function sleep(ms) {
  await new Promise((r) => setTimeout(r, ms));
}

async function killProcess(pid) {
  if (!pid) return;
  try {
    process.kill(pid, "SIGTERM");
  } catch (_) {
    return;
  }
  for (let i = 0; i < 20; i += 1) {
    await sleep(150);
    try {
      process.kill(pid, 0);
    } catch (_) {
      return;
    }
  }
  try {
    process.kill(pid, "SIGKILL");
  } catch (_) {}
}

module.exports = async () => {
  if (!fs.existsSync(CACHE_FILE)) return;
  const data = JSON.parse(fs.readFileSync(CACHE_FILE, "utf-8"));
  await killProcess(data.pid);
  if (data.tmpRoot && typeof data.tmpRoot === "string") {
    try {
      fs.rmSync(data.tmpRoot, { recursive: true, force: true });
    } catch (_) {}
  }
  try {
    fs.rmSync(CACHE_FILE, { force: true });
  } catch (_) {}
};

