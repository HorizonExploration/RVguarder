const fs = require("fs");
const path = require("path");

const CACHE_FILE = path.resolve(__dirname, "..", ".cache", "server.json");

function readServer() {
  if (!fs.existsSync(CACHE_FILE)) {
    throw new Error("e2e_server_cache_missing");
  }
  return JSON.parse(fs.readFileSync(CACHE_FILE, "utf-8"));
}

function getBaseUrl() {
  return readServer().url;
}

function getHookToken() {
  const server = readServer();
  const statePath = path.join(server.projectDir, "runtime", "hook-bridge.json");
  const state = JSON.parse(fs.readFileSync(statePath, "utf-8"));
  return state.auth_token;
}

module.exports = { readServer, getBaseUrl, getHookToken };
