import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import process from "node:process";
import { spawn } from "node:child_process";
import net from "node:net";

const cwd = process.cwd();
const repoRoot = path.resolve(cwd, "..", "..");
const envFile = path.join(repoRoot, ".env");

const parseDotEnv = (content) => {
  const values = {};
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const separator = line.indexOf("=");
    if (separator === -1) continue;
    const key = line.slice(0, separator).trim();
    if (!key) continue;
    let value = line.slice(separator + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    values[key] = value;
  }
  return values;
};

const envFromFile =
  existsSync(envFile) && readFileSync(envFile, "utf8")
    ? parseDotEnv(readFileSync(envFile, "utf8"))
    : {};

const pythonExecutable =
  [
    path.join(cwd, ".venv", "Scripts", "python.exe"),
    path.join(cwd, ".venv", "bin", "python"),
  ].find((candidate) => existsSync(candidate)) ??
  (process.platform === "win32" ? "py" : "python");

const port = process.env.PORT_AI || envFromFile.PORT_AI || "8000";
const env = {
  ...envFromFile,
  ...process.env,
  AI_API_KEY: process.env.AI_API_KEY || envFromFile.AI_API_KEY || "local-dev-key",
  PORT_AI: port,
};

const args =
  pythonExecutable === "py"
    ? [
        "-3",
        "-m",
        "uvicorn",
        "app.main:app",
        "--reload",
        "--host",
        "127.0.0.1",
        "--port",
        port,
      ]
    : [
        "-m",
        "uvicorn",
        "app.main:app",
        "--reload",
        "--host",
        "127.0.0.1",
        "--port",
        port,
      ];

const isPortFree = async (host, targetPort) =>
  new Promise((resolve) => {
    const server = net.createServer();
    server.unref();
    server.on("error", () => resolve(false));
    server.listen(targetPort, host, () => {
      server.close(() => resolve(true));
    });
  });

const probeExistingAiService = async (host, targetPort) => {
  try {
    const response = await fetch(`http://${host}:${targetPort}/health`);
    if (!response.ok) return false;
    const data = await response.json();
    return data?.service === "ai";
  } catch {
    return false;
  }
};

const spawnAiService = () => {
  const child = spawn(pythonExecutable, args, {
    cwd,
    stdio: "inherit",
    env,
  });

  child.on("error", (error) => {
    console.error("[ai-service] Failed to start Python runtime.");
    console.error(
      "[ai-service] Expected .venv at apps/ai-service/.venv or a system Python command.",
    );
    console.error(error.message);
    process.exit(1);
  });

  child.on("exit", (code, signal) => {
    if (signal) {
      process.kill(process.pid, signal);
      return;
    }
    process.exit(code ?? 0);
  });
};

const main = async () => {
  const host = "127.0.0.1";
  const free = await isPortFree(host, Number(port));
  if (!free) {
    const healthyExistingService = await probeExistingAiService(host, port);
    if (healthyExistingService) {
      console.log(
        `[ai-service] Reusing existing AI service at http://${host}:${port}.`,
      );
      process.exit(0);
    }
    console.error(
      `[ai-service] Port ${port} is already in use by another process. Stop that process or set PORT_AI to a different port.`,
    );
    process.exit(1);
  }

  spawnAiService();
};

void main();
