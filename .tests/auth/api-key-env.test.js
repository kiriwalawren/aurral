import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  setupIsolatedBackend,
  cleanupIsolatedState,
  resetDatabase,
} from "../helpers/backendTestHarness.js";

const [isolatedState, { db }, dbHelpers, authModule] = await setupIsolatedBackend(
  "api-key-env",
  "backend/config/db-sqlite.js",
  "backend/db/helpers/index.js",
  "backend/middleware/auth.js",
);

const { dbOps } = dbHelpers;
const {
  getApiKey,
  isApiKeyManagedByEnv,
  isEnvApiKeyTooShort,
  resolveRequestUser,
  rotateApiKey,
} = authModule;

const ENV_KEY = "a".repeat(32) + "-declarative-key";

const storedApiKey = () => dbOps.getSettings().integrations?.general?.apiKey;

function apiKeyRequest(key) {
  return {
    headers: { "x-api-key": key },
    query: {},
    socket: { remoteAddress: "127.0.0.1" },
    connection: { remoteAddress: "127.0.0.1" },
    ip: "127.0.0.1",
    ips: ["127.0.0.1"],
  };
}

test.beforeEach(() => {
  resetDatabase(db);
  delete process.env.AURRAL_API_KEY;
  delete process.env.AUTH_PROXY_ENABLED;
  delete process.env.AUTH_PROXY_HEADER;
});

test.after(async () => {
  delete process.env.AURRAL_API_KEY;
  await cleanupIsolatedState(isolatedState);
});

test("AURRAL_API_KEY is returned without being written to settings", () => {
  process.env.AURRAL_API_KEY = `  ${ENV_KEY}  `;

  assert.equal(getApiKey(), ENV_KEY);
  assert.equal(isApiKeyManagedByEnv(), true);
  assert.equal(storedApiKey(), undefined);
});

test("AURRAL_API_KEY authenticates requests and replaces the stored key", () => {
  const generated = getApiKey();
  assert.equal(storedApiKey(), generated);

  process.env.AURRAL_API_KEY = ENV_KEY;

  const user = resolveRequestUser(apiKeyRequest(ENV_KEY));
  assert.equal(user?.username, "api");
  assert.equal(user?.role, "admin");
  assert.equal(resolveRequestUser(apiKeyRequest(generated)), null);
});

test("rotating while AURRAL_API_KEY is set does not change the active key", () => {
  process.env.AURRAL_API_KEY = ENV_KEY;

  const rotated = rotateApiKey();

  assert.equal(storedApiKey(), rotated);
  assert.equal(getApiKey(), ENV_KEY);
});

test("short or blank AURRAL_API_KEY values are never accepted as the key", () => {
  process.env.AURRAL_API_KEY = "too-short";
  assert.equal(isEnvApiKeyTooShort(), true);
  assert.equal(isApiKeyManagedByEnv(), false);
  const generated = getApiKey();
  assert.notEqual(generated, "too-short");
  assert.equal(storedApiKey(), generated);
  assert.equal(resolveRequestUser(apiKeyRequest("too-short")), null);

  process.env.AURRAL_API_KEY = "   ";
  assert.equal(isEnvApiKeyTooShort(), false);
  assert.equal(isApiKeyManagedByEnv(), false);
  assert.equal(getApiKey(), generated);
});

test("removing AURRAL_API_KEY restores the stored key", () => {
  const generated = getApiKey();
  process.env.AURRAL_API_KEY = ENV_KEY;
  assert.equal(getApiKey(), ENV_KEY);

  delete process.env.AURRAL_API_KEY;

  assert.equal(isApiKeyManagedByEnv(), false);
  assert.equal(getApiKey(), generated);
  assert.equal(resolveRequestUser(apiKeyRequest(generated))?.username, "api");
});

test("the server refuses to start with a short AURRAL_API_KEY", async () => {
  const dataDir = mkdtempSync(join(tmpdir(), "aurral-api-key-env-"));
  try {
    const child = spawn(process.execPath, ["backend/server.js"], {
      env: {
        ...process.env,
        AURRAL_API_KEY: "too-short",
        AURRAL_DATA_DIR: dataDir,
        AURRAL_DB_PATH: join(dataDir, "aurral.db"),
        PORT: "0",
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let output = "";
    child.stdout.on("data", (chunk) => (output += chunk));
    child.stderr.on("data", (chunk) => (output += chunk));
    const timer = setTimeout(() => child.kill("SIGKILL"), 30_000);
    const [code] = await once(child, "exit");
    clearTimeout(timer);

    assert.equal(code, 1, output);
    assert.match(output, /AURRAL_API_KEY must be at least 32 characters/);
  } finally {
    rmSync(dataDir, { recursive: true, force: true });
  }
});
