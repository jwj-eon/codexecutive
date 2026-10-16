/** Provider-free OpenCodex management/admission probe for Issue 153. */

import { chmod, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { createHash } from "node:crypto";


const INPUT_SCHEMA = "orch-dork/frontier-admission-probe-input/v1";
const OUTPUT_SCHEMA = "orch-dork/frontier-admission-probe-output/v1";
const ADMIN_TOKEN = `ocx_admin_${"A".repeat(43)}`;
const BOOTSTRAP_DATA_TOKEN = "synthetic-bootstrap-data-token";
const MAX_INPUT_BYTES = 16_384;
let failureStage = "bootstrap";

type JsonRecord = Record<string, unknown>;

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function moduleUrl(root: string, relative: string): string {
  return pathToFileURL(join(root, ...relative.split("/"))).href;
}

function canonical(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  const record = value as JsonRecord;
  return `{${Object.keys(record).sort().map(key => `${JSON.stringify(key)}:${canonical(record[key])}`).join(",")}}`;
}

function digest(value: unknown): string {
  return createHash("sha256")
    .update(canonical(value))
    .digest("hex");
}

async function body(response: Response): Promise<unknown> {
  const text = await response.text();
  return text ? JSON.parse(text) : null;
}

async function main(): Promise<void> {
  failureStage = "read_input";
  const source = await Bun.stdin.text();
  if (Buffer.byteLength(source) > MAX_INPUT_BYTES) throw new Error("input_too_large");
  const input: unknown = JSON.parse(source);
  if (!isRecord(input) || input.schema !== INPUT_SCHEMA) throw new Error("input_invalid");
  const root = input.opencodex_root;
  if (
    typeof root !== "string"
    || !isAbsolute(root)
    || resolve(root) !== root
  ) throw new Error("runtime_invalid");

  failureStage = "environment";
  const allowedEnvironment = new Set(["LC_ALL", "PATH"]);
  if (Object.keys(process.env).some(name => !allowedEnvironment.has(name))) {
    throw new Error("environment_invalid");
  }
  const packageJson = JSON.parse(await readFile(join(root, "package.json"), "utf8"));
  if (packageJson?.name !== "@bitkyc08/opencodex") throw new Error("runtime_invalid");

  const home = await mkdtemp(join(tmpdir(), "orch-dork-153-admission-"));
  await chmod(home, 0o700);
  process.env.OPENCODEX_HOME = home;
  process.env.OPENCODEX_ADMIN_AUTH_TOKEN = ADMIN_TOKEN;
  process.env.OPENCODEX_API_AUTH_TOKEN = BOOTSTRAP_DATA_TOKEN;

  const originalLog = console.log;
  const originalWarn = console.warn;
  const originalError = console.error;
  console.log = () => {};
  console.warn = () => {};
  console.error = () => {};

  let server: { url: URL; stop: (force?: boolean) => Promise<void> } | null = null;
  let loopbackOrigin: string | null = null;
  let createdId: string | null = null;
  let deleteAttempted = false;
  let loopbackNetworkCalls = 0;
  let providerCalls = 0;
  const checks: Record<string, "PASS" | "FAIL"> = {};
  const mark = (name: string, accepted: boolean): void => {
    checks[name] = accepted ? "PASS" : "FAIL";
  };
  const rawFetch = globalThis.fetch;

  try {
    failureStage = "module_import";
    const [{ saveConfig }, { startServer }] = await Promise.all([
      import(moduleUrl(root, "src/config.ts")),
      import(moduleUrl(root, "src/server/index.ts")),
    ]);
    saveConfig({
      port: 0,
      // 127.0.0.2 keeps the socket on the loopback interface while exercising
      // OpenCodex's authenticated policy (which waives only its canonical
      // 127.0.0.1/localhost names). This proves the created key without briefly
      // exposing the synthetic management server on a non-loopback interface.
      hostname: "127.0.0.2",
      defaultProvider: "synthetic-disabled",
      providers: {
        "synthetic-disabled": {
          adapter: "openai-chat",
          baseUrl: "https://provider.invalid/v1",
          disabled: true,
          models: ["synthetic-model"],
        },
      },
      apiKeys: [],
    });
    server = startServer(0);
    loopbackOrigin = `http://127.0.0.2:${server.url.port}`;
    globalThis.fetch = (async (inputValue: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(
        typeof inputValue === "string"
          ? inputValue
          : inputValue instanceof URL
            ? inputValue.href
            : inputValue.url,
      );
      if (url.origin !== loopbackOrigin) {
        providerCalls += 1;
        throw new Error("provider_network_forbidden");
      }
      loopbackNetworkCalls += 1;
      return rawFetch(inputValue, init);
    }) as typeof fetch;

    const adminHeaders = {
      "Content-Type": "application/json",
      "X-OpenCodex-API-Key": ADMIN_TOKEN,
    };
    const dataHeaders = {
      "Content-Type": "application/json",
      "X-OpenCodex-API-Key": BOOTSTRAP_DATA_TOKEN,
    };

    failureStage = "unauthenticated_create";
    const unauthenticated = await fetch(new URL("/api/keys", loopbackOrigin), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: "issue153-probe" }),
    });
    mark("unauthenticated_create_refused", unauthenticated.status === 401);
    await body(unauthenticated);

    failureStage = "data_key_create";
    const dataKeyCreate = await fetch(new URL("/api/keys", loopbackOrigin), {
      method: "POST",
      headers: dataHeaders,
      body: JSON.stringify({ name: "issue153-probe" }),
    });
    mark("data_key_management_refused", dataKeyCreate.status === 401);
    await body(dataKeyCreate);

    failureStage = "admin_create";
    const create = await fetch(new URL("/api/keys", loopbackOrigin), {
      method: "POST",
      headers: adminHeaders,
      body: JSON.stringify({ name: "issue153-probe" }),
    });
    const created = await body(create);
    let createdKey = isRecord(created) && typeof created.key === "string" ? created.key : null;
    createdId = isRecord(created) && typeof created.id === "string" ? created.id : null;
    mark(
      "admin_create",
      create.status === 201
        && typeof createdId === "string"
        && /^ocx_data_[0-9a-f]{40}$/.test(createdKey ?? ""),
    );

    failureStage = "invalid_data_key";
    const invalidDataKey = await fetch(new URL("/v1/responses", loopbackOrigin), {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-OpenCodex-API-Key": `ocx_data_${"f".repeat(40)}`,
      },
      body: "{",
    });
    mark("invalid_data_key_refused", invalidDataKey.status === 401);
    await body(invalidDataKey);

    failureStage = "admission_probe";
    const admissionProbe = await fetch(new URL("/v1/responses", loopbackOrigin), {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-OpenCodex-API-Key": createdKey ?? "invalid",
      },
      body: "{",
    });
    const admissionBody = await body(admissionProbe);
    const admissionError = isRecord(admissionBody) && isRecord(admissionBody.error)
      ? admissionBody.error
      : null;
    mark(
      "admission_refused_before_provider",
      admissionProbe.status === 400
        && admissionError?.type === "invalid_request_error"
        && admissionError?.message === "Invalid JSON body",
    );

    failureStage = "delete";
    deleteAttempted = true;
    const deletion = await fetch(new URL("/api/keys", loopbackOrigin), {
      method: "DELETE",
      headers: adminHeaders,
      body: JSON.stringify({ id: createdId }),
    });
    mark("delete", deletion.status === 200);
    await body(deletion);

    failureStage = "census";
    const census = await fetch(new URL("/api/keys", loopbackOrigin), {
      headers: adminHeaders,
    });
    const censusBody = await body(census);
    const keys = isRecord(censusBody) && Array.isArray(censusBody.keys)
      ? censusBody.keys
      : null;
    mark(
      "absence_census",
      census.status === 200
        && Array.isArray(keys)
        && keys.every(item => !isRecord(item) || item.id !== createdId),
    );
    createdKey = null;

    const accepted = Object.values(checks).length === 7
      && Object.values(checks).every(status => status === "PASS")
      && loopbackNetworkCalls === 7
      && providerCalls === 0;
    const core = {
      schema: OUTPUT_SCHEMA,
      status: accepted ? "PASS" : "FAIL",
      checks,
      cleanup_status: checks.delete === "PASS" && checks.absence_census === "PASS"
        ? "COMPLETE"
        : "UNKNOWN",
      provider_dispatch_status: checks.admission_refused_before_provider === "PASS"
        ? "REFUSED_BEFORE_PROVIDER"
        : "UNKNOWN",
      provider_free: true,
      real_credential_reads: 0,
      synthetic_credential_reads: 1,
      loopback_network_calls: loopbackNetworkCalls,
      provider_calls: providerCalls,
      model_calls: 0,
      hosted_calls: 0,
      retries: 0,
      fallbacks: 0,
      repairs: 0,
      replacements: 0,
    };
    failureStage = "write_output";
    process.stdout.write(JSON.stringify({ ...core, probe_sha256: digest(core) }));
  } finally {
    globalThis.fetch = rawFetch;
    if (server) {
      if (createdId && !deleteAttempted) {
        try {
          await rawFetch(new URL("/api/keys", loopbackOrigin ?? server.url), {
            method: "DELETE",
            headers: {
              "Content-Type": "application/json",
              "X-OpenCodex-API-Key": ADMIN_TOKEN,
            },
            body: JSON.stringify({ id: createdId }),
          });
        } catch {
          // The outer qualification treats any thrown path as a failed probe.
        }
      }
      await server.stop(true);
    }
    console.log = originalLog;
    console.warn = originalWarn;
    console.error = originalError;
    delete process.env.OPENCODEX_HOME;
    delete process.env.OPENCODEX_ADMIN_AUTH_TOKEN;
    delete process.env.OPENCODEX_API_AUTH_TOKEN;
    await rm(home, { recursive: true, force: true });
  }
}

main().catch(() => {
  process.stderr.write(`frontier_admission_probe_failed:${failureStage}\n`);
  process.exitCode = 1;
});
