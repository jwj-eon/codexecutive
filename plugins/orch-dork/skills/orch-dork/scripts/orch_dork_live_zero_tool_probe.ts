/** Provider-free OpenCodex parser/adapter/bridge probe for Issues 140 and 155. */

import { access, readFile } from "node:fs/promises";
import { constants as fsConstants } from "node:fs";
import { isAbsolute, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";


const INPUT_SCHEMA = "orch-dork/open-codex-zero-tool-probe-input/v2";
const OUTPUT_SCHEMA = "orch-dork/open-codex-zero-tool-probe-output/v2";
const LIVE_REQUEST_SCHEMA = "orch-dork/live-zero-tool-request/v2";
const ROUTE_PREFLIGHT_REQUEST_SCHEMA =
  "orch-dork/route-preflight-zero-tool-request/v1";
const REQUEST_SCHEMAS = new Set([
  LIVE_REQUEST_SCHEMA,
  ROUTE_PREFLIGHT_REQUEST_SCHEMA,
]);
const REASONING_ENVELOPE_CONTRACT = "opencodex-2.35-hidden-reasoning/v1";
const MAX_INPUT_BYTES = 262_144;
let failureStage = "bootstrap";
let networkCalls = 0;

globalThis.fetch = (async () => {
  networkCalls += 1;
  throw new Error("network_forbidden");
}) as typeof fetch;

type JsonRecord = Record<string, unknown>;

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function moduleUrl(root: string, relative: string): string {
  return pathToFileURL(join(root, ...relative.split("/"))).href;
}

function normalizeResponseIds(value: JsonRecord, caseId: string): JsonRecord {
  const output = Array.isArray(value.output) ? value.output : [];
  let messageIndex = 0;
  let reasoningIndex = 0;
  const normalized = output.map((raw) => {
    if (!isRecord(raw)) return raw;
    const item = { ...raw };
    if (item.type === "message") item.id = `msg_issue140_${caseId}_${++messageIndex}`;
    if (item.type === "reasoning") item.id = `rs_issue140_${caseId}_${++reasoningIndex}`;
    return item;
  });
  return { ...value, id: `resp_issue140_${caseId}`, output: normalized };
}

async function main(): Promise<void> {
  failureStage = "read_input";
  const source = await Bun.stdin.text();
  if (Buffer.byteLength(source) > MAX_INPUT_BYTES) throw new Error("input_too_large");
  const input: unknown = JSON.parse(source);
  if (!isRecord(input) || input.schema !== INPUT_SCHEMA) throw new Error("input_invalid");
  const root = input.opencodex_root;
  const requestSchema = input.request_schema;
  const requestBody = input.request_body;
  const terminalResult = input.terminal_result;
  const responseModel = input.response_model;
  if (
    typeof root !== "string"
    || !isAbsolute(root)
    || resolve(root) !== root
    || typeof requestSchema !== "string"
    || !REQUEST_SCHEMAS.has(requestSchema)
    || !isRecord(requestBody)
    || !isRecord(terminalResult)
    || typeof responseModel !== "string"
    || !responseModel
  ) throw new Error("input_invalid");
  const requestText = isRecord(requestBody.text) ? requestBody.text : null;
  const requestFormat = requestText && isRecord(requestText.format)
    ? requestText.format
    : null;
  const expectedFormatName = requestSchema === ROUTE_PREFLIGHT_REQUEST_SCHEMA
    ? "orch_dork_route_preflight_candidate"
    : "orch_dork_live_sweep_lane_result";
  if (
    !requestFormat
    || requestFormat.name !== expectedFormatName
    || Object.prototype.hasOwnProperty.call(requestBody, "include_reasoning")
  ) throw new Error("request_schema_body_mismatch");

  failureStage = "environment";
  const allowedEnvironment = new Set(["LC_ALL", "PATH"]);
  if (Object.keys(process.env).some((name) => !allowedEnvironment.has(name))) {
    throw new Error("environment_invalid");
  }

  failureStage = "runtime_identity";
  await access(join(root, "package.json"), fsConstants.R_OK);
  const packageJson = JSON.parse(await readFile(join(root, "package.json"), "utf8"));
  if (packageJson?.name !== "@bitkyc08/opencodex") throw new Error("runtime_invalid");

  failureStage = "module_import";
  const [
    { parseRequest },
    { responsesRequestSchema },
    { createOpenAIChatAdapter },
    bridge,
    fixture,
    budgetModule,
  ] = await Promise.all([
    import(moduleUrl(root, "src/responses/parser.ts")),
    import(moduleUrl(root, "src/responses/schema.ts")),
    import(moduleUrl(root, "src/adapters/openai-chat.ts")),
    import(moduleUrl(root, "src/bridge.ts")),
    import(moduleUrl(root, "src/lab/conformance/fixture-provider.ts")),
    import(moduleUrl(root, "src/lib/translator-budget.ts")),
  ]);
  failureStage = "request_parse";
  const parsedSchema = responsesRequestSchema.safeParse(requestBody);
  if (!parsedSchema.success) throw new Error("request_parse_failed");
  const parsed = parseRequest(requestBody);
  failureStage = "adapter_create";
  const adapter = createOpenAIChatAdapter(fixture.fixtureProviderConfig("openai-chat"));
  const terminalText = JSON.stringify(terminalResult);

  async function translate(caseId: string, withReasoning: boolean): Promise<JsonRecord> {
    failureStage = `translate_${caseId}`;
    const usage = {
      prompt_tokens: 100,
      completion_tokens: 50,
      total_tokens: 150,
      prompt_tokens_details: { cached_tokens: 10 },
      completion_tokens_details: { reasoning_tokens: 20 },
    };
    const message: JsonRecord = { role: "assistant", content: terminalText };
    if (withReasoning) message.reasoning_content = "synthetic-hidden-reasoning";
    const upstream = new Response(
      JSON.stringify({ choices: [{ index: 0, message, finish_reason: "stop" }], usage }),
      { status: 200, headers: { "Content-Type": "application/json" } },
    );
    const translatorBudget = budgetModule.createTranslatorBudget();
    try {
      if (typeof adapter.parseResponse !== "function") {
        throw new Error("adapter_nonstream_unavailable");
      }
      const events = await adapter.parseResponse(upstream, translatorBudget);
      return normalizeResponseIds(
        bridge.buildResponseJSON(events, responseModel, {
          hideThinkingSummary: parsed.options.hideThinkingSummary,
          suppressReasoningOutput: parsed.options.suppressReasoningOutput,
        }),
        caseId,
      );
    } finally {
      translatorBudget.dispose();
    }
  }

  try {
    const parsedData = parsedSchema.data as JsonRecord;
    const output = {
      schema: OUTPUT_SCHEMA,
      request: {
        request_schema: requestSchema,
        reasoning_envelope_contract: REASONING_ENVELOPE_CONTRACT,
        include_reasoning_absent: !Object.prototype.hasOwnProperty.call(
          requestBody,
          "include_reasoning",
        ) && !Object.prototype.hasOwnProperty.call(parsedData, "include_reasoning"),
        reasoning_output_mode:
          parsed.options.hideThinkingSummary === true
          && parsed.options.suppressReasoningOutput !== true
            ? "hidden_envelope"
            : "invalid",
        reasoning_effort: parsed.options.reasoning ?? null,
        hide_thinking_summary: parsed.options.hideThinkingSummary === true,
        tools_count: Array.isArray(parsed.options.tools) ? parsed.options.tools.length : 0,
        tool_choice: parsed.options.toolChoice ?? null,
        stream: parsed.stream === true,
        store: parsedData.store === true,
        structured_output_type: parsed.options.textFormat?.type ?? null,
      },
      cases: [
        { id: "content_only", response: await translate("content_only", false) },
        { id: "reasoning_rich", response: await translate("reasoning_rich", true) },
      ],
      credential_reads: 0,
      network_calls: networkCalls,
      model_calls: 0,
      hosted_calls: 0,
    };
    failureStage = "encode_output";
    const encoded = JSON.stringify(output);
    failureStage = "write_output";
    process.stdout.write(encoded);
  } finally {
    failureStage = "adapter_dispose";
    if (typeof adapter.dispose === "function") adapter.dispose();
  }
}

main().catch(() => {
  process.stderr.write(`zero_tool_probe_failed:${failureStage}\n`);
  process.exitCode = 1;
});
