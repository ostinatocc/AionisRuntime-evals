import {
  canonicalClone,
  canonicalSha256,
  expectExactRecord,
  expectPositiveInteger,
} from "./canonical.mjs";

export const DEEPSEEK_ENDPOINT_V1 =
  "https://api.deepseek.com/chat/completions";
export const DEEPSEEK_MODEL_V1 = "deepseek-v4-flash";
export const DEEPSEEK_THINKING_MODE_V1 = "enabled";
export const DEEPSEEK_REASONING_EFFORT_V1 = "max";
export const DEEPSEEK_RESPONSE_FORMAT_V1 = "json_object";
export const DEEPSEEK_SCORED_ATTEMPT_LIMIT_V1 = 9;
export const DEEPSEEK_MAX_OUTPUT_TOKENS_V1 = 384_000;

const MODEL_PROTOCOL_KEYS = Object.freeze([
  "endpoint",
  "immutable_snapshot",
  "maximum_provider_request_attempt_count",
  "max_tokens",
  "provider",
  "provider_may_update_weights",
  "reasoning_effort",
  "requested_model",
  "response_format",
  "retries",
  "scored_agent_execution_count",
  "thinking_mode",
]);

function fail(code) {
  throw new Error(`aionis_eval_deepseek_model_protocol_${code}`);
}

export function verifyDeepSeekModelProtocolV1(value) {
  const protocol = expectExactRecord(
    value,
    MODEL_PROTOCOL_KEYS,
    "deepseek_model_protocol",
  );
  if (protocol.provider !== "deepseek"
    || protocol.endpoint !== DEEPSEEK_ENDPOINT_V1
    || protocol.requested_model !== DEEPSEEK_MODEL_V1
    || protocol.thinking_mode !== DEEPSEEK_THINKING_MODE_V1
    || protocol.reasoning_effort !== DEEPSEEK_REASONING_EFFORT_V1
    || protocol.response_format !== DEEPSEEK_RESPONSE_FORMAT_V1
    || protocol.retries !== 0
    || protocol.scored_agent_execution_count !== DEEPSEEK_SCORED_ATTEMPT_LIMIT_V1
    || protocol.maximum_provider_request_attempt_count
      !== DEEPSEEK_SCORED_ATTEMPT_LIMIT_V1
    || protocol.immutable_snapshot !== false
    || protocol.provider_may_update_weights !== true) {
    fail("invalid");
  }
  expectPositiveInteger(protocol.max_tokens, "deepseek_model_protocol_max_tokens");
  if (protocol.max_tokens > DEEPSEEK_MAX_OUTPUT_TOKENS_V1) {
    fail("max_tokens_invalid");
  }
  return canonicalClone(protocol);
}

export function deepSeekModelProtocolSha256V1(value) {
  return canonicalSha256(verifyDeepSeekModelProtocolV1(value));
}
