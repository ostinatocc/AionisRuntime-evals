#!/usr/bin/env node

import { canonicalJson } from "../canonical.mjs";
import {
  parseDeepSeekProviderContractSmokeCliArgumentsV1,
  runDeepSeekProviderContractSmokeV1,
} from "../deepseek-provider.mjs";

function writeStream(stream, text) {
  return new Promise((resolve, reject) => {
    stream.write(text, (error) => {
      if (error) reject(error);
      else resolve();
    });
  });
}

async function main() {
  try {
    const input = parseDeepSeekProviderContractSmokeCliArgumentsV1(
      process.argv.slice(2),
      process.env,
    );
    const receipt = await runDeepSeekProviderContractSmokeV1(input);
    await writeStream(process.stdout, `${canonicalJson(receipt)}\n`);
    if (receipt.outcome !== "provider_contract_verified") process.exitCode = 2;
  } catch {
    // Credentials, provider payloads, argv, and environment are never emitted.
    await writeStream(
      process.stderr,
      "aionis_eval_deepseek_provider_contract_smoke_failed\n",
    );
    process.exitCode = 1;
  }
}

main().catch(async () => {
  await writeStream(
    process.stderr,
    "aionis_eval_deepseek_provider_contract_smoke_failed\n",
  ).catch(() => {});
  process.exitCode = 1;
});
