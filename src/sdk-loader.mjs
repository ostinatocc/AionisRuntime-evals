import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import path from "node:path";

import { expectText } from "./canonical.mjs";

export async function loadPackedContinuationSdk(consumerRoot) {
  const root = path.resolve(expectText(consumerRoot, "sdk_consumer_root", {
    maximumBytes: 4_096,
  }));
  const packageRoot = path.join(root, "node_modules/@aionis/continuation-sdk");
  let manifest;
  try {
    manifest = JSON.parse(readFileSync(path.join(packageRoot, "package.json"), "utf8"));
  } catch (error) {
    throw new Error("aionis_eval_sdk_package_unavailable", { cause: error });
  }
  const importTarget = manifest?.exports?.["."]?.import;
  if (manifest.name !== "@aionis/continuation-sdk"
    || typeof importTarget !== "string"
    || !importTarget.startsWith("./")
    || importTarget.includes("..")) {
    throw new Error("aionis_eval_sdk_export_map_invalid");
  }
  const resolved = path.resolve(packageRoot, importTarget);
  if (!resolved.startsWith(`${packageRoot}${path.sep}`)) {
    throw new Error("aionis_eval_sdk_export_map_invalid");
  }
  const sdk = await import(pathToFileURL(resolved).href);
  const exports = Object.keys(sdk).sort();
  if (JSON.stringify(exports) !== JSON.stringify([
    "AionisRuntimeV1ClientError",
    "createAionisRuntimeV1Client",
  ])) throw new Error("aionis_eval_sdk_export_surface_invalid");
  return Object.freeze({
    createClient: sdk.createAionisRuntimeV1Client,
    clientError: sdk.AionisRuntimeV1ClientError,
    resolvedEntry: resolved,
  });
}
