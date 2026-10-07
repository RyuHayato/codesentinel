import type { Rule } from "../types.js";
import hardcodedSecrets from "./hardcodedSecrets.js";
import apiKeys from "./apiKeys.js";
import sqlInjection from "./sqlInjection.js";
import commandInjection from "./commandInjection.js";
import evalUsage from "./evalUsage.js";
import childProcess from "./childProcess.js";
import pathTraversal from "./pathTraversal.js";
import insecureHttp from "./insecureHttp.js";
import weakCrypto from "./weakCrypto.js";
import prototypePollution from "./prototypePollution.js";
import unsafeDeserialization from "./unsafeDeserialization.js";
import suspiciousDependencies from "./suspiciousDependencies.js";

export const ALL_RULES: Rule[] = [
  hardcodedSecrets,
  apiKeys,
  sqlInjection,
  commandInjection,
  evalUsage,
  childProcess,
  pathTraversal,
  insecureHttp,
  weakCrypto,
  prototypePollution,
  unsafeDeserialization,
  suspiciousDependencies,
];

export const RULES_BY_ID = new Map<string, Rule>(ALL_RULES.map((r) => [r.id, r]));
