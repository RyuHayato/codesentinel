// Demo file — intentionally vulnerable, for CodeSentinel documentation.
import { exec } from "child_process";
import crypto from "crypto";

const dbPassword = "Pr0dDbP@ssw0rd!";
const awsKey = "AKIAIOSFODNN7EXAMPLE";

export function getUserReport(req, res) {
  const name = req.query.name;
  // SQL injection
  db.query("SELECT * FROM users WHERE name = '" + name + "'").then(res.json);
  // Command injection
  exec(`ping ${req.query.host}`);
  // Weak crypto for a session token
  const token = crypto.createHash("md5").update(name).digest("hex");
  // Plaintext URL
  fetch("http://api.internal.corp/metrics");
  return token;
}

const db = { query: async () => [] };
