import fs from "fs";
import path from "path";

const ALLOWED_DIR = "/var/www/uploads";

export function serve(requested) {
  const resolved = path.resolve(ALLOWED_DIR, requested);
  if (!resolved.startsWith(ALLOWED_DIR)) {
    throw new Error("Invalid path");
  }
  return fs.readFileSync(ALLOWED_DIR + "/static/logo.png");
}
