import crypto from "crypto";

export function hash(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}

export function encrypt(key, iv, data) {
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  return cipher.update(data, "utf8", "hex") + cipher.final("hex");
}
