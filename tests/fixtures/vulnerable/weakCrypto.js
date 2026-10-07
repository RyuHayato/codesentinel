import crypto from "crypto";

export function hash(data) {
  return crypto.createHash("md5").update(data).digest("hex");
}

export function sign(key, data) {
  return crypto.createHmac("sha1", key).update(data).digest("hex");
}

export function encrypt(key, data) {
  const cipher = crypto.createCipher("des-cbc", key);
  return cipher.update(data) + cipher.final("hex");
}
