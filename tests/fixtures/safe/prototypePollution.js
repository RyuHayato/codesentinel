function sanitizeKey(key) {
  return ["__proto__", "constructor", "prototype"].includes(key) ? "_blocked" : key;
}

export function updateConfig(req, base) {
  const cfg = Object.assign({}, base);
  const obj = Object.create(null);
  const key = sanitizeKey(req.body.key);
  obj[key] = req.body.value;
  return { cfg, obj };
}
