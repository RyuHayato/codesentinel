export function compute(expr) {
  const parsed = JSON.parse(expr);
  return parsed;
}

export function schedule(cb) {
  setTimeout(() => cb(), 1000);
}
