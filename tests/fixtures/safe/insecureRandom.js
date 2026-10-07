import crypto from "crypto";

export function newSession() {
  const sessionId = crypto.randomBytes(16).toString("hex");
  return sessionId;
}

export function oneTimeCode() {
  const otp = crypto.randomInt(0, 1000000);
  return otp;
}

export function rollDice(sides) {
  // Math.random is fine for non-security gameplay randomness.
  return Math.floor(Math.random() * sides) + 1;
}
