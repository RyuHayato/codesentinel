export function newSession() {
  const sessionId = Math.random().toString(36).slice(2);
  return sessionId;
}

export function oneTimeCode() {
  const otp = Math.floor(Math.random() * 1000000);
  return otp;
}

export function createSalt() {
  const salt = Math.random().toString(16);
  return salt;
}
