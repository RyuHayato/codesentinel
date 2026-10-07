import jwt from "jsonwebtoken";

export function readToken(token) {
  // Signature is never checked — an attacker can forge any payload.
  return jwt.decode(token);
}

export function makeToken(payload, secret) {
  return jwt.sign(payload, secret, { algorithm: "none" });
}

export function checkToken(token, secret) {
  return jwt.verify(token, secret, { algorithms: ["none", "HS256"] });
}
