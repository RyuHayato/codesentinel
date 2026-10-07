import jwt from "jsonwebtoken";

export function checkToken(token, secret) {
  return jwt.verify(token, secret, { algorithms: ["HS256"] });
}

export function makeToken(payload, secret) {
  return jwt.sign(payload, secret, { algorithm: "HS256" });
}
