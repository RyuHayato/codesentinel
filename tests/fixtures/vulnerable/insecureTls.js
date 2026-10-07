import https from "https";

export function fetchUserData(url) {
  return https.get(url, { rejectUnauthorized: false });
}

process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
