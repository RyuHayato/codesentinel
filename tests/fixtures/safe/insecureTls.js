import https from "https";

export function fetchUserData(url) {
  return https.get(url, { rejectUnauthorized: true });
}
