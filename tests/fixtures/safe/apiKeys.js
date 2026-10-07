const apiKey = process.env.API_KEY;
const headers = { Authorization: `Bearer ${apiKey}` };

export async function fetchData(url) {
  const res = await fetch(url, { headers });
  return res.json();
}
