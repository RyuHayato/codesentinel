export async function login(db, req, res) {
  const { username } = req.body;
  // Parameters are validated/cast before use — safe against operator injection.
  const user = await db.collection("users").findOne({ username: String(username) });
  res.json(user);
}
