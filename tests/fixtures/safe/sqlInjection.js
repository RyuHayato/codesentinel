export async function findUser(db, req, res) {
  const id = req.query.id;
  const rows = await db.query("SELECT * FROM users WHERE id = ?", [id]);
  const recent = await db.query("SELECT * FROM logs WHERE ts > NOW() - INTERVAL 1 DAY");
  res.json({ rows, recent });
}
