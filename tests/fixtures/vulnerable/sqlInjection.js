export async function findUser(db, req, res) {
  const id = req.query.id;
  const query = "SELECT * FROM users WHERE id = " + id;
  const rows = await db.query(query);
  const q2 = `INSERT INTO logs (msg) VALUES ('${req.body.msg}')`;
  await db.execute(q2);
  res.json(rows);
}
