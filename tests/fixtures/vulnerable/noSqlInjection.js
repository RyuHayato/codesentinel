export async function login(db, req, res) {
  const filter = req.body; // attacker-controlled, e.g. { "username": "admin", "password": { "$gt": "" } }
  const user = await db.collection("users").findOne(filter);
  res.json(user);
}

export async function advancedSearch(db, term) {
  const results = await db.collection("items").find({ $where: `this.name.includes('${term}')` });
  return results;
}
