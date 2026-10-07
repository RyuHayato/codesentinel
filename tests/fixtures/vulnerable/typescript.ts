const db = {
  query: async (sql: string, params?: unknown[]) => ({ rows: [] as unknown[], sql, params }),
};

export async function getUserByName(name: string) {
  const sql = `SELECT * FROM users WHERE name = '${name}'`;
  return db.query(sql);
}

export async function safeGetUser(id: number) {
  return db.query("SELECT * FROM users WHERE id = ?", [id]);
}
